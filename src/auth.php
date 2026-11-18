<?php

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/respond.php';

function cp_new_challenge(string $fpr): string
{
    $nonce = bin2hex(random_bytes(32));
    $ttl = cp_config()['challenge_ttl'];
    $stmt = cp_db()->prepare(
        'INSERT INTO challenges (nonce, fpr, expires_at) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))'
    );
    $stmt->execute([$nonce, $fpr, $ttl]);
    return $nonce;
}

function cp_consume_challenge(string $fpr, string $nonce): bool
{
    $db = cp_db();
    $stmt = $db->prepare('SELECT nonce FROM challenges WHERE nonce = ? AND fpr = ? AND expires_at > UTC_TIMESTAMP()');
    $stmt->execute([$nonce, $fpr]);
    if (!$stmt->fetch()) {
        return false;
    }
    $db->prepare('DELETE FROM challenges WHERE nonce = ?')->execute([$nonce]);
    return true;
}

// A fingerprint is the identity. v4 keys have a 40-character (SHA-1) fingerprint,
// v6 keys (RFC 9580) a 64-character (SHA-256) one. Expects uppercase hex.
function cp_valid_fpr(string $fpr): bool
{
    return preg_match('/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/', $fpr) === 1;
}

// Path of the cp-verify binary, or null when the relay still verifies with gpg.
// gpg cannot read v6 keys, so without the verifier only v4 identities can log in.
function cp_verifier_bin(): ?string
{
    $bin = cp_config()['verifier_bin'] ?? null;
    return (is_string($bin) && $bin !== '') ? $bin : null;
}

// Shadow mode: gpg still decides, cp-verify runs alongside and any disagreement
// is logged. Lets a live relay confirm the verifier accepts every existing
// identity before it takes over. v6 logins stay refused while it is on.
function cp_verifier_shadow(): bool
{
    return cp_verifier_bin() !== null && !empty(cp_config()['verifier_shadow']);
}

function cp_import_pubkey(string $pubkey): void
{
    if (cp_verifier_bin() !== null && !cp_verifier_shadow()) {
        return;
    }
    $home = cp_config()['gnupg_home'];
    $proc = proc_open(
        'gpg --homedir ' . escapeshellarg($home) . ' --batch --import',
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return;
    }
    fwrite($pipes[0], $pubkey);
    fclose($pipes[0]);
    stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    proc_close($proc);
}

// Checks the signature with cp-verify. The key comes from the request when a
// device is registering, otherwise from the identities table. cp-verify requires
// the key's primary fingerprint to equal $fpr and the signature to come from that
// key or a signing subkey it has bound, so a stored or submitted key can never
// authenticate a different fingerprint.
function cp_verify_sig_bin(string $bin, string $fpr, string $nonce, string $sigArmored, ?string $pubkey, ?string &$why = null): bool
{
    $why = null;
    if ($pubkey === null) {
        $stmt = cp_db()->prepare('SELECT pubkey FROM identities WHERE fpr = ?');
        $stmt->execute([$fpr]);
        $row = $stmt->fetch();
        if (!$row) {
            $why = 'no_identity_row';
            return false;
        }
        $pubkey = (string) $row['pubkey'];
    }
    $proc = proc_open(
        [$bin],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        error_log('carrierpony: cannot run verifier ' . $bin);
        return false;
    }
    fwrite($pipes[0], json_encode(['pubkey' => $pubkey, 'fpr' => $fpr, 'data' => $nonce, 'sig' => $sigArmored]));
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $status = proc_close($proc);
    $res = json_decode((string) $out, true);
    $ok = $status === 0 && is_array($res) && ($res['ok'] ?? false) === true;
    if (!$ok) {
        // For the log only. Never sent to a client and never used to decide.
        $why = is_array($res)
            ? (string) ($res['error'] ?? '') . ': ' . (string) ($res['detail'] ?? '')
            : 'no answer from verifier, exit ' . $status;
    }
    return $ok;
}

function cp_verify_sig(string $fpr, string $nonce, string $sigArmored, ?string $pubkey = null): bool
{
    $bin = cp_verifier_bin();
    if ($bin !== null && !cp_verifier_shadow()) {
        return cp_verify_sig_bin($bin, $fpr, $nonce, $sigArmored, $pubkey);
    }
    if (strlen($fpr) !== 40) {
        return false;
    }
    $ok = cp_verify_sig_gpg($fpr, $nonce, $sigArmored);
    if ($bin !== null) {
        $new = cp_verify_sig_bin($bin, $fpr, $nonce, $sigArmored, $pubkey, $why);
        if ($new !== $ok) {
            // The signature and the one-time nonce are logged so a mismatch can
            // be reproduced offline. Both are public once sent, and the nonce
            // is spent. Shadow mode only.
            error_log('carrierpony verifier mismatch: gpg=' . ($ok ? 'ok' : 'fail')
                . ' cp-verify=' . ($new ? 'ok' : 'fail') . ' fpr=' . $fpr
                . ' why=' . preg_replace('/[^\x20-\x7e]/', '?', (string) $why)
                . ' nonce=' . base64_encode($nonce)
                . ' sig=' . base64_encode($sigArmored));
        }
    }
    return $ok;
}

function cp_verify_sig_gpg(string $fpr, string $nonce, string $sigArmored): bool
{
    $home = cp_config()['gnupg_home'];
    $sigFile = tempnam(sys_get_temp_dir(), 'cps');
    $dataFile = tempnam(sys_get_temp_dir(), 'cpd');
    file_put_contents($sigFile, $sigArmored);
    file_put_contents($dataFile, $nonce);
    $cmd = 'gpg --homedir ' . escapeshellarg($home)
        . ' --batch --status-fd 1 --verify '
        . escapeshellarg($sigFile) . ' ' . escapeshellarg($dataFile) . ' 2>/dev/null';
    $out = shell_exec($cmd);
    @unlink($sigFile);
    @unlink($dataFile);
    if ($out === null) {
        return false;
    }
    if (strpos($out, 'VALIDSIG') === false && strpos($out, 'GOODSIG') === false) {
        return false;
    }
    return strpos($out, strtoupper($fpr)) !== false;
}

function cp_authenticate(array $in): string
{
    $a = cp_require($in, ['fpr', 'nonce', 'sig']);
    $fpr = strtoupper($a['fpr']);
    if (!cp_valid_fpr($fpr)) {
        cp_json(400, ['error' => 'bad_fpr']);
    }
    if (!cp_consume_challenge($fpr, $a['nonce'])) {
        cp_json(401, ['error' => 'bad_challenge']);
    }
    if (!cp_verify_sig($fpr, $a['nonce'], $a['sig'])) {
        cp_json(401, ['error' => 'bad_signature']);
    }
    $stmt = cp_db()->prepare('SELECT fpr FROM identities WHERE fpr = ?');
    $stmt->execute([$fpr]);
    if (!$stmt->fetch()) {
        cp_json(403, ['error' => 'unknown_identity']);
    }
    return $fpr;
}
