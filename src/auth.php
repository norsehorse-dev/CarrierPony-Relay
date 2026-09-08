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

function cp_import_pubkey(string $pubkey): void
{
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

function cp_verify_sig(string $fpr, string $nonce, string $sigArmored): bool
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
    if (!preg_match('/^[0-9A-F]{40}$/', $fpr)) {
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
