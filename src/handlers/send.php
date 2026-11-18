<?php

require_once __DIR__ . '/../auth.php';

@ini_set('memory_limit', '512M');

// Size and shape check without base64_decode, which would hold a third full copy
// of a large attachment in memory just to measure it.
function cp_envelope_size(string $b64): ?int
{
    $len = strlen($b64);
    if ($len === 0 || $len % 4 !== 0) {
        return null;
    }
    if (strspn($b64, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=') !== $len) {
        return null;
    }
    $pad = substr($b64, -2) === '==' ? 2 : (substr($b64, -1) === '=' ? 1 : 0);
    if (strpos(substr($b64, 0, $len - $pad), '=') !== false) {
        return null;
    }
    return intdiv($len, 4) * 3 - $pad;
}

// A store that fails for size reasons answers 413 too_large instead of an opaque
// 500, so the client can say the attachment is too big for this relay.
function cp_store_failed(\Throwable $e): void
{
    $msg = $e->getMessage();
    error_log('carrierpony store failed: ' . $msg);
    if (stripos($msg, 'max_allowed_packet') !== false || stripos($msg, 'gone away') !== false
        || stripos($msg, 'packet') !== false) {
        cp_json(413, ['error' => 'too_large']);
    }
    cp_json(500, ['error' => 'store_failed']);
}

// Refuse an oversized body before PHP decodes it, rather than running out of
// memory partway through (base64 adds a third, plus the JSON around it).
$cfgEarly = cp_config();
$maxBody = (int) ceil(((int) $cfgEarly['max_envelope_bytes']) * 4 / 3) + 65536;
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > $maxBody) {
    cp_json(413, ['error' => 'too_large']);
}

$in = cp_input();
cp_authenticate($in);

$a = cp_require($in, ['to_fpr', 'envelope']);
$to = strtoupper($a['to_fpr']);
if (!cp_valid_fpr($to)) {
    cp_json(400, ['error' => 'bad_to_fpr']);
}

$cfg = cp_config();
$size = cp_envelope_size((string) $a['envelope']);
if ($size === null) {
    cp_json(400, ['error' => 'bad_envelope']);
}
if ($size > $cfg['max_envelope_bytes']) {
    cp_json(413, ['error' => 'too_large']);
}

$now = time();
$maxSec = $cfg['message_ttl_max_days'] * 86400;
$expires = isset($in['expires_at']) ? (int) $in['expires_at'] : 0;
if ($expires <= $now || $expires > $now + $maxSec) {
    $expires = $now + $maxSec;
}
$expiresSql = gmdate('Y-m-d H:i:s', $expires);

$db = cp_db();
$devs = $db->prepare('SELECT id FROM devices WHERE fpr = ?');
$devs->execute([$to]);
$deviceIds = $devs->fetchAll(PDO::FETCH_COLUMN);
if (!$deviceIds) {
    cp_json(404, ['error' => 'unknown_recipient']);
}

$messageId = bin2hex(random_bytes(16));
// A silent send (control op, self-copy, profile sync) is stored with alert = 0
// so a background check can tell it from a real message without opening it.
$alert = empty($in['silent']) ? 1 : 0;
try {
    $db->beginTransaction();
    $db->prepare(
        'INSERT INTO messages (message_id, to_fpr, envelope, size_bytes, alert, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    )->execute([$messageId, $to, $a['envelope'], $size, $alert, $expiresSql]);
    $pk = (int) $db->lastInsertId();
    $ins = $db->prepare('INSERT INTO deliveries (message_pk, device_pk) VALUES (?, ?)');
    foreach ($deviceIds as $deviceId) {
        $ins->execute([$pk, (int) $deviceId]);
    }
    $db->commit();
} catch (\Throwable $e) {
    if ($db->inTransaction()) {
        try { $db->rollBack(); } catch (\Throwable $ignored) {}
    }
    cp_store_failed($e);
}

require_once __DIR__ . '/../push.php';
$silent = !empty($in['silent']);
// The sender may say a deposit is a contact request, so the push can say so
// too. It is the only kind there is besides an ordinary message; anything else
// in the field, or a request marked silent, is an ordinary message.
$kind = (!$silent && ($in['kind'] ?? '') === 'request') ? 'request' : 'message';
cp_push_notify($deviceIds, $silent, $kind);

cp_json(200, ['message_id' => $messageId, 'expires_at' => $expires]);
