<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

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
$a = cp_require($in, ['mailbox', 'envelope']);
$mailbox = (string) $a['mailbox'];
if (!preg_match('/^[0-9a-f]{64}$/', $mailbox)) {
    cp_json(400, ['error' => 'bad_mailbox']);
}

$cfg = cp_config();
$size = cp_envelope_size((string) $a['envelope']);
if ($size === null) {
    cp_json(400, ['error' => 'bad_envelope']);
}
if ($size > (int) $cfg['max_envelope_bytes']) {
    cp_json(413, ['error' => 'too_large']);
}

$now = time();
$maxSec = ((int) ($cfg['message_ttl_max_days'] ?? 30)) * 86400;
$expires = isset($in['expires_at']) ? (int) $in['expires_at'] : 0;
if ($expires <= $now || $expires > $now + $maxSec) {
    $expires = $now + $maxSec;
}

$db = cp_db();
// Capability check. A deposit is stored only for a registered, unexpired
// mailbox. An unregistered or guessed address returns a plain ok so the
// endpoint is not an oracle for whether an address exists.
$sel = $db->prepare(
    'SELECT d.wake_token
     FROM mailboxes m JOIN sealed_devices d ON d.id = m.sealed_device_pk
     WHERE m.mailbox = ? AND m.expires_at > UTC_TIMESTAMP()'
);
$sel->execute([$mailbox]);
$box = $sel->fetch();
if (!$box) {
    cp_json(200, ['ok' => true]);
}

$cap = (int) ($cfg['sealed_pending_cap'] ?? 20);
$cnt = $db->prepare('SELECT COUNT(*) FROM sealed_messages WHERE mailbox = ? AND expires_at > UTC_TIMESTAMP()');
$cnt->execute([$mailbox]);
if ((int) $cnt->fetchColumn() >= $cap) {
    cp_json(200, ['ok' => true, 'throttled' => true]);
}

$messageId = bin2hex(random_bytes(16));
$alert = empty($in['silent']) ? 1 : 0;
try {
    $db->prepare(
        'INSERT INTO sealed_messages (message_id, mailbox, envelope, size_bytes, alert, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    )->execute([$messageId, $mailbox, (string) $a['envelope'], $size, $alert, gmdate('Y-m-d H:i:s', $expires)]);
} catch (\Throwable $e) {
    cp_store_failed($e);
}

$wake = $box['wake_token'] ?? null;
if ($wake) {
    cp_sealed_wake((string) $wake, !empty($in['silent']));
}
cp_json(200, ['ok' => true]);
