<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

$in = cp_input();
$a = cp_require($in, ['mailbox', 'envelope']);
$mailbox = (string) $a['mailbox'];
if (!preg_match('/^[0-9a-f]{64}$/', $mailbox)) {
    cp_json(400, ['error' => 'bad_mailbox']);
}

$cfg = cp_config();
$decoded = base64_decode((string) $a['envelope'], true);
if ($decoded === false) {
    cp_json(400, ['error' => 'bad_envelope']);
}
$size = strlen($decoded);
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
$db->prepare(
    'INSERT INTO sealed_messages (message_id, mailbox, envelope, size_bytes, expires_at) VALUES (?, ?, ?, ?, ?)'
)->execute([$messageId, $mailbox, (string) $a['envelope'], $size, gmdate('Y-m-d H:i:s', $expires)]);

$wake = $box['wake_token'] ?? null;
if ($wake) {
    cp_sealed_wake((string) $wake, !empty($in['silent']));
}
cp_json(200, ['ok' => true]);
