<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
cp_authenticate($in);

$a = cp_require($in, ['to_fpr', 'envelope']);
$to = strtoupper($a['to_fpr']);
if (!preg_match('/^[0-9A-F]{40}$/', $to)) {
    cp_json(400, ['error' => 'bad_to_fpr']);
}

$cfg = cp_config();
$decoded = base64_decode($a['envelope'], true);
if ($decoded === false) {
    cp_json(400, ['error' => 'bad_envelope']);
}
$size = strlen($decoded);
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
$db->beginTransaction();
$db->prepare(
    'INSERT INTO messages (message_id, to_fpr, envelope, size_bytes, expires_at) VALUES (?, ?, ?, ?, ?)'
)->execute([$messageId, $to, $a['envelope'], $size, $expiresSql]);
$pk = (int) $db->lastInsertId();
$ins = $db->prepare('INSERT INTO deliveries (message_pk, device_pk) VALUES (?, ?)');
foreach ($deviceIds as $deviceId) {
    $ins->execute([$pk, (int) $deviceId]);
}
$db->commit();

require_once __DIR__ . '/../push.php';
$silent = !empty($in['silent']);
cp_push_notify($deviceIds, $silent);

cp_json(200, ['message_id' => $messageId, 'expires_at' => $expires]);
