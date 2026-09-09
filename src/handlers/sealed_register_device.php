<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

$in = cp_input();
$a = cp_require($in, ['device_id', 'device_key']);
$deviceId = (string) $a['device_id'];
$deviceKey = (string) $a['device_key'];
if (!preg_match('/^[0-9a-f]{32}$/', $deviceId)) {
    cp_json(400, ['error' => 'bad_device_id']);
}
if (!preg_match('/^[0-9a-f]{64}$/', $deviceKey)) {
    cp_json(400, ['error' => 'bad_device_key']);
}
$wake = isset($in['wake_token']) && $in['wake_token'] !== '' ? substr((string) $in['wake_token'], 0, 64) : null;

$db = cp_db();
$existing = cp_sealed_device($deviceId);
if ($existing === null) {
    $db->prepare('INSERT INTO sealed_devices (device_id, device_key, wake_token, last_seen) VALUES (?, ?, ?, UTC_TIMESTAMP())')
        ->execute([$deviceId, $deviceKey, $wake]);
    cp_json(200, ['ok' => true]);
}

// Device already exists: only its owner (proving device_key) may update it.
if (!cp_sealed_verify($existing, 'register', $deviceId, $in['ts'] ?? 0, (string) ($in['auth'] ?? ''))) {
    cp_json(401, ['error' => 'bad_auth']);
}
$db->prepare('UPDATE sealed_devices SET wake_token = ?, last_seen = UTC_TIMESTAMP() WHERE id = ?')
    ->execute([$wake, (int) $existing['id']]);
cp_json(200, ['ok' => true]);
