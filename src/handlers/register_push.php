<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['device_id', 'push_token']);
if (!preg_match('/^[0-9a-f]{32}$/', $a['device_id'])) {
    cp_json(400, ['error' => 'bad_device_id']);
}
$token = substr((string) $a['push_token'], 0, 255);

// Which push pipe this device uses. Absent means APNs: every client that
// predates the field is an iPhone, so old iOS builds keep working unchanged.
$platform = strtolower((string) ($in['platform'] ?? 'apns'));
if (!in_array($platform, ['apns', 'fcm'], true)) {
    cp_json(400, ['error' => 'bad_platform']);
}

$db = cp_db();
$upd = $db->prepare('UPDATE devices SET push_token = ?, platform = ? WHERE fpr = ? AND device_id = ?');
$upd->execute([$token, $platform, $fpr, $a['device_id']]);
if ($upd->rowCount() === 0) {
    $chk = $db->prepare('SELECT id FROM devices WHERE fpr = ? AND device_id = ?');
    $chk->execute([$fpr, $a['device_id']]);
    if (!$chk->fetch()) {
        cp_json(403, ['error' => 'unknown_device']);
    }
}

cp_json(200, ['ok' => true]);
