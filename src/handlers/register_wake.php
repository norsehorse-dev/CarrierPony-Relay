<?php
// Store (or clear) a device's push-gateway wake token. Called by the app when
// a user on a self-hosted relay opts in to gateway push. An empty wake_token
// clears it (opt-out). The relay never sees the push token itself, only this
// opaque token it hands back to the gateway to nudge the device.

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['device_id']);
if (!preg_match('/^[0-9a-f]{32}$/', (string) $a['device_id'])) {
    cp_json(400, ['error' => 'bad_device_id']);
}

$wake = isset($in['wake_token']) ? (string) $in['wake_token'] : '';
if ($wake !== '' && !preg_match('/^[0-9a-f]{64}$/', $wake)) {
    cp_json(400, ['error' => 'bad_wake_token']);
}
$store = $wake === '' ? null : $wake;

$db = cp_db();
$upd = $db->prepare('UPDATE devices SET wake_token = ? WHERE fpr = ? AND device_id = ?');
$upd->execute([$store, $fpr, $a['device_id']]);
if ($upd->rowCount() === 0) {
    $chk = $db->prepare('SELECT id FROM devices WHERE fpr = ? AND device_id = ?');
    $chk->execute([$fpr, $a['device_id']]);
    if (!$chk->fetch()) {
        cp_json(403, ['error' => 'unknown_device']);
    }
}

cp_json(200, ['ok' => true]);
