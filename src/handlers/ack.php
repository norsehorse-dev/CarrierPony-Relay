<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['device_id', 'message_ids']);
if (!preg_match('/^[0-9a-f]{32}$/', $a['device_id'])) {
    cp_json(400, ['error' => 'bad_device_id']);
}
if (!is_array($a['message_ids'])) {
    cp_json(400, ['error' => 'bad_message_ids']);
}

$db = cp_db();
$dev = $db->prepare('SELECT id FROM devices WHERE fpr = ? AND device_id = ?');
$dev->execute([$fpr, $a['device_id']]);
$devicePk = $dev->fetchColumn();
if ($devicePk === false) {
    cp_json(403, ['error' => 'unknown_device']);
}

$ack = $db->prepare(
    'UPDATE deliveries d
     JOIN messages m ON m.id = d.message_pk
     SET d.acked_at = UTC_TIMESTAMP()
     WHERE d.device_pk = ? AND m.message_id = ? AND d.acked_at IS NULL'
);
$acked = 0;
foreach ($a['message_ids'] as $mid) {
    if (!is_string($mid) || !preg_match('/^[0-9a-f]{32}$/', $mid)) {
        continue;
    }
    $ack->execute([(int) $devicePk, $mid]);
    $acked += $ack->rowCount();
}

$db->exec(
    'DELETE m FROM messages m
     WHERE NOT EXISTS (
         SELECT 1 FROM deliveries d WHERE d.message_pk = m.id AND d.acked_at IS NULL
     )'
);
$db->exec('DELETE FROM messages WHERE expires_at <= UTC_TIMESTAMP()');

cp_json(200, ['acked' => $acked]);
