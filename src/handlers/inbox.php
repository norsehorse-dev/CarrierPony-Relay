<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['device_id']);
if (!preg_match('/^[0-9a-f]{32}$/', $a['device_id'])) {
    cp_json(400, ['error' => 'bad_device_id']);
}

$db = cp_db();
$dev = $db->prepare('SELECT id FROM devices WHERE fpr = ? AND device_id = ?');
$dev->execute([$fpr, $a['device_id']]);
$devicePk = $dev->fetchColumn();
if ($devicePk === false) {
    cp_json(403, ['error' => 'unknown_device']);
}
$db->prepare('UPDATE devices SET last_seen = UTC_TIMESTAMP() WHERE id = ?')->execute([(int) $devicePk]);

$stmt = $db->prepare(
    'SELECT m.message_id, m.envelope, m.received_at, m.expires_at
     FROM deliveries d
     JOIN messages m ON m.id = d.message_pk
     WHERE d.device_pk = ? AND d.acked_at IS NULL AND m.expires_at > UTC_TIMESTAMP()
     ORDER BY m.received_at ASC
     LIMIT 200'
);
$stmt->execute([(int) $devicePk]);

cp_json(200, ['messages' => $stmt->fetchAll()]);
