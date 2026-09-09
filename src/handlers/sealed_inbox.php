<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

$in = cp_input();
$a = cp_require($in, ['device_id', 'ts', 'auth']);
$dev = cp_sealed_device((string) $a['device_id']);
if ($dev === null) {
    cp_json(404, ['error' => 'unknown_device']);
}
if (!cp_sealed_verify($dev, 'inbox', (string) $a['device_id'], $a['ts'], (string) $a['auth'])) {
    cp_json(401, ['error' => 'bad_auth']);
}

$db = cp_db();
$db->prepare('UPDATE sealed_devices SET last_seen = UTC_TIMESTAMP() WHERE id = ?')->execute([(int) $dev['id']]);
$stmt = $db->prepare(
    'SELECT s.message_id, s.mailbox, s.envelope, s.received_at, s.expires_at
     FROM sealed_messages s
     JOIN mailboxes m ON m.mailbox = s.mailbox
     WHERE m.sealed_device_pk = ? AND s.expires_at > UTC_TIMESTAMP()
     ORDER BY s.received_at ASC
     LIMIT 200'
);
$stmt->execute([(int) $dev['id']]);
cp_json(200, ['messages' => $stmt->fetchAll()]);
