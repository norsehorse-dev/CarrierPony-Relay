<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

$in = cp_input();
$a = cp_require($in, ['device_id', 'ts', 'auth', 'message_ids']);
$dev = cp_sealed_device((string) $a['device_id']);
if ($dev === null) {
    cp_json(404, ['error' => 'unknown_device']);
}
if (!cp_sealed_verify($dev, 'ack', (string) $a['device_id'], $a['ts'], (string) $a['auth'])) {
    cp_json(401, ['error' => 'bad_auth']);
}

$ids = $a['message_ids'];
if (!is_array($ids) || count($ids) === 0) {
    cp_json(400, ['error' => 'no_ids']);
}
$ids = array_values(array_filter($ids, fn($x) => is_string($x) && preg_match('/^[0-9a-f]{32}$/', $x)));
$ids = array_slice($ids, 0, 200);
if (!$ids) {
    cp_json(200, ['ok' => true, 'deleted' => 0]);
}

$db = cp_db();
$ph = implode(',', array_fill(0, count($ids), '?'));
$stmt = $db->prepare(
    "DELETE s FROM sealed_messages s
     JOIN mailboxes m ON m.mailbox = s.mailbox
     WHERE m.sealed_device_pk = ? AND s.message_id IN ($ph)"
);
$stmt->execute(array_merge([(int) $dev['id']], $ids));
cp_json(200, ['ok' => true, 'deleted' => $stmt->rowCount()]);
