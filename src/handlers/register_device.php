<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$a = cp_require($in, ['fpr', 'pubkey', 'device_id', 'nonce', 'sig']);
$fpr = strtoupper($a['fpr']);
if (!preg_match('/^[0-9A-F]{40}$/', $fpr)) {
    cp_json(400, ['error' => 'bad_fpr']);
}
if (!preg_match('/^[0-9a-f]{32}$/', $a['device_id'])) {
    cp_json(400, ['error' => 'bad_device_id']);
}

cp_import_pubkey($a['pubkey']);
if (!cp_consume_challenge($fpr, $a['nonce'])) {
    cp_json(401, ['error' => 'bad_challenge']);
}
if (!cp_verify_sig($fpr, $a['nonce'], $a['sig'])) {
    cp_json(401, ['error' => 'bad_signature']);
}

$db = cp_db();
$db->prepare('INSERT INTO identities (fpr, pubkey) VALUES (?, ?) ON DUPLICATE KEY UPDATE pubkey = VALUES(pubkey)')
    ->execute([$fpr, $a['pubkey']]);

$label = isset($in['label']) ? substr((string) $in['label'], 0, 64) : null;
$db->prepare(
    'INSERT INTO devices (fpr, device_id, label) VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE last_seen = UTC_TIMESTAMP(), label = VALUES(label)'
)->execute([$fpr, $a['device_id'], $label]);

cp_json(200, ['ok' => true]);
