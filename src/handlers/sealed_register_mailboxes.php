<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

$in = cp_input();
$a = cp_require($in, ['device_id', 'ts', 'auth', 'mailboxes']);
$deviceId = (string) $a['device_id'];
$dev = cp_sealed_device($deviceId);
if ($dev === null) {
    cp_json(404, ['error' => 'unknown_device']);
}
if (!cp_sealed_verify($dev, 'mbx', $deviceId, $a['ts'], (string) $a['auth'])) {
    cp_json(401, ['error' => 'bad_auth']);
}

$mailboxes = $a['mailboxes'];
if (!is_array($mailboxes) || count($mailboxes) === 0) {
    cp_json(400, ['error' => 'no_mailboxes']);
}
if (count($mailboxes) > 512) {
    cp_json(400, ['error' => 'too_many']);
}

$cfg = cp_config();
$maxSec = ((int) ($cfg['message_ttl_max_days'] ?? 30)) * 86400;
$now = time();
$db = cp_db();
$devPk = (int) $dev['id'];
$db->prepare('UPDATE sealed_devices SET last_seen = UTC_TIMESTAMP() WHERE id = ?')->execute([$devPk]);

// mailbox => expiry, validated and de-duplicated.
$valid = [];
foreach ($mailboxes as $m) {
    $mid = is_array($m) ? (string) ($m['mailbox'] ?? '') : (string) $m;
    if (!preg_match('/^[0-9a-f]{64}$/', $mid)) {
        continue;
    }
    $exp = is_array($m) && isset($m['expires_at']) ? (int) $m['expires_at'] : ($now + $maxSec);
    if ($exp <= $now || $exp > $now + $maxSec) {
        $exp = $now + $maxSec;
    }
    $valid[$mid] = gmdate('Y-m-d H:i:s', $exp);
}
if (!$valid) {
    cp_json(200, ['ok' => true, 'registered' => 0]);
}

// A mailbox is owned by the first device to claim it and cannot be repointed to
// another device. This stops a group member, who can also derive a peer's group
// address, from hijacking that peer's registration.
//
// Set-based, so a 500-address batch is a handful of statements instead of ~4 per
// address. One multi-row INSERT IGNORE claims every unowned address (a row another
// device already owns is left alone, and a concurrent claim is settled by the
// unique key), one UPDATE per distinct expiry refreshes only rows this device
// owns, and one COUNT reports how many of the batch this device owns.
$rows = [];
$params = [];
foreach ($valid as $mid => $expSql) {
    $rows[] = '(?, ?, ?)';
    array_push($params, $mid, $devPk, $expSql);
}
$db->prepare('INSERT IGNORE INTO mailboxes (mailbox, sealed_device_pk, expires_at) VALUES ' . implode(',', $rows))
    ->execute($params);

$byExpiry = [];
foreach ($valid as $mid => $expSql) {
    $byExpiry[$expSql][] = $mid;
}
foreach ($byExpiry as $expSql => $mids) {
    $ph = implode(',', array_fill(0, count($mids), '?'));
    $db->prepare("UPDATE mailboxes SET expires_at = ? WHERE sealed_device_pk = ? AND mailbox IN ($ph)")
        ->execute(array_merge([$expSql, $devPk], $mids));
}

$ph = implode(',', array_fill(0, count($valid), '?'));
$cnt = $db->prepare("SELECT COUNT(*) FROM mailboxes WHERE sealed_device_pk = ? AND mailbox IN ($ph)");
$cnt->execute(array_merge([$devPk], array_keys($valid)));
cp_json(200, ['ok' => true, 'registered' => (int) $cnt->fetchColumn()]);
