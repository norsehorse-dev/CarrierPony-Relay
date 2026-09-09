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
$db->prepare('UPDATE sealed_devices SET last_seen = UTC_TIMESTAMP() WHERE id = ?')->execute([(int) $dev['id']]);

// A mailbox is owned by the first device to claim it and cannot be repointed to
// another device. This stops a group member, who can also derive a peer's group
// address, from hijacking that peer's registration.
$sel = $db->prepare('SELECT sealed_device_pk FROM mailboxes WHERE mailbox = ?');
$insNew = $db->prepare('INSERT IGNORE INTO mailboxes (mailbox, sealed_device_pk, expires_at) VALUES (?, ?, ?)');
$updOwn = $db->prepare('UPDATE mailboxes SET expires_at = ? WHERE mailbox = ? AND sealed_device_pk = ?');

$count = 0;
foreach ($mailboxes as $m) {
    $mid = is_array($m) ? (string) ($m['mailbox'] ?? '') : (string) $m;
    if (!preg_match('/^[0-9a-f]{64}$/', $mid)) {
        continue;
    }
    $exp = is_array($m) && isset($m['expires_at']) ? (int) $m['expires_at'] : ($now + $maxSec);
    if ($exp <= $now || $exp > $now + $maxSec) {
        $exp = $now + $maxSec;
    }
    $expSql = gmdate('Y-m-d H:i:s', $exp);
    $sel->execute([$mid]);
    $owner = $sel->fetchColumn();
    if ($owner === false) {
        // INSERT IGNORE, then re-read: a concurrent claim on the same
        // (group-derivable) address may have won the race.
        $insNew->execute([$mid, (int) $dev['id'], $expSql]);
        $sel->execute([$mid]);
        $owner = $sel->fetchColumn();
    }
    if ($owner !== false && (int) $owner === (int) $dev['id']) {
        $updOwn->execute([$expSql, $mid, (int) $dev['id']]);
        $count++;
    }
}
cp_json(200, ['ok' => true, 'registered' => $count]);
