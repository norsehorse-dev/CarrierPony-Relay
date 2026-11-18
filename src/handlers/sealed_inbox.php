<?php

require_once __DIR__ . '/../respond.php';
require_once __DIR__ . '/../sealed.php';

@ini_set('memory_limit', '512M');

$in = cp_input();
$a = cp_require($in, ['device_id', 'ts', 'auth']);
$dev = cp_sealed_device((string) $a['device_id']);
if ($dev === null) {
    cp_json(404, ['error' => 'unknown_device']);
}
if (!cp_sealed_verify($dev, 'inbox', (string) $a['device_id'], $a['ts'], (string) $a['auth'])) {
    cp_json(401, ['error' => 'bad_auth']);
}

// Stream {"messages":[...]} one row at a time, so memory holds one envelope at a
// time however much is waiting, instead of every row plus a full json_encode copy.
function cp_stream_messages(PDOStatement $one, array $ids): void
{
    http_response_code(200);
    header('Content-Type: application/json');
    echo '{"messages":[';
    $first = true;
    foreach ($ids as $id) {
        $one->execute([$id]);
        $row = $one->fetch();
        $one->closeCursor();
        if (!$row) {
            continue;
        }
        echo ($first ? '' : ','), json_encode($row);
        $first = false;
        unset($row);
    }
    echo ']}';
    exit;
}

// Oldest first, up to the byte budget (decoded envelope bytes). An envelope over
// the budget still goes out, but alone; smaller ones behind it are not held back
// by it. The rest stays queued for the next poll, so a pile of big attachments
// can no longer turn every poll into a 100+ MB download that never finishes.
function cp_pick_within_budget(array $candidates, int $budget): array
{
    $pick = [];
    $total = 0;
    foreach ($candidates as $c) {
        $size = (int) $c['size_bytes'];
        if ($pick && $total + $size > $budget) {
            continue;
        }
        $pick[] = (int) $c['id'];
        $total += $size;
        if ($total >= $budget) {
            break;
        }
    }
    return $pick;
}

// Optional skip list: message ids the client keeps failing to open. Leaving them
// out lets new messages through; the client still retries them now and then.
$skip = [];
if (isset($in['skip']) && is_array($in['skip'])) {
    foreach (array_slice($in['skip'], 0, 200) as $x) {
        if (is_string($x) && preg_match('/^[0-9a-f]{32}$/', $x)) {
            $skip[] = $x;
        }
    }
}
$skipSql = $skip ? ' AND s.message_id NOT IN (' . implode(',', array_fill(0, count($skip), '?')) . ')' : '';

$db = cp_db();
$db->prepare('UPDATE sealed_devices SET last_seen = UTC_TIMESTAMP() WHERE id = ?')->execute([(int) $dev['id']]);
$list = $db->prepare(
    "SELECT s.id, s.size_bytes
     FROM sealed_messages s
     JOIN mailboxes m ON m.mailbox = s.mailbox
     WHERE m.sealed_device_pk = ? AND s.expires_at > UTC_TIMESTAMP()$skipSql
     ORDER BY s.received_at ASC, s.id ASC
     LIMIT 200"
);
$list->execute(array_merge([(int) $dev['id']], $skip));
$budget = (int) (cp_config()['inbox_bytes_budget'] ?? 8388608);
$ids = cp_pick_within_budget($list->fetchAll(), $budget);

$one = $db->prepare('SELECT s.message_id, s.mailbox, s.envelope, s.alert, s.received_at, s.expires_at FROM sealed_messages s WHERE s.id = ?');
cp_stream_messages($one, $ids);
