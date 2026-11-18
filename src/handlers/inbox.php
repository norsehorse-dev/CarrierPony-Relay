<?php

require_once __DIR__ . '/../auth.php';

@ini_set('memory_limit', '512M');

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

$list = $db->prepare(
    'SELECT m.id, m.size_bytes
     FROM deliveries d
     JOIN messages m ON m.id = d.message_pk
     WHERE d.device_pk = ? AND d.acked_at IS NULL AND m.expires_at > UTC_TIMESTAMP()
     ORDER BY m.received_at ASC, m.id ASC
     LIMIT 200'
);
$list->execute([(int) $devicePk]);
$budget = (int) (cp_config()['inbox_bytes_budget'] ?? 8388608);
$ids = cp_pick_within_budget($list->fetchAll(), $budget);

$one = $db->prepare('SELECT m.message_id, m.envelope, m.alert, m.received_at, m.expires_at FROM messages m WHERE m.id = ?');
cp_stream_messages($one, $ids);
