<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['token']);
$token = (string) $a['token'];
if (!preg_match('/^[0-9a-f]{32}$/', $token)) {
    cp_json(400, ['error' => 'bad_token']);
}

$db = cp_db();
$sel = $db->prepare(
    'SELECT offerer_fpr, state, responder_fpr, responder_pubkey,
            (expires_at <= UTC_TIMESTAMP()) AS is_expired
     FROM pairing_offers WHERE token = ?'
);
$sel->execute([$token]);
$row = $sel->fetch();
if ($row === false) {
    cp_json(404, ['error' => 'no_such_offer']);
}
if (strtoupper((string) $row['offerer_fpr']) !== $fpr) {
    cp_json(403, ['error' => 'not_your_offer']);
}

if ($row['state'] === 'accepted') {
    cp_json(200, [
        'state'            => 'accepted',
        'responder_fpr'    => $row['responder_fpr'],
        'responder_pubkey' => $row['responder_pubkey'],
    ]);
}

// An accepted offer stays collectable after expires_at (the reaper keeps it for
// pair_accepted_keep_days). An open one past expiry can never be accepted, so
// say so instead of letting the client wait on it until the reaper's 404.
if ($row['state'] === 'open' && (int) $row['is_expired'] === 1) {
    cp_json(200, ['state' => 'expired']);
}
cp_json(200, ['state' => $row['state']]);
