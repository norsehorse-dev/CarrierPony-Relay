<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['token', 'pubkey']);
$token = (string) $a['token'];
if (!preg_match('/^[0-9a-f]{32}$/', $token)) {
    cp_json(400, ['error' => 'bad_token']);
}
$pubkey = (string) $a['pubkey'];
if (strlen($pubkey) > 100000) {
    cp_json(400, ['error' => 'bad_pubkey']);
}

$db = cp_db();

$upd = $db->prepare(
    "UPDATE pairing_offers
     SET state = 'accepted', responder_fpr = ?, responder_pubkey = ?
     WHERE token = ? AND state = 'open' AND expires_at > UTC_TIMESTAMP()"
);
$upd->execute([$fpr, $pubkey, $token]);

if ($upd->rowCount() === 0) {
    $chk = $db->prepare('SELECT state FROM pairing_offers WHERE token = ?');
    $chk->execute([$token]);
    if ($chk->fetch() === false) {
        cp_json(404, ['error' => 'no_such_offer']);
    }
    cp_json(410, ['error' => 'offer_closed']);
}

$sel = $db->prepare('SELECT offerer_fpr, offerer_pubkey FROM pairing_offers WHERE token = ?');
$sel->execute([$token]);
$offer = $sel->fetch();

cp_json(200, [
    'offerer_fpr'    => $offer['offerer_fpr'],
    'offerer_pubkey' => $offer['offerer_pubkey'],
]);
