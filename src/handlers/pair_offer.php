<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$fpr = cp_authenticate($in);

$a = cp_require($in, ['pubkey']);
$pubkey = (string) $a['pubkey'];
if (strlen($pubkey) > 100000) {
    cp_json(400, ['error' => 'bad_pubkey']);
}

$db = cp_db();

$maxOpen = (int) (cp_config()['pair_max_open'] ?? 20);
$cnt = $db->prepare(
    "SELECT COUNT(*) FROM pairing_offers
     WHERE offerer_fpr = ? AND state = 'open' AND expires_at > UTC_TIMESTAMP()"
);
$cnt->execute([$fpr]);
if ((int) $cnt->fetchColumn() >= $maxOpen) {
    cp_json(429, ['error' => 'too_many_offers']);
}

$ttl = (int) (cp_config()['pair_offer_ttl'] ?? 86400);
$token = bin2hex(random_bytes(16));

$db->prepare(
    "INSERT INTO pairing_offers (token, offerer_fpr, offerer_pubkey, state, created_at, expires_at)
     VALUES (?, ?, ?, 'open', UTC_TIMESTAMP(), DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))"
)->execute([$token, $fpr, $pubkey, $ttl]);

cp_json(200, ['token' => $token, 'expires_in' => $ttl]);
