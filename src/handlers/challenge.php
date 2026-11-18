<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$a = cp_require($in, ['fpr']);
$fpr = strtoupper($a['fpr']);
if (!cp_valid_fpr($fpr)) {
    cp_json(400, ['error' => 'bad_fpr']);
}
$nonce = cp_new_challenge($fpr);
cp_json(200, ['nonce' => $nonce]);
