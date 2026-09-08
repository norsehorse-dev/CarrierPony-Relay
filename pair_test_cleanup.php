<?php

require_once __DIR__ . '/src/db.php';

$fprs = array_slice($argv, 1);
if (!$fprs) {
    fwrite(STDERR, "usage: php pair_test_cleanup.php FPR [FPR ...]\n");
    exit(1);
}

$db = cp_db();
$home = cp_config()['gnupg_home'] ?? null;

foreach ($fprs as $f) {
    $f = strtoupper($f);
    if (!preg_match('/^[0-9A-F]{40}$/', $f)) {
        echo "skip (bad fpr): $f\n";
        continue;
    }
    $db->prepare('DELETE FROM pairing_offers WHERE offerer_fpr = ? OR responder_fpr = ?')->execute([$f, $f]);
    $db->prepare('DELETE FROM devices WHERE fpr = ?')->execute([$f]);
    $db->prepare('DELETE FROM identities WHERE fpr = ?')->execute([$f]);
    if ($home) {
        shell_exec('gpg --homedir ' . escapeshellarg($home) . ' --batch --yes --delete-keys ' . escapeshellarg($f) . ' 2>/dev/null');
    }
    echo "cleaned $f\n";
}
