<?php

// Apply a .sql migration using the relay's own config.php database credentials,
// one statement at a time (PDO::exec is unreliable for multi-statement SQL).
// Comment lines are stripped; each ";"-terminated statement is run in order.
// Migrations are written to be idempotent (CREATE TABLE IF NOT EXISTS, or an
// information_schema guard), so re-running is safe.
//
// Run as root so it can read a 640 config.php:
//   sudo php apply_migration.php <app_base_dir> <migration.sql>

$base = rtrim($argv[1] ?? '', '/');
$file = $argv[2] ?? '';
if ($base === '' || $file === '' || !is_file($base . '/config.php') || !is_file($file)) {
    fwrite(STDERR, "usage: php apply_migration.php <app_base_dir> <migration.sql>\n");
    exit(2);
}

$cfg = require $base . '/config.php';
$d = $cfg['db'];
$pdo = new PDO(
    "mysql:host={$d['host']};dbname={$d['name']};charset={$d['charset']}",
    $d['user'],
    $d['pass'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$sql = file_get_contents($file);
// Strip full-line "--" comments BEFORE splitting on ";", so a semicolon inside a
// comment cannot break a statement in two.
$lines = preg_split('/\r?\n/', $sql);
$noComments = implode("\n", array_filter($lines, fn($l) => !preg_match('/^\s*--/', $l)));
$n = 0;
foreach (explode(';', $noComments) as $chunk) {
    $code = trim($chunk);
    if ($code === '') {
        continue;
    }
    $pdo->exec($code);
    $n++;
}
echo "applied $n statement(s) from " . basename($file) . "\n";
