<?php

require_once __DIR__ . '/../auth.php';

$in = cp_input();
$reporter = cp_authenticate($in);

$a = cp_require($in, ['reported_fpr', 'category']);
$reported = strtoupper($a['reported_fpr']);
if (!preg_match('/^[0-9A-F]{40}$/', $reported)) {
    cp_json(400, ['error' => 'bad_reported_fpr']);
}

$allowed = ['spam', 'harassment', 'illegal', 'csam', 'other'];
$category = strtolower((string) $a['category']);
if (!in_array($category, $allowed, true)) {
    cp_json(400, ['error' => 'bad_category']);
}

$description = isset($in['description']) ? mb_substr((string) $in['description'], 0, 4000) : null;
$content     = isset($in['content']) ? mb_substr((string) $in['content'], 0, 20000) : null;
$attachMeta  = isset($in['attachment_meta']) ? mb_substr((string) $in['attachment_meta'], 0, 4000) : null;

cp_db()->prepare(
    'INSERT INTO reports (reporter_fpr, reported_fpr, category, description, content, attachment_meta)
     VALUES (?, ?, ?, ?, ?, ?)'
)->execute([$reporter, $reported, $category, $description, $content, $attachMeta]);

cp_json(200, ['ok' => true]);
