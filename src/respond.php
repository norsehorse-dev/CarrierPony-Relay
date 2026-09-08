<?php

function cp_json(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body);
    exit;
}

function cp_input(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function cp_require(array $in, array $keys): array
{
    $out = [];
    foreach ($keys as $k) {
        if (!isset($in[$k]) || $in[$k] === '') {
            cp_json(400, ['error' => "missing:$k"]);
        }
        $out[$k] = $in[$k];
    }
    return $out;
}
