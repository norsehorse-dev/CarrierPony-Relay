<?php

date_default_timezone_set('UTC');

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$path = '/' . trim($path, '/');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$routes = [
    'POST /v1/challenge'       => 'challenge.php',
    'POST /v1/register-device' => 'register_device.php',
    'POST /v1/send'            => 'send.php',
    'POST /v1/inbox'           => 'inbox.php',
    'POST /v1/ack'             => 'ack.php',
    'POST /v1/register-push'   => 'register_push.php',
    'POST /v1/register-wake'   => 'register_wake.php',
    'POST /v1/report'          => 'report.php',
    'POST /v1/pair/offer'      => 'pair_offer.php',
    'POST /v1/pair/accept'     => 'pair_accept.php',
    'POST /v1/pair/status'     => 'pair_status.php',
];

$key = $method . ' ' . $path;
if (!isset($routes[$key])) {
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'not_found']);
    exit;
}

require __DIR__ . '/../src/handlers/' . $routes[$key];
