<?php

// Sealed-sender helpers. The sealed path never sees a fingerprint: a device is
// known only by a random device_id plus a device_key it proves with an HMAC,
// and messages are addressed to opaque rotating mailbox ids the client derives
// from a per-pair secret. See CarrierPony-2.0-SealedSender-Design.md.

require_once __DIR__ . '/db.php';

function cp_sealed_device(string $deviceId): ?array
{
    if (!preg_match('/^[0-9a-f]{32}$/', $deviceId)) {
        return null;
    }
    $st = cp_db()->prepare('SELECT id, device_id, device_key, wake_token FROM sealed_devices WHERE device_id = ?');
    $st->execute([$deviceId]);
    $row = $st->fetch();
    return $row ?: null;
}

// Proves a request came from the device that owns device_key, without any
// fingerprint. auth = HMAC-SHA256(device_key, action:device_id:ts), the key
// being the 64-char hex string itself so clients need no hex decoding. ts is a
// unix time within a 300s window, which is enough since a replay only re-runs
// the same idempotent action for the same device.
function cp_sealed_verify(array $dev, string $action, string $deviceId, $ts, string $auth): bool
{
    $ts = (int) $ts;
    if (abs(time() - $ts) > 300) {
        return false;
    }
    if (!preg_match('/^[0-9a-f]{64}$/', $auth)) {
        return false;
    }
    $mac = hash_hmac('sha256', $action . ':' . $deviceId . ':' . $ts, (string) $dev['device_key']);
    return hash_equals($mac, strtolower($auth));
}

// Content-free wake to one device via the push gateway, same contract as
// cp_gateway_wake but keyed by a single wake_token from the sealed device row.
function cp_sealed_wake(string $wakeToken, bool $silent = false): void
{
    if ($wakeToken === '') {
        return;
    }
    $cfg = cp_config();
    $url = array_key_exists('push_gateway', $cfg)
        ? ($cfg['push_gateway']['url'] ?? null)
        : 'https://push.carrierpony.com';
    if (!$url) {
        return;
    }
    $endpoint = rtrim((string) $url, '/') . '/v1/wake';
    $payload = json_encode(['wake_token' => $wakeToken, 'silent' => $silent]);
    try {
        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HTTPHEADER     => ['content-type: application/json'],
        ]);
        curl_exec($ch);
        curl_close($ch);
    } catch (\Throwable $e) {
        // best-effort; a gateway hiccup must not fail delivery
    }
}
