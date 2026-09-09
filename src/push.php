<?php

// Contentless push. When a message is stored for a recipient, we notify that
// recipient's registered device tokens over their platform's pipe: APNs for
// iPhones (generic "New message" alert), FCM for Android (data-only wake; the
// app posts its own generic notification). Neither pipe ever carries sender or
// content, consistent with a relay that only ever handles sealed envelopes.
//
// APNs: token-based (p8) auth over HTTP/2. Requires an 'apns' block in
// config.php:
//   'apns' => [
//     'enabled'     => true,
//     'key_file'    => '/etc/carrierpony/AuthKey_XXXXXXXXXX.p8',
//     'key_id'      => 'XXXXXXXXXX',
//     'team_id'     => 'XXXXXXXXXX',
//     'bundle_id'   => 'com.carrierpony.app',
//     'environment' => 'production',   // 'sandbox' for Xcode/dev builds
//   ],
//
// FCM: HTTP v1 with a Google service-account key. The OAuth access token is
// derived from an RS256 JWT and cached on disk (~55 min) since PHP-FPM statics
// don't outlive a request. Requires an 'fcm' block in config.php:
//   'fcm' => [
//     'enabled'              => true,
//     'service_account_file' => '/etc/carrierpony/fcm-service-account.json',
//     'token_cache'          => '/var/lib/carrierpony/fcm_token.json',
//   ],
//
// Both senders NULL out a device's token when the platform reports it dead
// (APNs 410, FCM 404/UNREGISTERED), so dead tokens don't accumulate.

require_once __DIR__ . '/db.php';

// ── APNs ───────────────────────────────────────────────────────────────

function cp_apns_jwt(): ?string
{
    static $cached = null;
    static $cachedAt = 0;

    $cfg = cp_config()['apns'] ?? null;
    if (!$cfg || empty($cfg['enabled'])) {
        return null;
    }
    if ($cached !== null && (time() - $cachedAt) < 3000) {
        return $cached;
    }

    $header = ['alg' => 'ES256', 'kid' => $cfg['key_id']];
    $claims = ['iss' => $cfg['team_id'], 'iat' => time()];
    $seg = static fn($d) => rtrim(strtr(base64_encode(json_encode($d)), '+/', '-_'), '=');
    $signingInput = $seg($header) . '.' . $seg($claims);

    $pkey = @file_get_contents($cfg['key_file']);
    if ($pkey === false) {
        return null;
    }
    if (!openssl_sign($signingInput, $der, $pkey, OPENSSL_ALGO_SHA256)) {
        return null;
    }
    $raw = cp_der_to_raw_sig($der);
    if ($raw === null) {
        return null;
    }
    $jwt = $signingInput . '.' . rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');

    $cached = $jwt;
    $cachedAt = time();
    return $jwt;
}

function cp_der_to_raw_sig(string $der): ?string
{
    $off = 0;
    $len = strlen($der);
    if ($len < 8 || ord($der[$off++]) !== 0x30) {
        return null;
    }
    $seqLen = ord($der[$off++]);
    if ($seqLen & 0x80) {
        $n = $seqLen & 0x7f;
        $seqLen = 0;
        while ($n-- > 0) {
            $seqLen = ($seqLen << 8) | ord($der[$off++]);
        }
    }
    if (ord($der[$off++]) !== 0x02) {
        return null;
    }
    $rlen = ord($der[$off++]);
    $r = substr($der, $off, $rlen);
    $off += $rlen;
    if (ord($der[$off++]) !== 0x02) {
        return null;
    }
    $slen = ord($der[$off++]);
    $s = substr($der, $off, $slen);

    $r = ltrim($r, "\x00");
    $s = ltrim($s, "\x00");
    if (strlen($r) > 32 || strlen($s) > 32) {
        return null;
    }
    $r = str_pad($r, 32, "\x00", STR_PAD_LEFT);
    $s = str_pad($s, 32, "\x00", STR_PAD_LEFT);
    return $r . $s;
}

/**
 * Post to one APNs environment.
 *
 * @return array{code:int, reason:string} HTTP status (0 on transport failure)
 *         plus APNs' machine-readable reason string for a 4xx.
 */
function cp_apns_send(string $token, string $payload, string $environment, string $pushType = 'alert', int $priority = 10): array
{
    $cfg = cp_config()['apns'] ?? null;
    if (!$cfg) {
        return ['code' => 0, 'reason' => ''];
    }
    $jwt = cp_apns_jwt();
    if ($jwt === null) {
        return ['code' => 0, 'reason' => ''];
    }
    $host = ($environment === 'sandbox')
        ? 'api.sandbox.push.apple.com'
        : 'api.push.apple.com';

    $ch = curl_init("https://{$host}/3/device/{$token}");
    curl_setopt_array($ch, [
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_2_0,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_HTTPHEADER     => [
            'authorization: bearer ' . $jwt,
            'apns-topic: ' . $cfg['bundle_id'],
            'apns-push-type: ' . $pushType,
            'apns-priority: ' . $priority,
            'content-type: application/json',
        ],
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $reason = '';
    if ($code >= 400) {
        $body = @json_decode((string) $resp, true);
        if (is_array($body)) {
            $reason = (string) ($body['reason'] ?? '');
        }
    }
    return ['code' => $code, 'reason' => $reason];
}

/**
 * Deliver to one device, resolving which APNs environment its token belongs to.
 *
 * A token minted by a build signed aps-environment=development is only valid
 * against api.sandbox.push.apple.com; a token from a distributed build only
 * against api.push.apple.com. One configured environment is therefore wrong for
 * half the fleet. With 'sandbox' set, Xcode builds get notifications and every
 * TestFlight tester silently gets none: APNs answers 400 BadDeviceToken and
 * nothing here used to read that, so the failure was invisible on both ends.
 *
 * So try the environment last seen to work for this device, else the configured
 * default, and on BadDeviceToken try the other. Whichever answers 200 is
 * remembered, so a device pays the double round trip at most once.
 *
 * @return array{delivered:bool, dead:bool}
 */
function cp_apns_deliver(int $devicePk, string $token, string $payload, ?string $known, string $default, string $pushType = 'alert', int $priority = 10): array
{
    $candidates = [];
    foreach ([$known, $default, 'production', 'sandbox'] as $env) {
        if ($env !== null && $env !== '' && !in_array($env, $candidates, true)) {
            $candidates[] = $env;
        }
    }

    foreach ($candidates as $env) {
        $result = cp_apns_send($token, $payload, $env, $pushType, $priority);

        if ($result['code'] === 200) {
            if ($known !== $env) {
                cp_db()->prepare('UPDATE devices SET apns_env = ? WHERE id = ?')
                    ->execute([$env, $devicePk]);
            }
            return ['delivered' => true, 'dead' => false];
        }
        if ($result['code'] === 410 || $result['reason'] === 'Unregistered') {
            return ['delivered' => false, 'dead' => true];
        }
        // BadDeviceToken means "right token, wrong environment" at least as
        // often as it means a junk token, so try the other host before writing
        // the token off.
        if ($result['code'] === 400 && $result['reason'] === 'BadDeviceToken') {
            continue;
        }
        // Anything else (auth, throttling, an APNs outage) is not about the
        // token; leave it alone and try again on the next message.
        return ['delivered' => false, 'dead' => false];
    }

    return ['delivered' => false, 'dead' => false];
}

// ── FCM (HTTP v1) ──────────────────────────────────────────────────────

/** OAuth access token for the FCM service account, disk-cached until expiry. */
function cp_fcm_access_token(): ?string
{
    $cfg = cp_config()['fcm'] ?? null;
    if (!$cfg || empty($cfg['enabled'])) {
        return null;
    }

    $cachePath = $cfg['token_cache'] ?? (sys_get_temp_dir() . '/cp_fcm_token.json');
    $cached = @json_decode((string) @file_get_contents($cachePath), true);
    if (is_array($cached) && isset($cached['token'], $cached['expires_at']) && time() < (int) $cached['expires_at'] - 60) {
        return (string) $cached['token'];
    }

    $sa = @json_decode((string) @file_get_contents($cfg['service_account_file']), true);
    if (!is_array($sa) || empty($sa['client_email']) || empty($sa['private_key'])) {
        return null;
    }

    $now = time();
    $header = ['alg' => 'RS256', 'typ' => 'JWT'];
    $claims = [
        'iss'   => $sa['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud'   => 'https://oauth2.googleapis.com/token',
        'iat'   => $now,
        'exp'   => $now + 3600,
    ];
    $seg = static fn($d) => rtrim(strtr(base64_encode(json_encode($d)), '+/', '-_'), '=');
    $signingInput = $seg($header) . '.' . $seg($claims);
    if (!openssl_sign($signingInput, $sig, $sa['private_key'], OPENSSL_ALGO_SHA256)) {
        return null;
    }
    $jwt = $signingInput . '.' . rtrim(strtr(base64_encode($sig), '+/', '-_'), '=');

    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $jwt,
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);

    $body = @json_decode((string) $resp, true);
    if (!is_array($body) || empty($body['access_token'])) {
        return null;
    }
    $token = (string) $body['access_token'];
    $ttl = isset($body['expires_in']) ? (int) $body['expires_in'] : 3600;

    @file_put_contents(
        $cachePath,
        json_encode(['token' => $token, 'expires_at' => time() + $ttl]),
        LOCK_EX
    );
    @chmod($cachePath, 0600);

    return $token;
}

/** @return array{code:int, unregistered:bool} */
function cp_fcm_send(string $token, bool $silent = false): array
{
    $cfg = cp_config()['fcm'] ?? null;
    if (!$cfg || empty($cfg['enabled'])) {
        return ['code' => 0, 'unregistered' => false];
    }
    $sa = @json_decode((string) @file_get_contents($cfg['service_account_file']), true);
    $projectId = is_array($sa) ? ($sa['project_id'] ?? null) : null;
    $access = cp_fcm_access_token();
    if ($access === null || !$projectId) {
        return ['code' => 0, 'unregistered' => false];
    }

    // Data-only wake with zero content. The Android client refreshes its inbox
    // and posts its own generic local notification when backgrounded.
    $payload = json_encode([
        'message' => [
            'token'   => $token,
            'data'    => $silent ? ['wake' => '1', 'silent' => '1'] : ['wake' => '1'],
            'android' => ['priority' => 'HIGH'],
        ],
    ]);

    $ch = curl_init("https://fcm.googleapis.com/v1/projects/{$projectId}/messages:send");
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_HTTPHEADER     => [
            'authorization: Bearer ' . $access,
            'content-type: application/json',
        ],
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $unregistered = false;
    if ($code === 404) {
        $unregistered = true;
    } elseif ($code >= 400) {
        $body = @json_decode((string) $resp, true);
        $status = $body['error']['details'][0]['errorCode'] ?? ($body['error']['status'] ?? '');
        if ($status === 'UNREGISTERED' || $status === 'NOT_FOUND') {
            $unregistered = true;
        }
    }
    return ['code' => $code, 'unregistered' => $unregistered];
}

// ── Dispatch ───────────────────────────────────────────────────────────

/**
 * Send a contentless push to the given device primary keys, best-effort,
 * over each device's registered platform. Tokens the platform reports dead
 * are cleared so they don't accumulate.
 */
function cp_push_notify(array $devicePks, bool $silent = false): void
{
    if (!$devicePks) {
        return;
    }
    $cfg = cp_config();

    // Opted-in devices are woken through the push gateway. This runs even when
    // this relay has no local APNs/FCM credentials of its own, which is the
    // whole point for a self-hosted relay.
    cp_gateway_wake($devicePks, $silent);

    $apnsEnabled = !empty($cfg['apns']['enabled']);
    $fcmEnabled = !empty($cfg['fcm']['enabled']);
    if (!$apnsEnabled && !$fcmEnabled) {
        return;
    }

    // Two payload shapes. A real message gets the alert banner (content-available
    // is set too so the app can fetch in the background); the banner carries no
    // sender or content. A silent send (a control message or self-copy, flagged by
    // the client) gets a background wake only, so the app fetches and syncs without
    // a phantom "New message" the user opens to find nothing behind.
    if ($silent) {
        // Silent background wake: no alert, no sound. Wakes the app to fetch and
        // apply a control message or self-copy without buzzing the user (read
        // receipts, profile updates, deletes, cross-device self-copies). The
        // client marks these silent because they surface nothing to read.
        $apnsPayload = json_encode(['aps' => ['content-available' => 1]]);
        $apnsPushType = 'background';
        $apnsPriority = 5;
    } else {
        $apnsPayload = json_encode([
            'aps' => [
                'alert'             => ['title' => 'CarrierPony', 'body' => 'New message'],
                'sound'             => 'default',
                'content-available' => 1,
            ],
        ]);
        $apnsPushType = 'alert';
        $apnsPriority = 10;
    }

    $apnsDefault = (string) ($cfg['apns']['environment'] ?? 'production');

    $placeholders = implode(',', array_fill(0, count($devicePks), '?'));
    $stmt = cp_db()->prepare(
        "SELECT id, push_token, platform, apns_env FROM devices
         WHERE id IN ($placeholders) AND push_token IS NOT NULL AND push_token <> ''"
    );
    $stmt->execute(array_map('intval', array_values($devicePks)));
    $rows = $stmt->fetchAll();

    $dead = [];
    foreach ($rows as $row) {
        $token = (string) $row['push_token'];
        try {
            if (($row['platform'] ?? 'apns') === 'fcm') {
                if (!$fcmEnabled) {
                    continue;
                }
                $result = cp_fcm_send($token, $silent);
                if ($result['unregistered']) {
                    $dead[] = (int) $row['id'];
                }
            } else {
                if (!$apnsEnabled) {
                    continue;
                }
                $known = isset($row['apns_env']) && $row['apns_env'] !== ''
                    ? (string) $row['apns_env']
                    : null;
                $result = cp_apns_deliver((int) $row['id'], $token, $apnsPayload, $known, $apnsDefault, $apnsPushType, $apnsPriority);
                if ($result['dead']) {
                    $dead[] = (int) $row['id'];
                }
            }
        } catch (\Throwable $e) {
            // best-effort; a bad token shouldn't fail message delivery
        }
    }

    if ($dead) {
        $ph = implode(',', array_fill(0, count($dead), '?'));
        cp_db()->prepare("UPDATE devices SET push_token = NULL WHERE id IN ($ph)")
            ->execute($dead);
    }
}

/**
 * Nudge the push gateway for any of these devices that opted in (have a
 * wake_token). The gateway receives only the opaque token and the silent flag,
 * never a sender or content. Best-effort and non-fatal; guarded so a relay
 * whose schema predates the wake_token column simply does nothing.
 */
function cp_gateway_wake(array $devicePks, bool $silent = false): void
{
    if (!$devicePks) {
        return;
    }
    // Absent push_gateway config defaults to the CarrierPony gateway, so an
    // existing self-hosted relay picks this up with no config edit. A relay
    // that sets push_gateway.url to null has explicitly disabled gateway wakes.
    $cfg = cp_config();
    $url = array_key_exists('push_gateway', $cfg)
        ? ($cfg['push_gateway']['url'] ?? null)
        : 'https://push.carrierpony.com';
    if (!$url) {
        return;
    }
    $endpoint = rtrim((string) $url, '/') . '/v1/wake';

    try {
        $placeholders = implode(',', array_fill(0, count($devicePks), '?'));
        $stmt = cp_db()->prepare(
            "SELECT wake_token FROM devices
             WHERE id IN ($placeholders) AND wake_token IS NOT NULL AND wake_token <> ''"
        );
        $stmt->execute(array_map('intval', array_values($devicePks)));
        $tokens = $stmt->fetchAll();
    } catch (\Throwable $e) {
        // Column not present (older schema) or DB hiccup; nothing to wake.
        return;
    }

    foreach ($tokens as $row) {
        $payload = json_encode(['wake_token' => (string) $row['wake_token'], 'silent' => $silent]);
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
            // best-effort; a gateway hiccup must not fail message delivery
        }
    }
}
