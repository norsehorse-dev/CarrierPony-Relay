<?php

require_once __DIR__ . '/db.php';

$db = cp_db();

$days = (int) (cp_config()['device_stale_days'] ?? 0);
$staleDevices = 0;
if ($days > 0) {
    $staleDevices = $db->exec(
        "DELETE FROM devices WHERE last_seen IS NOT NULL AND last_seen < DATE_SUB(UTC_TIMESTAMP(), INTERVAL $days DAY)"
    );
}

$expiredMessages = $db->exec('DELETE FROM messages WHERE expires_at <= UTC_TIMESTAMP()');

$ackedMessages = $db->exec(
    'DELETE m FROM messages m
     WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_pk = m.id AND d.acked_at IS NULL)'
);

$staleChallenges = $db->exec('DELETE FROM challenges WHERE expires_at <= UTC_TIMESTAMP()');

$expiredSealed = $db->exec('DELETE FROM sealed_messages WHERE expires_at <= UTC_TIMESTAMP()');
$staleMailboxes = $db->exec(
    'DELETE FROM mailboxes
     WHERE expires_at <= UTC_TIMESTAMP()
       AND NOT EXISTS (SELECT 1 FROM sealed_messages s WHERE s.mailbox = mailboxes.mailbox)'
);

// Anonymous sealed devices are never otherwise removed. Reap ones idle well
// past the max message TTL (default 60 days), so cascading their mailboxes
// cannot cut off a still-live message. Keep the default above 2x the TTL.
$sdays = (int) (cp_config()['sealed_device_stale_days'] ?? 60);
$staleSealedDevices = 0;
if ($sdays > 0) {
    $staleSealedDevices = $db->exec(
        "DELETE FROM sealed_devices WHERE last_seen IS NOT NULL AND last_seen < DATE_SUB(UTC_TIMESTAMP(), INTERVAL $sdays DAY)"
    );
}

$staleOffers = $db->exec('DELETE FROM pairing_offers WHERE expires_at <= UTC_TIMESTAMP()');

printf(
    "%s reaper: expired_messages=%d acked_messages=%d stale_challenges=%d stale_devices=%d stale_offers=%d expired_sealed=%d stale_mailboxes=%d stale_sealed_devices=%d\n",
    gmdate('Y-m-d H:i:s'),
    $expiredMessages,
    $ackedMessages,
    $staleChallenges,
    $staleDevices,
    $staleOffers,
    $expiredSealed,
    $staleMailboxes,
    $staleSealedDevices
);
