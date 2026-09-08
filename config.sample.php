<?php

// CarrierPony relay configuration. Copy to config.php and fill in.
// config.php sits above the web root and is never served.

return [
    'db' => [
        'host'    => '127.0.0.1',
        'name'    => 'carrierpony',
        'user'    => 'carrierpony',
        'pass'    => 'CHANGE_ME',
        'charset' => 'utf8mb4',
    ],

    // Where the relay keeps its gnupg home (used to import public keys and
    // verify the challenge signatures). Must be writable by the web server
    // user and nothing else. See INSTALL.md.
    'gnupg_home'            => '/var/lib/carrierpony/gnupg',

    'challenge_ttl'         => 300,        // seconds a login nonce stays valid
    'message_ttl_max_days'  => 30,         // hard cap on how long a message is held
    'max_envelope_bytes'    => 26214400,   // reject envelopes larger than this

    // Push notifications are OFF by default, and that is the right setting for
    // almost every self-hosted relay. Waking the CarrierPony app in the
    // background requires the app publisher's own APNs key (iOS) and Firebase
    // service account (Android), both tied to the published bundle/app id. A
    // third party does not have those, so a self-hosted relay cannot push to
    // installs from the App Store or Play Store. With push off, clients still
    // receive everything by polling while the app is open. Only enable these if
    // you are also shipping your own CarrierPony build with your own
    // credentials.
    //
    // 'apns' => [
    //     'enabled'     => false,
    //     'key_file'    => '/etc/carrierpony/AuthKey_XXXXXXXXXX.p8',
    //     'key_id'      => 'XXXXXXXXXX',
    //     'team_id'     => 'XXXXXXXXXX',
    //     'bundle_id'   => 'com.example.yourapp',
    //     'environment' => 'production', // or 'sandbox' for a dev build
    // ],
    //
    // 'fcm' => [
    //     'enabled'              => false,
    //     'service_account_file' => '/etc/carrierpony/fcm-service-account.json',
    //     'token_cache'          => '/var/lib/carrierpony/fcm-token.json',
    // ],
];
