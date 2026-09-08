#!/bin/sh
# Generate config.php from the environment on first boot, prepare the gnupg
# home, then hand off to Apache. Push stays off for a self-hosted relay; see
# INSTALL.md for why. config.php is regenerated only when absent, so a mounted
# config is respected.
set -e

CONFIG=/var/www/html/config.php
if [ ! -f "$CONFIG" ]; then
  cat > "$CONFIG" <<PHP
<?php

return [
    'db' => [
        'host'    => '${DB_HOST:-db}',
        'name'    => '${DB_NAME:-carrierpony}',
        'user'    => '${DB_USER:-carrierpony}',
        'pass'    => '${DB_PASSWORD}',
        'charset' => 'utf8mb4',
    ],
    'gnupg_home'           => '/var/lib/carrierpony/gnupg',
    'challenge_ttl'        => 300,
    'message_ttl_max_days' => 30,
    'max_envelope_bytes'   => 26214400,
];
PHP
fi

mkdir -p /var/lib/carrierpony/gnupg
chown -R www-data:www-data /var/lib/carrierpony/gnupg
chmod 700 /var/lib/carrierpony/gnupg

exec "$@"
