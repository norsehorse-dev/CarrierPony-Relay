#!/bin/sh
# Generate config.php from the environment on first boot, prepare the gnupg
# home, bring the database up to date, then hand off to Apache. Push stays off
# for a self-hosted relay; see INSTALL.md for why. config.php is regenerated
# only when absent, so a mounted config is respected.
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
    'verifier_bin'         => '/usr/local/bin/cp-verify',
    'challenge_ttl'        => 300,
    'message_ttl_max_days' => 30,
    'max_envelope_bytes'   => 26214400,
];
PHP
fi

mkdir -p /var/lib/carrierpony/gnupg
chown -R www-data:www-data /var/lib/carrierpony/gnupg
chmod 700 /var/lib/carrierpony/gnupg

# The database container loads the schema and migrations only when its volume is
# first created. A relay that was already running needs the newer migrations
# too, so they are applied here on every start. Each one changes something only
# when it is missing, so running them again does nothing. If the database is not
# reachable after a minute the relay still starts, and the next start tries again.
ready=0
i=0
while [ "$i" -lt 30 ]; do
  if php -r '
    $c = require "/var/www/html/config.php"; $d = $c["db"];
    try { new PDO("mysql:host={$d["host"]};dbname={$d["name"]};charset={$d["charset"]}", $d["user"], $d["pass"]); }
    catch (Throwable $e) { exit(1); }
  ' 2>/dev/null; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 2
done
if [ "$ready" -eq 1 ]; then
  for m in /var/www/html/migrations/*.sql; do
    php /var/www/html/tools/apply_migration.php /var/www/html "$m" >/dev/null \
      || echo "carrierpony: migration $(basename "$m") failed, see the database log" >&2
  done
else
  echo "carrierpony: database not reachable yet, migrations not applied on this start" >&2
fi

exec "$@"
