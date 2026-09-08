#!/usr/bin/env bash
#
# CarrierPony relay installer for a fresh Ubuntu/Debian server with Apache,
# MySQL and PHP. It installs dependencies, creates the database, loads the
# schema and migrations, prepares the gnupg home, writes config.php, and sets
# up an Apache virtual host with a Let's Encrypt certificate.
#
# For a container-based install use Docker instead (see README.md). Push stays
# off; a self-hosted relay cannot wake App Store / Play installs (see INSTALL.md).
#
# Run as root from the repository directory:  sudo ./install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root: sudo ./install.sh" >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read -rp "Relay domain (e.g. relay.example.com): " DOMAIN
read -rp "Database name [carrierpony]: " DB_NAME
DB_NAME="${DB_NAME:-carrierpony}"
read -rp "Database user [carrierpony]: " DB_USER
DB_USER="${DB_USER:-carrierpony}"
read -rsp "Database password: " DB_PASS
echo

if [ -z "$DOMAIN" ] || [ -z "$DB_PASS" ]; then
  echo "Domain and database password are required." >&2
  exit 1
fi

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apache2 mysql-server php php-mysql php-curl libapache2-mod-php gnupg certbot python3-certbot-apache
a2enmod rewrite

echo "==> Creating database and user"
mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

echo "==> Loading schema and migrations"
mysql "$DB_NAME" < "$APP_DIR/schema.sql"
for m in "$APP_DIR"/migrations/*.sql; do
  echo "    $(basename "$m")"
  mysql "$DB_NAME" < "$m"
done

echo "==> Preparing gnupg home"
install -d -o www-data -g www-data -m 700 /var/lib/carrierpony/gnupg

echo "==> Writing config.php"
cat > "$APP_DIR/config.php" <<PHP
<?php

return [
    'db' => [
        'host'    => '127.0.0.1',
        'name'    => '${DB_NAME}',
        'user'    => '${DB_USER}',
        'pass'    => '${DB_PASS}',
        'charset' => 'utf8mb4',
    ],
    'gnupg_home'           => '/var/lib/carrierpony/gnupg',
    'challenge_ttl'        => 300,
    'message_ttl_max_days' => 30,
    'max_envelope_bytes'   => 26214400,
];
PHP
chown www-data:www-data "$APP_DIR/config.php"
chmod 640 "$APP_DIR/config.php"

echo "==> Configuring Apache"
cat > "/etc/apache2/sites-available/carrierpony.conf" <<VHOST
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${APP_DIR}/public

    <Directory ${APP_DIR}/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
VHOST
a2ensite carrierpony
a2dissite 000-default || true
systemctl reload apache2

echo "==> Requesting a certificate"
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect || \
  echo "certbot failed; run 'certbot --apache -d $DOMAIN' by hand once DNS is pointed at this server."

echo "==> Installing the cleanup cron"
echo "*/5 * * * * www-data php ${APP_DIR}/src/reaper.php >> /var/log/carrierpony-reaper.log 2>&1" > /etc/cron.d/carrierpony-reaper

echo
echo "Done. Point CarrierPony at https://${DOMAIN} in Settings > Relay."
echo "Verify: curl -sS -X POST https://${DOMAIN}/v1/challenge -H 'Content-Type: application/json' -d '{\"fpr\":\"0000000000000000000000000000000000000000\"}'"
