#!/usr/bin/env bash
#
# CarrierPony relay installer.
#
# The most portable way to run the relay is Docker (see README.md):
#   docker compose up -d
# works on any Linux with Docker and never touches the host's packages. This
# script is the bare-metal alternative. It supports the Debian/Ubuntu family
# (Apache + MySQL/MariaDB) and the Fedora/RHEL family (httpd + MariaDB, with
# SELinux). It installs the app under /opt/carrierpony, never a home directory,
# which the web server cannot traverse.
#
# On Fedora/RHEL, SELinux and running gpg from PHP can need extra tuning; if the
# bare-metal path fights you there, the Docker path sidesteps all of it.
#
# Push stays off. A self-hosted relay cannot wake App Store / Play installs on
# its own; see the self-host page for the opt-in push gateway.
#
# Safe to re-run. Run as root from the repository directory:  sudo ./install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root: sudo ./install.sh" >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "Cannot detect the distribution. Use the Docker path (README.md)." >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
haystack=" ${ID:-} ${ID_LIKE:-} "
if [[ "$haystack" == *" debian "* || "$haystack" == *" ubuntu "* ]]; then
  FAMILY=debian
  WEB_USER=www-data
elif [[ "$haystack" == *" rhel "* || "$haystack" == *" fedora "* || "$haystack" == *" centos "* ]]; then
  FAMILY=rhel
  WEB_USER=apache
else
  echo "Unsupported distribution '${ID:-unknown}'. The Docker path works everywhere: README.md." >&2
  exit 1
fi
echo "==> Detected ${PRETTY_NAME:-${ID:-unknown}} (${FAMILY} family)"

APP_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/carrierpony"

read -rp "Relay domain (e.g. relay.example.com): " DOMAIN
[ -n "$DOMAIN" ] || { echo "Domain is required." >&2; exit 1; }

if [ "$FAMILY" = debian ]; then
  export DEBIAN_FRONTEND=noninteractive
  echo "==> Installing packages"
  apt-get update
  if [ "${ID:-}" = ubuntu ]; then DB_PKG=mysql-server; else DB_PKG=mariadb-server; fi
  apt-get install -y apache2 "$DB_PKG" php php-mysql php-curl libapache2-mod-php gnupg certbot python3-certbot-apache
  a2enmod rewrite
  WEB_SVC=apache2
  VHOST_PATH=/etc/apache2/sites-available/carrierpony.conf
else
  echo "==> Installing packages"
  dnf install -y epel-release || true
  dnf install -y httpd mod_ssl mariadb-server php php-mysqlnd gnupg2 certbot python3-certbot-apache policycoreutils-python-utils
  systemctl enable --now mariadb
  systemctl enable --now httpd
  WEB_SVC=httpd
  VHOST_PATH=/etc/httpd/conf.d/carrierpony.conf
fi

echo "==> Installing the app into $APP_DIR"
mkdir -p "$APP_DIR"
cp -a "$APP_SRC"/. "$APP_DIR"/
rm -rf "$APP_DIR/.git" "$APP_DIR/.env"

echo "==> Preparing gnupg home"
install -d -o "$WEB_USER" -g "$WEB_USER" -m 700 /var/lib/carrierpony/gnupg

if [ ! -f "$APP_DIR/config.php" ]; then
  read -rp "Database name [carrierpony]: " DB_NAME
  DB_NAME="${DB_NAME:-carrierpony}"
  read -rp "Database user [carrierpony]: " DB_USER
  DB_USER="${DB_USER:-carrierpony}"
  read -rsp "Database password: " DB_PASS
  echo
  [ -n "$DB_PASS" ] || { echo "Database password is required on a first install." >&2; exit 1; }

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
else
  echo "==> Existing config.php found in $APP_DIR, keeping the database and config"
fi
chown "$WEB_USER":"$WEB_USER" "$APP_DIR/config.php"
chmod 640 "$APP_DIR/config.php"

echo "==> Configuring the web server"
cat > "$VHOST_PATH" <<VHOST
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${APP_DIR}/public

    <Directory ${APP_DIR}/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
VHOST

if [ "$FAMILY" = debian ]; then
  a2ensite carrierpony
  a2dissite 000-default || true
fi

if [ "$FAMILY" = rhel ]; then
  echo "==> Configuring SELinux"
  semanage fcontext -a -t httpd_sys_content_t "${APP_DIR}(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t httpd_sys_content_t "${APP_DIR}(/.*)?" || true
  restorecon -Rv "$APP_DIR" || true
  semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/carrierpony/gnupg(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t httpd_sys_rw_content_t "/var/lib/carrierpony/gnupg(/.*)?" || true
  restorecon -Rv /var/lib/carrierpony/gnupg || true
  setsebool -P httpd_can_network_connect_db on || true
fi

systemctl reload "$WEB_SVC" || systemctl restart "$WEB_SVC"

echo "==> Requesting a certificate"
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect || \
  echo "certbot failed; run 'certbot --apache -d $DOMAIN' by hand once DNS is pointed at this server."

echo "==> Installing the cleanup cron"
echo "*/5 * * * * ${WEB_USER} php ${APP_DIR}/src/reaper.php >> /var/log/carrierpony-reaper.log 2>&1" > /etc/cron.d/carrierpony-reaper

echo
echo "Done. Point CarrierPony at https://${DOMAIN} in Settings > Relay."
echo "Verify: curl -sS -X POST https://${DOMAIN}/v1/challenge -H 'Content-Type: application/json' -d '{\"fpr\":\"0000000000000000000000000000000000000000\"}'"
