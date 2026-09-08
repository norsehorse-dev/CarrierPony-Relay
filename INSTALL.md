# Self-hosting a CarrierPony relay

The relay is a small PHP application. It stores and forwards end-to-end encrypted
PGP envelopes between devices and never sees plaintext. It holds only ciphertext
plus the minimum routing metadata needed to deliver a message: recipient
fingerprint, an opaque message id, size, and timestamps.

This guide sets up a relay on a fresh server. It is siloed: one relay serves the
people who point their app at it, and they can only exchange messages with each
other. There is no federation between relays.

## Requirements

- Ubuntu 24.04 or similar
- Apache 2.4 with `mod_rewrite`
- PHP 8.1+ with `pdo_mysql`
- MySQL 8
- `gnupg` (the `gpg` binary)
- A domain name and a TLS certificate. HTTPS is not optional. The login step
  sends a nonce and a signature, and those must not travel in clear.

Install the packages:

```
sudo apt update
sudo apt install apache2 mysql-server php php-mysql php-curl libapache2-mod-php gnupg
sudo a2enmod rewrite
```

## 1. Get the code

Put the repository somewhere outside the web root, for example `/opt/carrierpony`.
Only the `public/` directory is ever served.

```
sudo mkdir -p /opt/carrierpony
sudo rsync -a ./ /opt/carrierpony/
```

## 2. Database

Create the database and a user, then load the schema and the migrations in order.

```
sudo mysql <<'SQL'
CREATE DATABASE carrierpony CHARACTER SET utf8mb4;
CREATE USER 'carrierpony'@'127.0.0.1' IDENTIFIED BY 'CHANGE_ME';
GRANT ALL PRIVILEGES ON carrierpony.* TO 'carrierpony'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

cd /opt/carrierpony
mysql -u carrierpony -p carrierpony < schema.sql
for m in migrations/*.sql; do echo "applying $m"; mysql -u carrierpony -p carrierpony < "$m"; done
```

The migrations add the pairing table and the per-device push columns. Applying
them on a fresh `schema.sql` install is safe and leaves you at the current
layout.

## 3. gnupg home

The relay imports each identity's public key and verifies the challenge
signature with `gpg`. It needs a private gnupg home that only the web server user
can read.

```
sudo mkdir -p /var/lib/carrierpony/gnupg
sudo chown www-data:www-data /var/lib/carrierpony/gnupg
sudo chmod 700 /var/lib/carrierpony/gnupg
```

## 4. config.php

Copy the sample and fill it in. It lives above the web root and is never served.

```
cd /opt/carrierpony
cp config.sample.php config.php
$EDITOR config.php
```

Set the database password to the one from step 2 and confirm `gnupg_home` points
at the directory from step 3. Leave the push blocks commented out unless you have
read the push section below.

## 5. Apache virtual host

Point `DocumentRoot` at `public/` and allow the `.htaccess` rewrite that routes
every request to `index.php`.

```
<VirtualHost *:443>
    ServerName relay.example.com
    DocumentRoot /opt/carrierpony/public

    <Directory /opt/carrierpony/public>
        AllowOverride All
        Require all granted
    </Directory>

    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/relay.example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/relay.example.com/privkey.pem
</VirtualHost>
```

A certificate from Let's Encrypt works:

```
sudo apt install certbot python3-certbot-apache
sudo certbot --apache -d relay.example.com
```

Reload Apache after enabling the site:

```
sudo a2ensite carrierpony
sudo systemctl reload apache2
```

## 6. Scheduled cleanup

`src/reaper.php` deletes expired messages, fully acknowledged messages, stale
login nonces, and expired pairing offers. Run it every few minutes from cron.

```
*/5 * * * * www-data php /opt/carrierpony/src/reaper.php >> /var/log/carrierpony-reaper.log 2>&1
```

To also reap devices that stop checking in (so they don't pin messages until
TTL), set `'device_stale_days' => 30` in config.php.

## 7. Verify

The challenge endpoint is a good smoke test. It returns a one-time nonce for any
well-formed fingerprint.

```
curl -sS -X POST https://relay.example.com/v1/challenge \
  -H 'Content-Type: application/json' \
  -d '{"fpr":"0000000000000000000000000000000000000000"}'
```

A JSON body with a `nonce` field means the relay is up and reachable. A `404`
means the rewrite isn't active; a `500` usually means `config.php` or the
database is wrong.

## 8. Point a client at it

In the iOS app: Settings > Relay > enter `https://relay.example.com`, tap Test
Connection, then Use This Relay and relaunch the app. Everyone you want to talk
to must set the same relay, and pairing happens on that relay, so switch before
you pair or re-pair afterward.

## 9. Push notifications

Push is off by default and for a self-hosted relay it should stay off. Waking the
CarrierPony app in the background needs the app publisher's APNs key (iOS) and
Firebase service account (Android), both tied to the published app. You do not
have those for an App Store or Play Store install, so a self-hosted relay cannot
push to it. With push off nothing breaks: the app receives messages by polling
while it is open. The push config blocks only make sense if you are also building
and distributing your own CarrierPony app with your own credentials.

## Security notes

- Serve over HTTPS only. Do not expose the relay on plain http.
- Keep `config.php`, `src/`, and the gnupg home above or outside the web root.
  Only `public/` should be reachable.
- The relay never holds plaintext or private keys. The worst a relay operator can
  see is ciphertext and routing metadata (who has messages waiting, sizes,
  timing). Run it somewhere you control.

Apache-2.0.
