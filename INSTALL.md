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
- Go 1.23 or later, to build the login verifier (step 4). Only needed at build
  time, and not needed at all if you download the published binary instead.
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

Each migration changes something only when it is missing, so applying them on a
fresh `schema.sql` install is safe, and so is applying them again later. See
"Upgrading an existing relay" below for a relay that is already running.

## 3. gnupg home

The relay imports each identity's public key into a private gnupg home. Without
the login verifier from step 4, `gpg` also checks the challenge signature. It needs a private gnupg home that only the web server user
can read.

```
sudo mkdir -p /var/lib/carrierpony/gnupg
sudo chown www-data:www-data /var/lib/carrierpony/gnupg
sudo chmod 700 /var/lib/carrierpony/gnupg
```

## 4. Login verifier (cp-verify)

CarrierPony 4.0 and later create OpenPGP v6 identities, and `gpg` cannot read v6
keys. `cp-verify` is a small Go program in `verifier/` that checks the login
signature for both v4 and v6 keys. A relay without it keeps working, but only for
v4 accounts: anyone who sets up a new account in CarrierPony 4.0 or later will not
be able to register.

Build it from source with Go 1.23 or later:

```
cd /opt/carrierpony/verifier
CGO_ENABLED=0 go build -trimpath -o cp-verify ./cmd/cp-verify
sudo install -m 755 cp-verify /usr/local/bin/cp-verify
```

If you would rather not install Go, each relay release carries prebuilt Linux
binaries for amd64 and arm64. `verifier/RELEASE` in the repository names the
release tag and the SHA-256 of each binary, so check the download against it
before installing:

```
cd /opt/carrierpony
TAG=$(awk '$1 == "tag" { print $2 }' verifier/RELEASE)
curl -fsSL -o /tmp/cp-verify "https://github.com/norsehorse-dev/CarrierPony-Relay/releases/download/${TAG}/cp-verify-linux-amd64"
echo "$(awk '$1 == "amd64" { print $2 }' verifier/RELEASE)  /tmp/cp-verify" | sha256sum -c -
sudo install -m 755 /tmp/cp-verify /usr/local/bin/cp-verify
```

Use `arm64` in both places on an ARM server. `install.sh` and the Docker image do
this step for you. The installer builds from source when Go is present and
otherwise downloads and checks the published binary. The Docker image always
builds from source.

## 5. config.php

Copy the sample and fill it in. It lives above the web root and is never served.

```
cd /opt/carrierpony
cp config.sample.php config.php
$EDITOR config.php
```

Set the database password to the one from step 2 and confirm `gnupg_home` points
at the directory from step 3. To use the verifier from step 4, uncomment
`verifier_bin`:

```
'verifier_bin' => '/usr/local/bin/cp-verify',
```

Leave the push blocks commented out unless you have
read the push section below.

## 6. Apache virtual host

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

## 7. Scheduled cleanup

`src/reaper.php` deletes expired messages, fully acknowledged messages, stale
login nonces, and expired pairing offers. Run it every few minutes from cron.

```
*/5 * * * * www-data php /opt/carrierpony/src/reaper.php >> /var/log/carrierpony-reaper.log 2>&1
```

To also reap devices that stop checking in (so they don't pin messages until
TTL), set `'device_stale_days' => 30` in config.php.

## 8. Verify

The challenge endpoint is a good smoke test. It returns a one-time nonce for any
well-formed fingerprint (40 hex characters for a v4 key, 64 for v6).

```
curl -sS -X POST https://relay.example.com/v1/challenge \
  -H 'Content-Type: application/json' \
  -d '{"fpr":"0000000000000000000000000000000000000000"}'
```

A JSON body with a `nonce` field means the relay is up and reachable. A `404`
means the rewrite isn't active; a `500` usually means `config.php` or the
database is wrong.

## 9. Point a client at it

In the iOS app: Settings > Relay > enter `https://relay.example.com`, tap Test
Connection, then Use This Relay and relaunch the app. Everyone you want to talk
to must set the same relay, and pairing happens on that relay, so switch before
you pair or re-pair afterward.

## 10. Push notifications

Push is off by default and for a self-hosted relay it should stay off. Waking the
CarrierPony app in the background needs the app publisher's APNs key (iOS) and
Firebase service account (Android), both tied to the published app. You do not
have those for an App Store or Play Store install, so a self-hosted relay cannot
push to it. With push off nothing breaks: the app receives messages by polling
while it is open. The push config blocks only make sense if you are also building
and distributing your own CarrierPony app with your own credentials.

## Upgrading an existing relay

Take a database backup first. Then update the code, apply the migrations and add
the verifier.

```
cd /path/to/CarrierPony-Relay
git pull
sudo rsync -a --exclude config.php ./ /opt/carrierpony/
cd /opt/carrierpony
for m in migrations/*.sql; do sudo php tools/apply_migration.php /opt/carrierpony "$m"; done
```

`tools/apply_migration.php` reads the database settings from `config.php`, so it
asks for no password. Every migration checks before it changes anything, so
running all of them again is safe. The 4.0 migrations widen the fingerprint
columns from 40 to 64 characters for v6 keys, add the alert flag on messages and
add the reports table. Existing accounts and queued messages are kept.

Running `sudo ./install.sh` again from an updated checkout does the same: it
keeps the existing `config.php`, applies the migrations and installs the
verifier. With Docker, `docker compose up -d --build` rebuilds the image, and the
container applies the migrations each time it starts.

### Turning the verifier on with existing accounts

The installer and the Docker image only write `verifier_bin` into a `config.php`
they create. An existing `config.php` is left alone, so add the line from step 5
yourself. If the relay already has accounts and you want to see the verifier agree
with `gpg` before it takes over, turn on shadow mode first:

```
'verifier_bin'    => '/usr/local/bin/cp-verify',
'verifier_shadow' => true,
```

In shadow mode `gpg` still decides every login and `cp-verify` runs alongside. Any
login where the two disagree is written to the PHP error log. v6 accounts are
still refused while shadow mode is on. After a few days with no disagreements,
remove the `verifier_shadow` line and `cp-verify` decides from then on.

## Security notes

- Serve over HTTPS only. Do not expose the relay on plain http.
- Keep `config.php`, `src/`, and the gnupg home above or outside the web root.
  Only `public/` should be reachable.
- The relay never holds plaintext or private keys. The worst a relay operator can
  see is ciphertext and routing metadata (who has messages waiting, sizes,
  timing). Run it somewhere you control.

Apache-2.0.

## Optional: direct WAN paths (STUN)

To let your users set up direct peer-to-peer paths (UDP hole punching) instead of
always going through store-and-forward, run the tiny STUN responder in `stun/`. It is
optional and safe to skip; see `stun/README.md`. In short:

    sudo mkdir -p /opt/carrierpony/stun
    sudo cp stun/ponystun.py /opt/carrierpony/stun/
    sudo cp stun/ponystun.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now ponystun
    sudo ufw allow 3478/udp

Signaling for direct paths rides the sealed relay path, so the STUN responder only
reflects a public address back to the client; it never sees message content or who is
talking to whom.
