# CarrierPony Relay

Store-and-forward relay for CarrierPony. It carries end-to-end encrypted PGP envelopes between devices and never sees plaintext. Identity is a PGP key fingerprint; authentication is a challenge-response signature with that key. The relay holds only ciphertext plus the minimum routing metadata needed to deliver: recipient fingerprint, an opaque message id, size, and timestamps.

Self-hostable. Apache-2.0.

## Self-hosting

Three ways to stand up your own relay.

**Docker (recommended).** The most portable option: it runs the same on any
Linux with Docker (Debian, Ubuntu, Fedora, RHEL, Arch, ...) and never touches
the host's packages. With Docker installed and a domain pointed at your server:

```
cp .env.example .env
```

Edit `.env` to set `DOMAIN` and the database passwords, then:

```
docker compose up -d
```

Caddy fetches a Let's Encrypt certificate for your domain automatically, the
schema and migrations load on first boot, and the relay comes up at
`https://your-domain`. The image builds the login verifier from source, and the
container applies any newer migrations each time it starts.

**Installer.** A bare-metal install for the Debian/Ubuntu family (Apache +
MySQL or MariaDB) or the Fedora/RHEL family (httpd + MariaDB + SELinux). Run
from the repository directory:

```
sudo ./install.sh
```

It installs Apache, MySQL, PHP and gnupg, creates the database, loads the
schema, writes `config.php`, sets up the virtual host, and requests a
certificate. It also installs the login verifier: built from source when Go is
installed, otherwise the binary published with the release, checked against the
SHA-256 in `verifier/RELEASE`. Run on a server that already has a relay, it keeps
`config.php` and applies the newer migrations.

**By hand.** [INSTALL.md](INSTALL.md) walks through every step manually, and
covers upgrading a relay that is already running.

**OpenPGP v6 accounts.** CarrierPony 4.0 and later create v6 identities, which
`gpg` cannot verify. The relay checks those logins with `cp-verify`, a small Go
program in `verifier/`. A relay without it still serves v4 accounts, but new 4.0
accounts cannot register on it.

A self-hosted relay runs without push notifications, and that is expected:
waking the app in the background needs the app publisher's APNs and Firebase
credentials, which a third party does not have. Clients still receive messages
by polling while the app is open. Point the app at your relay in Settings >
Relay.

## Requirements

- Ubuntu 24.04 or similar
- Apache 2.4 with mod_rewrite
- PHP 8.1+ with pdo_mysql
- MySQL 8
- gnupg (the `gpg` binary)
- Go 1.23+ to build the login verifier, unless you use the published binary

## Layout

```
config.sample.php   copy to config.php and fill in
schema.sql          database tables
migrations/         changes since the first schema, safe to re-apply
verifier/           cp-verify, the login signature verifier (Go)
tests/              contract tests run against a local relay
src/                db, auth, response helpers, request handlers
public/             web root (DocumentRoot points here)
```

The web server document root must be `public/`. Everything in `src/` and `config.php` sits above the web root and is not served.

## Endpoints

All POST, JSON in and out, paths tolerate an optional trailing slash.

- `POST /v1/challenge` — `{ fpr }` returns a one-time `nonce`. `fpr` is 40 hex characters for a v4 key, 64 for v6.
- `POST /v1/register-device` — `{ fpr, pubkey, device_id, nonce, sig, label? }`. Imports the public key, verifies the self-signature over the nonce, registers the identity and device.
- `POST /v1/send` — auth `{ fpr, nonce, sig }` plus `{ to_fpr, envelope, expires_at? }`. `envelope` is base64. Fans out a delivery row per registered recipient device.
- `POST /v1/inbox` — auth plus `{ device_id }`. Returns unacked, unexpired envelopes for that device.
- `POST /v1/ack` — auth plus `{ device_id, message_ids[] }`. Marks per-device delivery. A message is deleted once every registered device has acked it, or when its TTL passes.
- `POST /v1/register-push` — auth plus `{ device_id, push_token }`.

## Self-sync

Read state, deletions, and disappearing-message expiry are coordinated across a user's own devices by ordinary envelopes addressed to the sender's own fingerprint. No separate endpoint: the relay cannot tell them from normal traffic beyond the recipient being self.

## Notes and hardening (not yet done)

- Serve over HTTPS only in production. Auth nonces and signatures must not travel in clear.
- The auth signature currently covers only the nonce. Binding it to the request body would prevent replay with a different body.
- A device staleness or deregistration policy should reap devices that never return, so they do not pin envelopes until TTL.
- A scheduled job should expire old challenges and TTL-elapsed messages independently of ack traffic.
