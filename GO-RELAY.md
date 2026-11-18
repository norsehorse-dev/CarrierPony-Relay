# The Go relay

The relay is being rewritten in Go. The Go relay serves the same endpoints as the
PHP one, with the same answers, so every CarrierPony app works with either. It
is one static binary with no PHP, no Apache module and no gpg, and it can keep
its data in a single SQLite file instead of a MySQL server.

**Status: preview.** The PHP relay is still what `install.sh` and the Docker
image set up, and what [INSTALL.md](INSTALL.md) describes. That changes in the
2.0.0 release. Until then this page is for people who want to run the Go relay
early.

Both relays are held to the same test, `tests/parity_test.py`, which checks the
status code and JSON of every endpoint, every refusal included.

## Build

You need Go 1.24 or later.

```
go build -o carrierpony-relay ./cmd/carrierpony-relay
sudo install -m 755 carrierpony-relay /usr/local/bin/carrierpony-relay
```

## A new relay

A new relay needs no database server. Create a user for it and a config:

```
sudo useradd --system --home-dir /var/lib/carrierpony --shell /usr/sbin/nologin carrierpony
sudo install -d -m 750 -o root -g carrierpony /etc/carrierpony
sudo install -m 640 -o root -g carrierpony config.sample.toml /etc/carrierpony/config.toml
```

The sample works as it is: SQLite at `/var/lib/carrierpony/relay.db`, listening
on `127.0.0.1:8080`, push through the CarrierPony gateway for users who opt in.
Then install the service:

```
sudo install -m 644 contrib/systemd/carrierpony-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now carrierpony-relay
```

The relay speaks plain HTTP on loopback. Put a web server in front of it for
TLS, as described under "The web server in front" below.

## Moving a PHP relay to Go

The Go relay uses the same MySQL tables as the PHP relay. Nothing is converted
and nothing is lost: accounts, devices and queued messages stay where they are,
and you can go back to PHP by undoing the last step.

1. Back up the database.

2. Install the binary (see Build) and create the user and `/etc/carrierpony` as
   for a new relay, without copying the sample config.

3. Write `config.toml` from your `config.php`. This reads the PHP file with the
   `php` already on the server and prints anything it did not carry over:

   ```
   sudo carrierpony-relay convert-config -out /etc/carrierpony/config.toml /opt/carrierpony/config.php
   sudo chown root:carrierpony /etc/carrierpony/config.toml
   sudo chmod 640 /etc/carrierpony/config.toml
   ```

   If the relay pushes with its own APNs key or Firebase service account, the
   `carrierpony` user must be able to read those files too.

4. Bring the tables up to date. It is safe to run on a database that already
   is:

   ```
   sudo -u carrierpony carrierpony-relay migrate -config /etc/carrierpony/config.toml
   ```

5. Start it. It listens on `127.0.0.1:8080` and the PHP relay keeps serving the
   public address, so nothing has changed for your users yet:

   ```
   sudo install -m 644 contrib/systemd/carrierpony-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now carrierpony-relay
   curl -sS -X POST http://127.0.0.1:8080/v1/challenge -d '{"fpr":"0000000000000000000000000000000000000000"}'
   ```

   A JSON body with a `nonce` means it is up. If it does not start,
   `journalctl -u carrierpony-relay` says why.

6. Point the web server at it (next section) and reload the web server.

7. Remove the PHP relay's cron line, `/etc/cron.d/carrierpony-reaper`. The Go
   relay cleans up after itself.

To go back, restore the web server's old configuration and reload it. Both
relays can run against the same database at the same time.

One thing to check before step 6 on a busy relay. The Go relay stores times in
UTC. The PHP relay left `received_at` to MySQL, which uses the server's time
zone. If these two differ, messages stored just before and just after the switch
can be delivered out of order until the older ones are collected:

```
mysql -e "SELECT NOW(), UTC_TIMESTAMP()"
```

## The web server in front

The relay must be reached over HTTPS only. Whatever terminates TLS has to allow
request bodies as large as your biggest envelope in base64: about 35 MB with the
default `max_envelope_bytes`.

Caddy gets and renews the certificate itself:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    client_max_body_size 40m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

Apache, for a relay that was serving the PHP relay from the same virtual host.
Enable the modules with `sudo a2enmod proxy proxy_http`, then replace the
`DocumentRoot` and `<Directory>` lines with:

```
ProxyPreserveHost On
ProxyTimeout 300
ProxyPass        / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
```

On Fedora and RHEL, SELinux also has to let the web server connect out:
`sudo setsebool -P httpd_can_network_connect 1`.

## Commands

```
carrierpony-relay serve   -config FILE    run the relay (the default command)
carrierpony-relay migrate -config FILE    create or update the MySQL tables
carrierpony-relay reap    -config FILE    one clean-up pass, printed as one line
carrierpony-relay convert-config [-out FILE] config.php
carrierpony-relay version
```

`-config` defaults to `/etc/carrierpony/config.toml`. A setting the relay does
not know is an error, so a misspelled name cannot quietly leave a default in
place. [config.sample.toml](config.sample.toml) describes every setting.

## SQLite

The database is one file, plus `-wal` and `-shm` files next to it while the
relay runs. To back it up while the relay is running, do not copy the file. Ask
SQLite for a consistent copy:

```
sudo -u carrierpony sqlite3 /var/lib/carrierpony/relay.db ".backup '/var/lib/carrierpony/relay-backup.db'"
```

SQLite suits a relay for a household, a team or a few hundred people. A relay
that expects more should use MySQL or MariaDB.

## What is different from the PHP relay

For the apps, nothing. For whoever runs it:

- Logins are checked by the relay itself. There is no gpg home and no
  `cp-verify` binary.
- Expired and delivered rows are removed by the relay every few minutes
  (`reap_every_minutes`). No cron job.
- A relay with its own push credentials refuses to start if it cannot read the
  key, instead of running and silently pushing nothing.
- Pushes and gateway wakes are sent after the sender has been answered, so a
  slow push service no longer slows down sending.
- The Firebase access token is kept in memory. The `token_cache` file is not
  used.
