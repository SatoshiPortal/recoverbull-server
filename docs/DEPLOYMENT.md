# RecoverBull deployment

This repository contains templates for one service instance:

* binary: `/opt/recoverbull/bin/keychain`
* user/group: `recoverbull:recoverbull`
* working and data directory: `/var/lib/recoverbull`
* dotenv: `/var/lib/recoverbull/.env` (read from the working directory)
* Axum: `127.0.0.1:3001` → reference nginx (or the conditional Caddy
  alternative): `127.0.0.1:3000` → Tor onion service

The model requires strict single-instance operation. The binary does not
enforce that requirement, and only warns when bound publicly. Stop the old
instance before starting a replacement; never overlap them. Do not restart
daily: the in-memory wipe is internal and runs every 24 hours. An exceptional
restart resets the budget and collection.

For the SQLite backup, verification, and restore drill, follow
[deploy/backup/README.md](../deploy/backup/README.md).

The application grace period is 35 seconds. systemd allows 40 seconds for
stop, and `Restart=no` avoids turning a crash loop into repeated budget resets.
`LimitCORE=0`, `UMask=0077`, and the SQLite-compatible sandbox are intentional.
`MemoryMax=512M` is a reference gate, not a universal guarantee: the README's
default-capacity measurement reached about 254 MiB peak RSS on one host, so
measure RSS
with the configured identifier cap and snapshot size before selecting a value.

## Reproducible installation

The commands below use sample paths and never contain a secret. Run privileged
commands as `root` or through `sudo`; keep the operator-selected `.env` values
out of shell history and version control.

```sh
getent passwd recoverbull >/dev/null || sudo useradd --system --home-dir /var/lib/recoverbull --shell /usr/sbin/nologin recoverbull
sudo install -d -o recoverbull -g recoverbull -m 0700 /var/lib/recoverbull
sudo install -d -o root -g root -m 0755 /opt/recoverbull/bin
sudo install -o root -g root -m 0755 ./keychain /opt/recoverbull/bin/keychain
sudo touch /var/lib/recoverbull/.env
sudo chown recoverbull:recoverbull /var/lib/recoverbull/.env
sudo chmod 0600 /var/lib/recoverbull/.env
```

Populate `.env` using the operator's secret-management procedure. It must
contain the deployment values required by the server, including the database
path, loopback address, canary, cooldown, and candidate budget; this document
does not provide example secrets or canary values. Keep the SQLite database,
WAL, and any Litestream state below `/var/lib/recoverbull`.

Install the maintained application, Tor, and logging templates without changing
their concrete paths. Nginx is the default runbook path; choose exactly one
reverse proxy and never install/start both listeners:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/recoverbull.service /etc/systemd/system/recoverbull.service
sudo install -o root -g root -m 0644 deploy/nginx/recoverbull.conf /etc/nginx/conf.d/recoverbull.conf
sudo install -o root -g root -m 0644 deploy/tor/recoverbull.torrc.example /etc/tor/conf.d/recoverbull.conf
sudo install -o root -g root -m 0644 deploy/logrotate/recoverbull /etc/logrotate.d/recoverbull
```

To choose Caddy instead, do not install the nginx template. Follow
[deploy/caddy/README.md](../deploy/caddy/README.md) for the pinned custom build,
atomic binary/config installation, service ownership, and Caddy validation; the
repository does not provide a versioned Caddy systemd unit. Caddy is admissible
only after those checks and its required HTTP smokes pass.

The Tor service account must be able to create and read
`/var/lib/tor/recoverbull/`; do not copy its private hostname keys into this
repository. Adjust the distribution-specific Tor include path only when the
local package requires it.

Validate before starting, using the privileges required by each installed
service:

```sh
sudo systemd-analyze verify /etc/systemd/system/recoverbull.service
sudo nginx -t
sudo -u debian-tor tor --verify-config -f /etc/tor/conf.d/recoverbull.conf
```

For the exclusive Caddy choice, replace `nginx -t` with the `adapt --validate`
and `validate` commands in the Caddy README. Do not start either proxy until
its validation succeeds.

If the Tor account is named differently, use that account. `systemd-analyze`
can validate the unit without starting it; nginx and Tor validation may need
root or their service account because the configured directories are private.
The unit's `ProtectSystem=full` leaves the system tree protected while
`ReadWritePaths=/var/lib/recoverbull` permits SQLite's database and WAL. Its
address-family restriction permits loopback TCP and Unix sockets, not public
exposure policy; the binary's public-bind behavior remains a warning by design.

Start in dependency order and smoke-test each boundary:

```sh
sudo systemctl daemon-reload
sudo systemctl enable recoverbull nginx tor
sudo systemctl start recoverbull
sudo systemctl start nginx
sudo systemctl start tor
curl --fail http://127.0.0.1:3000/info
curl --fail --compressed http://127.0.0.1:3000/attempts
```

For Caddy, enable/start the operator-provided Caddy service instead of nginx,
using the start/stop procedure in `deploy/caddy/README.md`; never run both.

Run store/fetch/trash with a test fixture appropriate to the environment, then
verify the canary and inspect `systemctl status` and restricted logs before
admitting onion traffic. Monitor process liveness, memory against the measured
capacity, disk/WAL growth, canary changes, unexpected snapshot activity, and
`429` alarms. `Restart=no` is intentional: an exited process requires manual
investigation and recovery rather than an automatic in-memory budget reset.

## Rollback and manual recovery

Do not perform a rolling replacement. Stop Tor first, then the selected proxy,
then RecoverBull, and verify the old process is gone before replacing the binary or
configuration. Start the replacement in the same order as above and repeat the
smokes. Keep the previous binary and configuration outside the data directory
for a tested rollback; never restore them while an old instance is running.

For an outage, preserve the existing database/WAL and follow
[RETENTION.md](RETENTION.md)'s restore and rollback checks. Recovery after an
inaccessible wallet is available only through a previously exported Backup Key
or a second independent server; do not imply that an export can be created
after access is lost.

The [RecoverBull whitepaper repository](https://github.com/SatoshiPortal/recoverbull-whitepaper)
contains the conceptual whitepaper and is the publication location for the
normative protocol specification. This server revision must not be delivered
until `SPECIFICATION.md` has been published in that repository; do not replace
this statement with a link to the file before it exists.
