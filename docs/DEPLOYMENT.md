# RecoverBull deployment

This repository contains templates for one service instance:

* binary: `/opt/recoverbull/bin/keychain`
* user/group: `recoverbull:recoverbull`
* working and data directory: `/var/lib/recoverbull`
* dotenv: `/var/lib/recoverbull/.env` (read from the working directory)
* Axum: `127.0.0.1:3001` → reference Caddy:
  `127.0.0.1:3000` → Tor onion service

The model requires strict single-instance operation. The binary does not
enforce that requirement, and only warns when bound publicly. Stop the old
instance before starting a replacement; never overlap them. Do not restart
daily: the in-memory wipe is internal and runs every 24 hours. An exceptional
restart resets the budget and collection.

For the SQLite backup, verification, and restore drill, follow
[deploy/backup/README.md](../deploy/backup/README.md).

The application grace period is 35 seconds, and it is one budget for both
halves of stopping: Axum draining its in-flight requests, and the detached
SQLite work those requests handed to blocking threads. The process bounds
both itself — it builds its Tokio runtime explicitly and stops waiting for
detached work when the period is spent — so `TimeoutStopSec=40s` is the outer
safety net rather than the only bound. Blocking work is not cancellable, so a
thread may still be finishing when the process exits; that is why the SQLite
operations are transactional. `Restart=no` avoids turning a crash loop into
repeated budget resets.
`LimitCORE=0`, `UMask=0077`, and the SQLite-compatible sandbox are intentional.
`MemoryMax=512M` is a reference gate, not a universal guarantee. Startup reads
the limit the kernel will actually enforce on the process from the cgroup and
sizes `RATE_LIMIT_MAX_IDENTIFIERS` against the lower of that and
`RATE_LIMIT_MEMORY_BUDGET_MB`, using the measured per-entry cost and the
configured `RATE_LIMIT_MAX_ATTEMPTS`. It refuses to start rather than let the
cgroup kill a full map mid-snapshot — which, with `Restart=no`, would leave the
service down until an operator intervenes. Lowering `MemoryMax` therefore
tightens the capacity check automatically, and startup warns when the enforced
limit overrides the declared budget. Still declare
`RATE_LIMIT_MEMORY_BUDGET_MB`: it is the only bound when the service runs
without a cgroup memory limit.

At the default capacity (100,000 identifiers, 3 `secret_id` values) a release build
measured 117 MB peak RSS, 22.1 MB JSON, and 4.01 MB gzip; an earlier audit
recorded about 254 MiB peak on a different host with the same gzip size. Both
are far above the 150-180 bytes per entry the code used to claim, which is why
the fixed capacity ceiling was replaced by the budget check. Per-entry cost is
dominated by the `secret_id` budget, so re-measure RSS after changing
`RATE_LIMIT_MAX_ATTEMPTS` or the identifier cap before selecting a value:

```sh
# with the service running under its real configuration, after the map has
# filled and at least one /attempts snapshot has been built
grep VmHWM /proc/$(systemctl show -p MainPID --value recoverbull)/status
```

## Log volume and retention

The service writes little: one `WARN` line per server error, one aggregate
counter line every five minutes at `info`, and a few lifecycle lines. A `503`
is never logged per request, so an exhausted token bucket cannot fill the
disk. There is no in-process log quota; volume control belongs here.

`systemd-journald` rate-limits per service, 10,000 messages per 30 seconds by
default, and records a "suppressed N messages" line when it does. Set an
explicit policy in a drop-in if the default is not wanted:

```ini
# /etc/systemd/system/recoverbull.service.d/logging.conf
[Service]
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
```

Never run a live service with `RUST_LOG=trace`: Axum traces extractor
rejections at that level with a message derived from the request body. The
reference `RUST_LOG` is `info`. Reverse-proxy and Tor logs are not covered by
the application's log guarantees. The reference Caddy proxy sends its error
log to journald; configure its service's journald retention explicitly.
`deploy/logrotate/recoverbull` belongs only to the unsupported nginx migration
aid. [docs/RETENTION.md](RETENTION.md) governs retention.

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
path, loopback address, canary, cooldown, and `secret_id` budget; this document
does not provide example secrets or canary values. Keep the SQLite database,
WAL, and any Litestream state below `/var/lib/recoverbull`.

Install the maintained application and Tor templates without changing their
concrete paths:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/recoverbull.service /etc/systemd/system/recoverbull.service
sudo install -o root -g root -m 0644 deploy/tor/recoverbull.torrc.example /etc/tor/conf.d/recoverbull.conf
```

Follow [deploy/caddy/README.md](../deploy/caddy/README.md) for the pinned custom
build, vulnerability gates, atomic binary/config installation, service
ownership, and validation. The repository does not provide a versioned Caddy
systemd unit, so the operator must provide one whose error output goes to
journald. Caddy is admissible only after the documented checks and HTTP smokes
pass.

`deploy/nginx/recoverbull.conf` and `deploy/logrotate/recoverbull` are
unsupported migration aids for operators who already run nginx. They have no
executable smoke or CI coverage. An operator retaining them owns validation,
upgrades, and any divergence from the reference Caddy behavior. Never install
or start both listeners.

The Tor service account must be able to create and read
`/var/lib/tor/recoverbull/`; do not copy its private hostname keys into this
repository. Adjust the distribution-specific Tor include path only when the
local package requires it.

Validate before starting, using the privileges required by each installed
service:

```sh
sudo systemd-analyze verify /etc/systemd/system/recoverbull.service
/path/to/caddy adapt --config /path/to/Caddyfile --adapter caddyfile --validate
/path/to/caddy validate --config /path/to/Caddyfile --adapter caddyfile
python3 deploy/caddy/smoke.py /path/to/caddy
sudo -u debian-tor tor --verify-config -f /etc/tor/conf.d/recoverbull.conf
```

If the Tor account is named differently, use that account. `systemd-analyze`
can validate the unit without starting it; Caddy and Tor validation may need
their service accounts because the configured directories are private.
The unit's `ProtectSystem=full` leaves the system tree protected while
`ReadWritePaths=/var/lib/recoverbull` permits SQLite's database and WAL. Its
address-family restriction permits loopback TCP and Unix sockets, not public
exposure policy; the binary's public-bind behavior remains a warning by design.

Start in dependency order and smoke-test each boundary:

```sh
sudo systemctl daemon-reload
sudo systemctl enable recoverbull caddy tor
sudo systemctl start recoverbull
sudo systemctl start caddy
sudo systemctl start tor
curl --fail http://127.0.0.1:3000/info
curl --fail --compressed http://127.0.0.1:3000/attempts
```

Here `caddy` is the operator-provided service described in its README; substitute
its actual unit name if different.

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
