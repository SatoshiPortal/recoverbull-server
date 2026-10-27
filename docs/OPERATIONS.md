# Deploying and operating RecoverBull

Configure the binary, nginx and Tor separately, keeping your own directories, service user, process manager and backup setup. The Debian/systemd commands below are examples to adapt to your host.

```text
Tor onion :80 → nginx 127.0.0.1:3000 → RecoverBull 127.0.0.1:3001 → SQLite
```

nginx is required: it bounds slow requests, caches `/attempts` and applies limits per Tor circuit. Keep both listeners on loopback. Run **one server instance only**; attempt budgets live in memory and reset on every restart. Schedule restarts deliberately.

## 1. Check versions and packages

Review installed versions and available security updates for Rust, nginx, Tor, SQLite and the other host packages. Install missing build tools and services with your package manager; for example, on Debian:

```sh
sudo apt update
apt-cache policy nginx tor sqlite3
sudo apt install build-essential git curl nginx tor sqlite3
```

If Rust is missing, install it with [rustup](https://rust-lang.org/learn/get-started/). Use the version pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) and keep `Cargo.lock`. Review newer releases separately. SQLite is bundled into the server: updating the system `sqlite3` command does not update the server's SQLite library.

## 2. Back up an existing installation

Identify the active binary, service user, working directory, `.env`, database file and Tor `HiddenServiceDir`. Record the current revision and keep the old binary and configuration. **Preserve the actual database path and onion keys**: a new database filename can silently create an empty database; new onion keys change the server address.

As the database owner, make a consistent backup in a private directory writable by that owner, using a new destination filename:

```sh
/path/to/recoverbull backup /path/to/production_db.sqlite3 /private/backups/before-upgrade.sqlite3
```

This includes the WAL, checks integrity and refuses to overwrite an existing backup. If the old binary lacks this command, use [SQLite's `.backup`](https://sqlite.org/cli.html) with a new destination. Do not copy just the live `.sqlite3` file with `cp`.

Back up `.env` and the entire existing `HiddenServiceDir` too, preserving ownership and permissions. Store backups encrypted off the host. Database backups retain deleted secrets; together with a user's Backup File, they allow offline password guessing.

## 3. Build

Select the revision you intend to deploy, then build as your normal user:

```sh
cargo build --release --locked
```

The binary is `target/release/recoverbull`. Keep the running binary in place until the configuration and backups are ready.

## 4. Edit the production configuration

Choose the service account and working data directory first. For a **new installation**, create the account if needed, then create the directory owned by that account with mode `0700`. For an **existing installation**, preserve the current data directory and service account. The service needs write access to the directory for SQLite's WAL files.

Keep the database and any existing SQLite sidecars (`-wal`, `-shm`, `-journal`) owned by the service account with mode `0600`; restrict backups to their required owner too. Use `umask 077` when creating configuration files or launching manually, or the equivalent in your process manager, so newly created files stay private. The reference systemd unit sets `UMask=0077`; a restrictive umask does not repair existing ownership or permissions.

For a **new installation**, copy [`.env.example`](../.env.example) to `.env` in that directory and edit it. It is the single production template. For an **existing installation**, edit the active file without overwriting it with a template. Updating the template does not correct existing files or process-environment overrides: review their actual values, especially if you previously copied a test-oriented example with a one-minute cooldown and global limits of `10000`.

Keep `.env` readable by the service account: use service account ownership with mode `0600`, or `root` ownership with the service's private group and mode `0640`. The removed installer used the latter layout; preserve it when appropriate instead of changing only the mode.

Uncomment `CANARY` and set your current warrant canary. The copied template leaves it unset, so startup refuses to proceed unless you define it in the file or process environment. An explicitly empty `CANARY=` signals that the server is compromised.

| Setting | Production value or choice |
|---|---|
| `DATABASE_URL` | Absolute path to the actual database, for example `/path/to/production_db.sqlite3`. The template's relative `production_db.sqlite3` is for a new local database; preserve an existing database's path. |
| `SERVER_ADDRESS` | `127.0.0.1:3001`, matching nginx's upstream |
| `CANARY` | Your current warrant canary; uncomment and set the line |
| `SECRET_MAX_LENGTH` | `128` Base64 characters, or your existing choice within `128`–`832` |
| `RATE_LIMIT_COOLDOWN` | `1440` **minutes** (24 hours), rather than the test value `1` |
| `RATE_LIMIT_MAX_ATTEMPTS` | `3` distinct passwords per identifier and cooldown |
| `STORE_RATE_LIMIT_BURST` / `STORE_RATE_LIMIT_REFILL_PER_SECOND` | `10` / `2`, global limit on new backups |
| `LOOKUP_RATE_LIMIT_BURST` / `LOOKUP_RATE_LIMIT_REFILL_PER_SECOND` | `100` / `5`, global limit on `/fetch` and `/trash` |
| `ATTEMPTS_RATE_LIMIT_BURST` / `ATTEMPTS_RATE_LIMIT_REFILL_PER_SECOND` | `20` / `2`, global limit on uncached `/attempts` |
| `STORAGE_RESERVE_MB` | `64`; refuses `/store` below this much free space. `0` disables the reserve. |
| `RATE_LIMIT_MEMORY_BUDGET_MB` | `512`, matching the service's actual memory limit |

The template lists every supported setting, including the snapshot TTL of `60` seconds, identifier capacity and database concurrency. `STORAGE_RESERVE_MB` also defaults to `64` in code when absent. Test values live separately in `tests/fixtures/server.env`; never copy that fixture to the server's `.env`.

The server reads `.env` from its working directory or a parent; process environment variables take precedence. Validate under the same user, directory and environment as the service:

```sh
cd /path/to/data
/path/to/new/recoverbull check-config
```

This does not start the server or open the database. It checks this command's memory limit, so also verify the service's limit. A malformed or unreadable `.env` is an error; a missing file is allowed when the process environment supplies the required settings.

After any later ownership, permission or configuration change, run `check-config` again under the actual service user, working directory and environment before starting the service.

## 5. Pause onion traffic and configure nginx

Stop the actual Tor instance serving RecoverBull **before editing either active nginx or Tor configuration**, and keep it stopped through steps 5–7. This also pauses any other onions served by that instance. The PROXY protocol settings must change as a pair; if either validation fails, keep Tor stopped until matching configurations have been restored and validated.

Create `/var/cache/nginx/recoverbull` with the worker user/group from your nginx configuration. For a Debian host using `www-data`:

```sh
sudo install -d -o www-data -g www-data -m 0700 /var/cache/nginx/recoverbull
```

Copy [`deploy/nginx/recoverbull.conf`](../deploy/nginx/recoverbull.conf) to a file included in nginx's **`http` context**, for example `/etc/nginx/conf.d/recoverbull.conf`. Do not paste it inside a `server` block. Review existing listeners and disable an unused public default site on a dedicated onion-only host.

nginx listens on `127.0.0.1:3000`; both `proxy_pass` directives target `127.0.0.1:3001`. To change ports, update the nginx listener and Tor target together, and both nginx upstreams and `SERVER_ADDRESS` together. Keep the PROXY protocol settings and loopback-only trusted forwarder.

Validate with `sudo nginx -t`, using the same configuration options as the running nginx instance.

## 6. Edit the Tor configuration

With Tor still stopped, merge [`deploy/tor/recoverbull.torrc`](../deploy/tor/recoverbull.torrc) into the configuration your Tor instance actually loads. Preserve an existing `HiddenServiceDir`; for a new service, choose a private directory owned by Tor. Define this onion service once and check that any separate file is included.

The template requires Tor **0.4.8 or newer**, with these directives in the RecoverBull service block:

```text
HiddenServicePort 80 127.0.0.1:3000
HiddenServiceEnableIntroDoSDefense 1
HiddenServicePoWDefensesEnabled 1
HiddenServiceExportCircuitID haproxy
```

Keep your other Tor hardening settings. `HiddenServiceExportCircuitID haproxy` must stay paired with nginx's PROXY protocol settings so its limits count per circuit. Validate with `tor --verify-config`, using your instance's actual torrc, defaults and user/options.

## 7. Install and start the server

Use your existing process manager. For a new systemd service, adapt [`deploy/systemd/recoverbull.service`](../deploy/systemd/recoverbull.service): `User`, `Group`, `WorkingDirectory`, `ExecStart`, `ReadWritePaths` and `MemoryMax` must match your layout and configuration. Check its filesystem restrictions too: `ProtectHome=true` blocks paths under `/home`, and `PrivateTmp=true` isolates `/tmp`. Keep `Restart=no`; each restart resets attempt budgets.

For an upgrade, stop the old server while Tor remains stopped. Take a final consistent backup with a new filename for recovery, preserving writes received since step 2, before replacing the binary or starting the new server.

For an upgrade, restore the final backup to a **disposable copy** as the database owner and validate it with the new binary before proceeding:

```sh
/path/to/new/recoverbull check-database /path/to/disposable-restored.sqlite3
```

The argument is a literal filesystem path, not a SQLite URI. The command checks integrity and applies migrations to the copy; keep the backup archive untouched. Continue only if the check succeeds.

Install the new binary and your adapted service definition. For systemd, run `systemctl daemon-reload` if the unit changed. Start one server under the service account; startup applies embedded database migrations. Reload or start nginx after validation, then the actual Tor instance. The reference Debian service names are `recoverbull`, `nginx` and `tor@default`; use yours.

For recovery, stop the server and any other database users, including Litestream, then move the failed database and its sidecars aside. Restore the final snapshot with the matching old binary, configuration and ownership; verify the server and replication again.

## 8. Check the result and Litestream

Check service logs and the backend:

```sh
curl --fail --show-error http://127.0.0.1:3001/info
```

Confirm the canary and cooldown. A plain HTTP request to nginx's port `3000` fails because it expects Tor's PROXY header. Check the onion next, using your actual SOCKS endpoint; for example, if it is `127.0.0.1:9050`:

```sh
curl --fail --show-error --socks5-hostname 127.0.0.1:9050 http://YOUR_ADDRESS.onion/info
curl --fail --show-error --compressed --socks5-hostname 127.0.0.1:9050 http://YOUR_ADDRESS.onion/attempts
```

Allow a few minutes for a newly started onion. Verify both application listeners are on loopback and an existing onion address stayed the same.

**If you use Litestream**, configure it to replicate the same actual SQLite file the server opens, including the filename. Use the absolute filesystem path in Litestream; resolve relative `DATABASE_URL` values from the server's working directory, and do not copy SQLite URI prefixes or query parameters into a filesystem path. After changing that path or replacing the database, restart your actual Litestream service and check its logs for successful replication. Use the [configuration documentation](https://litestream.io/reference/config/) for your installed version; never run two producers against one replica destination. Verify backups by restoring to a separate new file.

## Day to day

Keep security updates current and monitor free space, service status and the five-minute counter summaries. `store_storage_pressure` or `/store` returning `503` can mean the reserve was reached or a storage write failed. Freeing space resumes stores in the first case; after a write failure, fix the cause before deliberately restarting.

The store pressure gate does not block `/fetch` or `/trash`. They still depend on SQLite: a full, unwritable or damaged volume can make recovery fail too. Keep free-space alerts and test restores independently of the gate.

After changing `RATE_LIMIT_MAX_IDENTIFIERS`, `RATE_LIMIT_MAX_ATTEMPTS`, the allocator or dependencies, measure memory on an isolated deployment with representative traffic: fill the ledger to the configured identifier and candidate limits, request a fresh `/attempts` snapshot, and compare peak RSS with the actual process memory limit. On Linux, `VmHWM` in `/proc/<PID>/status` reports peak RSS in kB. For systemd, obtain the PID and limit with `systemctl show --property=MainPID --property=MemoryMax recoverbull`, using your service name. Leave headroom for SQLite, worker stacks and concurrent requests; a startup capacity check does not replace this measurement.

The server writes one line per server error and one summary every five minutes. Configure rate and retention limits in your log daemon. For systemd, an example service drop-in is:

```ini
# /etc/systemd/system/recoverbull.service.d/logging.conf
[Service]
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
```

Apply unit changes with `systemctl daemon-reload`; they take effect on the next deliberate service start. Suppression can discard the five-minute summaries too. Review the host's journal size and retention settings (`SystemMaxUse`, `RuntimeMaxUse`, `MaxRetentionSec`) and current usage with `journalctl --disk-usage`; those limits affect other services sharing the journal. See [systemd's service logging settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LogRateLimitIntervalSec=) and [journal retention settings](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html#SystemMaxUse=).

Keep the canary current: file edits take effect within ten minutes without a restart, unless a `CANARY` process-environment override takes precedence. Never use `RUST_LOG=trace`, which can expose request bodies. See [SECURITY.md](../SECURITY.md) and the [API response contracts](API.md).
