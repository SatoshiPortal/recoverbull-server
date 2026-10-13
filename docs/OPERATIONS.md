# Operating a RecoverBull server

One Debian 13 host runs three services. Clients only ever reach it through Tor:

```
Tor onion service ──► nginx 127.0.0.1:3000 ──► keychain 127.0.0.1:3001 ──► SQLite
  (tor@default)        per-circuit limits,       (recoverbull.service)     /var/lib/recoverbull
                       /attempts cache
```

nginx is not optional: it bounds slow requests before they reach the server, keeps a single cached copy of `/attempts`, and applies rate limits per Tor circuit (Tor passes a circuit id with the PROXY protocol, which is also why `curl 127.0.0.1:3000` gets no answer).

`deploy/recoverbull` installs and upgrades all of it. Backups stay yours: this page says what to copy and how.

## Six rules

1. **One instance, ever.** Attempt budgets live in memory: two copies, or two hosts sharing the same onion keys, would double every budget. Never run a second copy, even briefly.
2. **Never expose ports 3000 or 3001.** Only Tor talks to nginx, only nginx talks to the server. The host needs no inbound port except SSH.
3. **Back up the onion keys, not only the database.** The keys in `/var/lib/tor/recoverbull/` *are* the server address, and the Bull app has it built in. Lose them and every user loses this server.
4. **Restart only when you must.** Each restart resets every attempt budget. The service never restarts by itself (`Restart=no`): if it stops, find out why before starting it again.
5. **Keep the canary current.** An empty canary tells clients the server is compromised.
6. **Never set `RUST_LOG=trace`.** At that level request bodies can reach the logs.

## Install

You need a fresh Debian 13 host with 2 GB of RAM (for the Rust build; the server itself is capped at 512 MB), `sudo`, and Rust:

```sh
sudo apt install build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none
. ~/.cargo/env
```

Then, as your own user:

```sh
git clone https://github.com/SatoshiPortal/recoverbull-server.git
cd recoverbull-server
cargo build --release --locked
sudo deploy/recoverbull install
```

It asks for the warrant canary (or pass `--canary '<text>'`), then:

- installs `tor`, `nginx`, `python3`, `curl` and `unattended-upgrades` from Debian;
- creates the `recoverbull` account, installs the binary under `/opt/recoverbull` and the configuration from `deploy/`;
- disables nginx's default public site;
- starts the server, nginx and Tor, and prints the onion address.

**Then back up the onion keys** (see [Backups](#backups)).

### Redeploying an existing server

To move a server to a new host with the same data and onion address, stop it first (Tor, then the server), copy its SQLite database and its Tor `HiddenServiceDir` to the new host, and install from them:

```sh
sudo deploy/recoverbull install --database /path/to/old.sqlite3 --onion-keys /path/to/old-hidden-service/
```

The database can have any file name, and a `-wal` file next to it is included. A database from before the migration ledger is adopted automatically. Once `status` is green, shut the old host down for good (rule 1).

## Upgrade

Run the same command again after updating the checkout:

```sh
git pull
cargo build --release --locked
sudo deploy/recoverbull install
```

It lists the files that changed and asks before stopping anything (`--yes` to skip the question). Then it stops Tor and the server, keeps a copy of the current version and database in `/var/lib/recoverbull/previous-version/`, installs the new files, migrates the database, and starts everything again.

If the new version fails to start, it puts the previous one back, with its database, and tells you. One reason this happens: a new version needs a setting that your `.env` does not have yet. The script never edits `.env`; read the logs, add the setting, and run the install again. If nothing changed, it does nothing.

## Backups

The script does not make backups. Copy these three things off the host, encrypted, on your own schedule:

| What | Where | Why |
|---|---|---|
| Onion keys | `/var/lib/tor/recoverbull/` | They are the server address. Copy them once; they never change. |
| Database | `/var/lib/recoverbull/database.sqlite3` | Every stored secret. |
| Configuration | `/var/lib/recoverbull/.env` | The canary and settings. |

Never copy the database file with `cp` while the server runs: recent writes may still be in `database.sqlite3-wal`. Use SQLite's backup API instead, which is safe while the server runs:

```sh
sudo python3 deploy/backup/sqlite_backup.py backup /var/lib/recoverbull/database.sqlite3 /root/recoverbull-$(date +%F).sqlite3
```

To restore on a new host, use `install --database --onion-keys` as above.

The database holds encrypted secrets only, but together with a user's Backup File it allows offline password guessing. Keep backups encrypted and limit how long you keep them: deleting a secret with `/trash` does not remove it from older backups.

## Day to day

| Task | How |
|---|---|
| Check health | `sudo deploy/recoverbull status` (exits non-zero when something is wrong) |
| Read logs | `sudo deploy/recoverbull logs` (`-f` to follow, `-n 500` for more, `--all` to add nginx and Tor) |
| Change the canary | Edit `CANARY` in `/var/lib/recoverbull/.env`; served within ten minutes, no restart |
| Know the onion address | `sudo cat /var/lib/tor/recoverbull/hostname` |

For about ten minutes after Tor starts, `status` reports the onion as `starting` while the address is being published.

What to watch:

- **Disk.** Each stored secret is a few hundred bytes, but a sustained `/store` flood can grow the database by up to about 90 MB per day. Alert at 70% use and never let the disk fill up: the server must keep accepting writes. A dedicated volume for `/var/lib/recoverbull` keeps a flood from filling the system disk.
- **The five-minute counter line** in the logs (`sudo deploy/recoverbull logs`). `lookup_rate_limited`, `database_busy`, `database_error` and `request_timeout` should stay near zero.
- **The service being down.** It does not restart on its own (rule 4).

The server logs one line per server error and one summary every five minutes, never request contents. journald limits each service to 10,000 lines per 30 seconds by default.

Debian security updates for Tor and nginx install automatically through `unattended-upgrades`. Upgrades of the server itself are yours to schedule (rule 4).

## Configuration

`/var/lib/recoverbull/.env` starts from [`deploy/recoverbull.env.example`](../deploy/recoverbull.env.example), which explains each required value. These optional settings have safe defaults; change one only for a measured reason, then restart.

| Setting | Default | Meaning |
|---|---|---|
| `STORE_RATE_LIMIT_BURST` / `_REFILL_PER_SECOND` | 10 / 2 | Global limit on new backups |
| `LOOKUP_RATE_LIMIT_BURST` / `_REFILL_PER_SECOND` | 100 / 5 | Global limit on `/fetch` and `/trash` |
| `ATTEMPTS_RATE_LIMIT_BURST` / `_REFILL_PER_SECOND` | 20 / 2 | Global limit on uncached `/attempts` |
| `ATTEMPTS_SNAPSHOT_TTL_SECONDS` | 60 | How long one `/attempts` snapshot is reused |
| `RATE_LIMIT_MAX_IDENTIFIERS` | 100000 | Identifiers tracked at once; more get `503` |
| `RATE_LIMIT_MEMORY_BUDGET_MB` | 512 | Keep equal to `MemoryMax=` in the systemd unit |
| `DATABASE_MAX_CONCURRENCY` | 16 | Parallel database operations |

The server checks every value at startup and refuses to start, with an explicit message, if one is out of bounds or if the identifier capacity does not fit the memory budget. The older name `RATE_LIMIT_MAX_FAILED_ATTEMPTS` is still accepted for `RATE_LIMIT_MAX_ATTEMPTS`, with a warning.

The default capacity peaked at 117 MB on one host and about 250 MB on another. After raising `RATE_LIMIT_MAX_IDENTIFIERS` or `RATE_LIMIT_MAX_ATTEMPTS`, let the map fill up and compare the peak with `MemoryMax`:

```sh
sudo grep VmHWM /proc/$(systemctl show -p MainPID --value recoverbull)/status
```

## What the script does not do

- Back up anything (see [Backups](#backups)).
- Harden SSH, set up a firewall, or update the operating system beyond Debian security updates.

The files under `deploy/` are the reference configuration; the comments in each explain its choices. The reasoning behind the security model and its accepted risks is in [SECURITY.md](../SECURITY.md).
