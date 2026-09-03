# Secret Server

The server provides secret storage without relying on traditional credentials systems (account based).

For the threat model, the risks accepted by design, the security invariants
guarded by tests and the reviewer checklist, see [SECURITY.md](SECURITY.md).
For the implementation ownership map and audit reading path, start with the
`Reviewer reading map` and `Ownership and dependency map` in [SECURITY.md](SECURITY.md).
Operational templates are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and
[docs/RETENTION.md](docs/RETENTION.md), with versioned files under `deploy/`.
The SQLite backup and restore procedure is in [deploy/backup/README.md](deploy/backup/README.md).

## Description

### Definitions
- `secret` The cleartext secret of the user.
- `password` A user-chosen password (may be weak).
- `authentication_key` A deterministic hash derived from `password` used server-side to compute an internal `secret_id`.
- `encryption_key` A deterministic hash derived from `password` used client-side to **encrypt** the `secret` **before** storage on the server.
- `identifier` random secure octets (e.g., in a local file), required to retrieve the `encrypted_secret`.
- `secret_id` = `hash(identifier + authentication_key)` Unique record key in the server’s database. Concretely: **SHA-256 over the concatenation of the two lowercase hex *strings*** (128 ASCII bytes) — not over the decoded raw bytes. This differs from the `/attempts` `id_hash`, which hashes the raw identifier bytes; client implementations must not mix the two.
- `encrypted_secret` = `encrypt(private_key: encryption_key, payload: secret)` The ciphertext of the secret using `encryption_key`.

### Request diagnostics and security counters

Every response includes a server-generated `X-Request-ID`. Client-provided
`x-request-id` headers are removed before routing and are never reused. The
security counter reporter emits one aggregate summary every five minutes at
`info`, including the saturating `diagnostic_logs_emitted` and
`diagnostic_logs_suppressed` counters.

Detailed request events are disabled at the normal `info` level. For temporary
diagnosis, enable `RUST_LOG=info,request_diagnostics=debug`; debug logging must not
be left enabled during normal operation. It is globally quota-limited per
class to a burst of 10 events with a refill rate of 1 event per second. The
only request-event fields are the generated `request_id`, static route enum
(`store`, `fetch`, `trash`, `info`, `attempts`, `other`), static method enum,
numeric HTTP `status`, static category enum, and static duration bucket enum.
Categories are `success`, `client_error`, `overload`, or `server_error`; duration
buckets are `lt500ms`, `500ms_1s`, `1s_5s`, or `gte5s`.
Raw URIs, query strings, headers, bodies, remote addresses, database paths,
identifiers, hashes, tags, keys, ciphertexts, canary values, and raw errors
are never logged.

### Store

 1. On the client side, generate a random secure `identifier`, that you can store securely in a file, and let the user define a `password`.

  2. If the user's password/PIN has low entropy, use a password hashing function such as Argon2 to slow offline guesses while deriving a 64 octets (512 bits) key split in two keys. The cloud and database together permit offline validation, so security ultimately depends on the user's secret entropy:
- `authentication_key` the first 32 octets (256bits)
- `encryption_key` the remaining 32 octets to encrypt/decrypt the secret
> Argon2 `salt` is stored alongside the `identifier`. Other params used to derive keys from the password should be the same to derive the exact same keys.
> Argon2 params include `mode=Argon2id`, `iterations=2`, `memory=19Mb`, `parallelism=1` [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

 3. The client encrypts his `secret` using `encryption_key` and make a `store` request to the server containing:
- `identifier`
- `authentication_key`
- `encrypted_secret`
> The `nonce` and `mac` generated during the encryption are encoded with  `nonce`|`ciphertext`|`hmac`

4. The server receive the `store` request and generate the `secret_id` from the `hash(identifier + authentication_key)`. Then, the server create a new database entry:
- id: `secret_id`
- created_at: `DateTime.now()`
- value: `encrypted_secret`


### Fetch

 1. The client, must own informations needed such as `identifier`, `password`, `salt`…

 2. From the `password` we re-generate the two derived keys `authentication_key` and `encryption_key` using the same Argon2 params and `salt`.

 3. The client make a `fetch` request to the server containing:
- `identifier`
- `authentication_key`

  4. The server receives the `fetch secret` request and performs:
- Compute the candidate tag `secret_id`/`key_id` from the identifier and authentication key. The per-identifier bucket is always `sha256(identifier)`.
- Retain only the derived `CandidateTag` in memory. It is exactly `secret_id/key_id`: never raw authentication or password material. Candidate tags are state-only, have at most `RATE_LIMIT_MAX_ATTEMPTS` slots, are wiped after the cooldown or a restart, and are never logged or included in a snapshot.
- A new candidate immediately reserves one slot and counts in the budget. A duplicate `Pending` candidate receives `503` before saturation rather than taking another slot.
- If `candidate_count >= max`, return `429` before membership or database work for **every** candidate, including known, `Pending`, and `Committed`, so saturation cannot be an authentication oracle.
- A `Committed` replay is free only before saturation: it increments `total_requests`, does not extend the candidate cooldown, and does not add another attempt. `/fetch` and `/trash` share this candidate set.
- Finalization is detached and generation-safe. A hit or miss commits the candidate; a miss increments `failed_attempts` exactly once. A database error or cancellation before database work removes `Pending`; a trash race returning `202`/`401` does not create a false failed candidate.

 5. The user can fetch his `secret` by deciphering `encrypted_secret` using his `encryption_key` as encryption key.

> On success, the response also contains an `attempt_status` object: the attempt counters recorded for this `identifier` during the current cooldown window.
>
> ```json
> {
>   "attempt_status": {
>     "version": 1,
>     "total_attempts": 3,
>     "failed_attempts": 1,
>     "total_requests": 5,
>     "remaining_attempts": 0,
>     "window_started_at": "2026-08-05T12:17:41Z",
>     "previous_attempt_at": "2026-08-05T14:37:22Z",
>     "resets_at": "2026-08-06T15:04:13Z"
>   }
> }
> ```
>
> - `total_attempts` is the number of distinct candidates admitted in the current cooldown window. A hit does not prove ownership, because a public `/store` caller can plant a matching row.
> - `failed_attempts` counts distinct candidates for which no database row existed, incremented once when that candidate is finalized as a miss.
> - `remaining_attempts` is `rate_limit_max_attempts - total_attempts`, saturating at zero.
> - `total_requests` counts every `/fetch` and `/trash` request attached to this identifier's active entry, including replays, pending duplicates, and saturation rejections. Requests rejected because the global identifier map is already full have no per-identifier entry and are not included. The global lookup bucket remains the defense against floods of identical replays.
> - `previous_attempt_at` is the admitted attempt immediately preceding this request (`null` when this request opened the window), and `resets_at` is when the budget expires.
> - A successful lookup never resets the counters; they expire only after the configured cooldown.

#### Timestamp precision by response

Timestamp precision follows the knowledge gradient — the more a caller must already know, the more precise the timestamps it receives:

- **Successful `/fetch` and `/trash` (`attempt_status`)**: exact, second-precision timestamps. Reachable by anyone holding the `identifier` (a hit can always be manufactured by planting a row through `/store`), so exact precision here widens no audience.
- **Failed lookup (`401`)**: `requested_at` is the time of the caller's own request — it reveals nothing about anyone else.
- **Lockout (`429`)**: `requested_at` is the **exact** time of the last *admitted* attempt, which may be the victim's. Anyone holding the `identifier` can read it once the budget is exhausted. This is accepted: the same caller already gets hour precision from the public snapshot, and the exact value is what a client needs to compute its retry time.
- **Public `/attempts` snapshot**: hour-truncated timestamps, because the audience is everyone — exact timestamps would ease correlation without requiring any knowledge of the `identifier`.

### Error responses

Clients classify errors **only by HTTP status**. Application error responses are
JSON objects containing at least an `error` field. The `error` text is for
humans and logs; it is not contractual and must never be matched to make a
retry or security decision.

| HTTP status | Meaning | Client treatment |
|---|---|---|
| `400` | Invalid request data. | Fix the request. |
| `401` | Invalid credentials. | Treat as an authentication failure. |
| `429` | The targeted identifier's distinct-candidate budget is locked. This is the only security alarm. | Surface the targeted lockout and honor `Retry-After`. |
| `503` | Server pressure or unavailability, including global lookup/store/telemetry limits, a full rate-limit map, a busy database, or a request the server could not finish within its 30-second timeout. | Back off and retry using `Retry-After`. |
| `500` | Internal server error. | Treat as a server failure. |

Every `429` and `503` response carries `Retry-After`, in seconds. On a `503`
from one of the global token buckets (store, lookup, telemetry) the value is
the server's estimate of when the next token exists, computed from the
configured refill rate at the moment of refusal and rounded up to at least one
second; on the other `503`s (busy database, full identifier map, pending
duplicate, request timeout) there is no deadline to derive and the value is a
one-second advisory. Framework-generated rejections such as `404`, `405`,
`413`, and `415` may not be JSON.

### Attempts

`GET /attempts` returns a public telemetry snapshot for the current cooldown windows:

```json
{
    "version": 1,
  "collection_started_at": "2026-08-05T09:00:00Z",
  "entries": [
    {
      "id_hash": "7a06e6b2…",
      "total_attempts": 3,
      "failed_attempts": 1,
      "total_requests": 5,
      "window_started_at": "2026-08-05T12:00:00Z",
      "last_attempt_at": "2026-08-05T14:00:00Z"
    }
  ]
}
```

- `id_hash`: SHA-256 of the raw `identifier` **bytes** (not the hex string). A client recognizes its own identifier by hashing it locally; nobody can recover a raw identifier from the list (pre-image resistance), which keeps the list useless for griefing or targeted lockout.
- `total_attempts`: number of distinct candidates admitted in the current cooldown window.
- `failed_attempts`: number of distinct candidates for which no database row existed.
- `total_requests`: every `/fetch` and `/trash` request attached to this identifier's active entry, including replays; map-capacity rejections for previously unseen identifiers cannot be attributed to an entry. It is telemetry, not candidate budget.
- `window_started_at` / `last_attempt_at`: hour-truncated timestamps of the current window; `last_attempt_at` is the last distinct candidate timestamp, not the latest replay request. The JSON field name is retained for compatibility.
- `collection_started_at`: hour-truncated start of the in-memory collection. It changes at startup and after each global 24-hour wipe; clients must reset their baseline.

Identifiers are kept and published hashed, never raw. The entire identifier map, including CandidateTags, is wiped every 24 hours from map startup and the attempt budget resets at that boundary. The cooldown sweep runs earlier for shorter-lived entries; nothing is persisted.

The body is **always gzip-compressed JSON** (`Content-Encoding: gzip`); clients must be gzip-capable. This initial telemetry contract, version `1`, reports distinct-candidate counters plus `total_requests` and never exposes CandidateTags. The snapshot is rebuilt at most once per minute and served as immutable shared bytes with a strong `ETag`: send `If-None-Match` to receive a bodyless `304` when nothing changed. `Cache-Control: public, max-age=<remaining seconds>` reflects the real freshness. A dedicated global token bucket (`ATTEMPTS_RATE_LIMIT_*`) bounds cache-bypass traffic; production deployments must additionally cache and rate-limit this route at the reverse proxy (see Deployment). Nginx is the reference template; Caddy is a conditional, mutually exclusive alternative under `deploy/caddy/`.

Server deployment and wallet rollout are two stages of the same detection
feature. Bull Mobile does not currently poll `/attempts`, so deploying this
server alone leaves proactive detection temporarily incomplete; a compatible
Bull Mobile release is required to finish the rollout. That release should
poll regularly while the app is in the foreground and use best-effort
background scheduling where the operating system permits it. Requests should
be jittered, respect snapshot freshness and `ETag`, and travel through Tor and
the shared proxy cache. The global request does not reveal the identifier being
checked because matching happens locally. It does add observable wallet-online
timing; a private per-identifier endpoint or push subscription would be more
linkable because it would reveal the target or require stable device/account
state. `attempt_status` remains the passive signal available when a lookup
already occurs.

If a client opts into proactive detection, it should implement these semantics:
- **Poll `/attempts` proactively** while foregrounded and, where supported, from a best-effort background task (never more often than the snapshot freshness, and with jitter): if your identifier hash appears with attempts you did not make, someone is probing your backup.
- **Check the fill ratio, not only your own hash.** Compare the number of published entries with `max_attempt_identifiers` from `/info`. A saturated map means new identifiers are being refused with `503`, and **a victim in that situation has no entry of its own to find**: an attacker filling the map with identifiers it chose never touches yours. Recognizing your own `id_hash` is therefore not sufficient as a detection strategy — a high ratio is itself a first-order alarm. At the default capacity this costs an attacker about 1.16 requests per second sustained and roughly 50 MB of traffic per day, so a saturated ratio is cheap to produce and must be treated as expected, not exceptional.
- **Treat a `429` or unexpected snapshot activity as an alarm**: global service pressure uses `503` instead. If the wallet is still accessible, rotate/transfer immediately; otherwise recovery availability depends on a **previously exported** Backup Key or a second independent server. See [Error responses](#error-responses) for the full table; do not match on the `error` text.
- **`attempt_status` on a successful fetch is the freshest signal**: it needs no extra request and stays available even when `/attempts` is overloaded. Failures older than the cooldown expire (entries are swept and forgotten), but a success never resets the counters early.
- **Telemetry is advisory**: the server cannot distinguish an attacker from the user or another of the user's devices, and a compromised server can fabricate or suppress counters. Clients must warn, never act automatically.
- **A failing `/attempts` means "I do not know", not "no alarm".** The snapshot carries a negative signal, so track the last *successful* poll and treat a stale one as unverified rather than as quiet. `/info` is never rate-limited and needs no snapshot, so the pair tells the two failures apart:

| `/info` | `/attempts` | Meaning |
|---|---|---|
| OK | `200` / `304` | Verified: compare your `id_hash`, the counters, and the fill ratio. |
| OK | `503` | Telemetry bucket or service pressure: back off per `Retry-After`; the state stays unverified. |
| OK | `500` | The telemetry subsystem itself is failing; recovery routes are unaffected. Operators see it as `attempts_snapshot_failed` in the five-minute counter window. |
| fails | any | The server or the network is unreachable. |

`GET /info` exposes `rate_limit_max_attempts`, the total per-identifier lookup
budget. The response also retains `rate_limit_max_failed_attempts` as a
legacy alias with the same value. It complements the snapshot with two static
fields: `attempts_collection_started_at` (hour-truncated, same value as the
snapshot — a cheap wipe check during the existing connection check) and
`max_attempt_identifiers` (the configured map capacity, so a client can
compute the snapshot fullness ratio and warn when the service is under
pressure). `/info` does not carry a live identifier count, but that is a
shape choice, not a protection: `/attempts` publishes **every** active
entry, so counting them yields the live map size exactly. Treat the ratio as
public.

The canary from the dotenv file is read on a blocking worker for every `/info`
request, without cache metadata. File reads are serialized by a dedicated
permit to protect Tokio's bounded blocking pool; the selected reverse-proxy/Tor limits remain
necessary. A readable file without CANARY returns an empty string; an
unavailable file falls back to startup. A process-environment `CANARY` is
authoritative and skips file access.

The global wipe is a process-memory boundary, not guaranteed erasure: a
suspended process, swap, or core dump may retain old pages. The 24-hour timer
does not advance while the process is stopped or suspended; restart begins a
new collection.

### Sensitive POST response floor

`POST /store`, `POST /fetch`, and `POST /trash` share a production response
floor of 500 ms. The floor timer starts when routing hands the request to the
matched route, before JSON extraction and parsing, so fast validation and body
or extractor rejections on these three routes are covered too. It targets a
minimum server-side time until the response is ready (TTFB); it cannot equalize
network transfer, client timing, request-body upload time, or proxy/Tor delay.
If processing already takes at least 500 ms, the server adds no sleep. Longer
processing remains observable and is not hidden by delaying or caching a
database operation. `/info`, `/attempts`, 404s, 405s, and all other routes are
excluded, and no timing header or sensitive timing data is emitted.

The extra response wait can increase concurrent connections during a flood.
Production deployments compensate with the store/lookup token buckets and the
selected reverse-proxy and Tor connection, request, and DoS defenses described
below; it is not a
replacement for those limits. The invariant and dedicated timing tests are
listed in [SECURITY.md](SECURITY.md).



### Privacy and recovery security summary

The protocol's privacy goals and accepted recovery-lockout trade-off are defined by the whitepaper. Implementation invariants, candidate accounting, telemetry limits, and review evidence are maintained in [SECURITY.md](SECURITY.md); clients must follow the wire contracts above and operators must follow the deployment runbook below.


## Deployment

### Tor onion service (the supported deployment)

The server is designed to be reached exclusively through a **Tor onion service**: it protects the transport confidentiality of the `authentication_key` and the IP anonymity of clients. **Never expose it directly on a public interface** — the server refuses to stay silent about it and prints a startup warning when `SERVER_ADDRESS` is not loopback. Production deployments must put a reverse proxy between Tor and Axum because Axum's route timeout starts after HTTP headers have been read.

The supported deployment is **strictly single-instance**: rate limits, token
buckets, the cache, and the collection marker are in memory. The binary does
not enforce Tor or single-instance operation; a non-loopback bind only emits a
startup warning. Load balancing or rolling overlap would multiply budgets and
make telemetry inconsistent. Stop the old instance before activating a new
one; no daily restart is needed. The internal collection wipe occurs every 24
hours. An exceptional restart starts a new budget and collection and must not
overlap the old instance.

Use the maintained templates rather than copying this overview:
`deploy/systemd/recoverbull.service`, `deploy/nginx/recoverbull.conf` (the
reference proxy),
`deploy/tor/recoverbull.torrc.example`, and `deploy/logrotate/recoverbull`.
The conditional Caddy alternative is documented in `deploy/caddy/README.md`;
choose exactly one proxy, and admit Caddy only after its build, validation, and
specific smokes succeed.

The HTTP status contract is shared by both maintained proxy templates: `429` is
exclusively a targeted Axum lockout, while all shared pressure is `503` with
`Retry-After`. Clients classify by standard status only; they must not depend
on custom status codes or error text. Caddy has no native connection-count cap:
its 10-second header timeout and Tor defenses are compensating controls, so
operators must budget and monitor file descriptors and processes for the host.

1. Keep Axum on a private loopback port: `SERVER_ADDRESS=127.0.0.1:3001`
2. Configure nginx on `127.0.0.1:3000` with strict header/body timeouts and connection limits:

```nginx
limit_conn_zone $binary_remote_addr zone=recoverbull_connections:10m;
limit_req_zone $binary_remote_addr zone=recoverbull_attempts:10m rate=5r/s;
proxy_cache_path /var/cache/nginx/recoverbull levels=1:2 keys_zone=recoverbull_cache:10m max_size=100m inactive=2m;

server {
    listen 127.0.0.1:3000;
    access_log off;
    error_log /var/log/nginx/recoverbull-error.log crit;
    client_max_body_size 1k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 35s;
    limit_conn recoverbull_connections 100;

    # The telemetry snapshot can reach several megabytes: cache the
    # precompressed body, coalesce concurrent fills and shape egress.
    location = /attempts {
        proxy_pass http://127.0.0.1:3001;
        proxy_connect_timeout 2s;
        proxy_read_timeout 35s;
        proxy_cache recoverbull_cache;
        # /attempts ignores query parameters. Exclude them from the key so an
        # attacker cannot mint one cache entry per random query string.
        proxy_cache_key $scheme$proxy_host$uri;
        proxy_cache_lock on;
        proxy_cache_valid 200 30s;
        limit_req zone=recoverbull_attempts burst=20 nodelay;
        limit_rate 512k;
    }

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_connect_timeout 2s;
        proxy_read_timeout 35s;
    }
}
```

Keep the error log readable only by service administrators, for example with
owner `root:adm` and mode `0640`, and configure logrotate (or an equivalent
collector) with an operator-selected short retention policy. `crit` reduces
volume but does not guarantee that request metadata is absent. Apply the same
level, permission, and explicitly configured retention policy to journald and
Tor logs. Application log guarantees do not cover reverse-proxy or system logs
unless this runbook is applied. The five-minute global counters retain coarse
activity metadata and also require restricted access and retention.

All Tor connections reach nginx from loopback, so these connection and request limits are intentionally global. The backend already serves `/attempts` precompressed: nginx caches that exact body instead of recompressing per request. The explicit cache key uses `$uri`, not the default `$request_uri`, because `/attempts` ignores query parameters: `/attempts?x=1` and `/attempts?x=2` must share one entry and one cache-fill lock. The Caddy alternative enforces the same invariant with `disable_query` and `disable_host`, and its smoke test proves that different Host/query values cause only one backend call. `limit_rate` caps per-connection throughput; multiplied by the connection limit it bounds aggregate snapshot egress. The proxy is also what lets slow clients take their time: with default `proxy_buffering`, nginx drains Axum quickly (within its 30s route timeout) and feeds the client at its own pace.

> **Conditional requests behind nginx**: when serving `/attempts` from `proxy_cache`, nginx answers with the cached `200` body without evaluating the client's `If-None-Match` — the bodyless `304` path only benefits clients reaching Axum directly. Clients behind nginx therefore re-download the snapshot body whenever nginx's cache entry has expired (30s) and the content changed. This is an egress tradeoff, not a correctness issue: clients must still compare the received `ETag` to detect change, and aggregate egress stays bounded by `limit_conn` × `limit_rate`.

3. Configure the onion service in `torrc` to reach nginx, with Tor's built-in DoS defenses enabled (they cover connection floods; body downloads remain an nginx concern):

```
HiddenServiceDir /var/lib/tor/recoverbull/
HiddenServicePort 80 127.0.0.1:3000
HiddenServiceEnableIntroDoSDefense 1
# Tor 0.4.8+: proof-of-work defense, makes opening many new rendezvous
# circuits expensive under load. Neither defense covers body downloads
# over established circuits — that remains an nginx concern (above).
HiddenServicePoWDefensesEnabled 1
```

4. Reload nginx and Tor, then read the onion hostname:

```sh
sudo systemctl reload nginx
sudo systemctl reload tor
sudo cat /var/lib/tor/recoverbull/hostname
```

### dotenv

```sh
echo "DATABASE_URL=production_db.sqlite3" >> .env && \
echo "SERVER_ADDRESS=127.0.0.1:3001" >> .env && \
echo "SECRET_MAX_LENGTH=128" >> .env && \
echo "CANARY='🐦'" >> .env && \
echo "RATE_LIMIT_COOLDOWN=1440" >> .env && \
echo "RATE_LIMIT_MAX_ATTEMPTS=3" >> .env
```

The file holds the database path and the canary: keep it readable by the
service account only (`chmod 600 .env`, same `0700` directory discipline as
the database volume).

`CANARY` is the warrant canary served by `/info`. When it is provided by
this file (the common case), `/info` re-reads the file on every request,
following the whitepaper's warrant-canary workflow without a restart. Reads
are serialized to protect Tokio's bounded blocking pool; selected reverse-proxy
and Tor limits remain necessary:

- **Edit the value** → the new value is served immediately.
- **Remove the `CANARY` line** → an **empty** canary is served: this is the
  compromise signal clients watch for, and it is never masked by a fallback.
- **File missing or unreadable** (ops error) → the startup value is served,
  so a deploy mishap does not raise a false alarm.

When `CANARY` is instead provided by the process environment (e.g. systemd
`Environment=`), the environment is authoritative: file edits are ignored,
and signaling requires a restart with a changed value. The server refuses to
start without a canary.

Optional, with defaults shown — a global token bucket dampening unauthenticated `/store` writes (per-IP is useless behind an onion service):

```sh
echo "STORE_RATE_LIMIT_BURST=10" >> .env && \
echo "STORE_RATE_LIMIT_REFILL_PER_SECOND=2" >> .env && \
echo "LOOKUP_RATE_LIMIT_BURST=100" >> .env && \
echo "LOOKUP_RATE_LIMIT_REFILL_PER_SECOND=5" >> .env && \
echo "ATTEMPTS_RATE_LIMIT_BURST=20" >> .env && \
echo "ATTEMPTS_RATE_LIMIT_REFILL_PER_SECOND=2" >> .env && \
echo "ATTEMPTS_SNAPSHOT_TTL_SECONDS=60" >> .env && \
echo "RATE_LIMIT_MAX_IDENTIFIERS=100000" >> .env && \
echo "RATE_LIMIT_MEMORY_BUDGET_MB=512" >> .env && \
echo "DATABASE_MAX_CONCURRENCY=16" >> .env
```
This configuration admits two `/store` requests per second (172,800 per day)
in steady state. After startup, or after five seconds without a `/store`
request, the bucket holds an initial burst of ten requests, so the first day
can admit at most 172,810 requests. Every admitted request consumes a token,
including an idempotent duplicate that does not create a new row. If every
request has a new identifier and a maximum-size secret, SQLite grows by about
43 to 86 MB/day, depending on page and index overhead.
`RATE_LIMIT_MAX_ATTEMPTS` is the canonical configuration name for the
per-identifier distinct-candidate budget. Every distinct candidate consumes it,
including database hits and misses; replay requests consume no new candidate
slot. If the canonical variable is absent, the server accepts
`RATE_LIMIT_MAX_FAILED_ATTEMPTS` as a deprecated legacy alias and logs a
warning; when both are present, the canonical variable wins. The
`remaining_attempts` field of `attempt_status` derives from it.
The lookup bucket is a separate global safety limit for `/fetch` and `/trash`.

`/trash` removes the active row transactionally. SQLite `secure_delete` is
forced on every application connection, so pages rewritten by that deletion
are scrubbed. With WAL enabled, the main database file (or a copy of it) may
still contain pre-checkpoint state; backups, Litestream replicas, and
historical snapshots are not purged. A consistent backup must include the
database and WAL, or use SQLite's backup API. Operators must define retention
and deletion policies for those copies.

The attempts bucket is a third global limit for `GET /attempts`, sized for
direct cache-bypass traffic; the reverse-proxy cache absorbs normal reads.
`ATTEMPTS_SNAPSHOT_TTL_SECONDS` controls how long a snapshot is reused
before being rebuilt (at most one rebuild per window, single-flight). It must
be shorter than `RATE_LIMIT_COOLDOWN`: the cache is invalidated only by the
TTL and the daily wipe, never by a new attempt, so with a TTL at or above the
cooldown an attempt admitted just after a rebuild could expire before the next
one and never appear in `/attempts`. Startup refuses such a value.
The identifier cap bounds the number of `sha256(identifier)` buckets without
evicting active security entries; new identifiers receive `503` while the cap
is full. Each bucket's CandidateTag set is bounded by the distinct-candidate
budget. SQLite work is limited to
16 concurrent blocking operations, and requests waiting more than one second
for a slot receive `503` without consuming their per-identifier attempt.
Both capacities are checked at startup, and a zero or over-budget value
makes the server refuse to start rather than run unbounded.
`DATABASE_MAX_CONCURRENCY` must be in `[1, 1024]`.
`RATE_LIMIT_MAX_IDENTIFIERS` is not bounded by a fixed ceiling: it is
validated against the **lower** of `RATE_LIMIT_MEMORY_BUDGET_MB` (default
`512`, matching `MemoryMax=512M` in the systemd template) and the memory limit
the kernel actually enforces on the process, read from the cgroup
(v2 `memory.max`, walked up the hierarchy, or v1 `memory.limit_in_bytes`). The
enforced limit wins whenever it is lower, and startup warns when it does, so
lowering `MemoryMax` without lowering the declared budget cannot silently
disable the check. With no discoverable cgroup limit, only the declared budget
applies. The model uses the measured per-entry cost,
which also depends on `RATE_LIMIT_MAX_ATTEMPTS` because each retained
CandidateTag is a 64-character string. The model reserves 64 MiB of the
budget for the base process, SQLite, and worker stacks, then requires
`capacity x (1100 + 150 x max_attempts)` bytes to fit what remains. At the
default budget that admits about 303,000 identifiers at
`RATE_LIMIT_MAX_ATTEMPTS=3`, and about 11,900 at the `255` ceiling. Raising
the capacity means declaring the budget that pays for it — set
`RATE_LIMIT_MEMORY_BUDGET_MB` to the deployment's real cgroup limit. The
error names the offending values and the maximum capacity that would fit.

This replaced a fixed `10000000` ceiling whose justification (150-180 bytes
per entry, "~2 GB") was low by roughly an order of magnitude: that capacity
actually costs about 14.4 GiB at snapshot peak, so the ceiling admitted the
silent memory-exhaustion kill it was meant to prevent. With
`Restart=no` in the systemd template, such a kill leaves the service down
until an operator intervenes.
Token bursts are validated mathematically: they must be finite, contain at
least one token, and `burst - 1.0` must differ from `burst` in `f64`. This
rejects numerically ineffective values without an arbitrary throughput cap.
Operators must still set a memory gate with headroom: the budget check uses
a conservative estimate, not a guarantee.
The release bundles SQLite 3.51.3 through `libsqlite3-sys`, the upstream WAL
reset fix. Startup verifies the runtime version and exactly
`journal_mode=wal`; every application connection verifies exactly
`journal_mode=wal` and `secure_delete=1`. The runtime version is immutable for
the bundled process and is not re-queried on every request connection.
> `SECRET_MAX_LENGTH=128` represents the size of a 96 octets encrypted secret encoded using base64
> 96 octets =  `nonce` (16 octets) | `ciphertext` (32 octets) | `hmac` (32 octets) + 16 octets padding to round up to 32 octets blocks

Startup accepts `SECRET_MAX_LENGTH` between `128` and `832`. Below 128 every
Profile 1 backup is refused; above 832 `/info` advertises a length that a
compact `/store` body cannot carry under the 1024-byte request body limit
(191 bytes of JSON envelope plus a Base64 value whose length is a multiple of
four), so `/store` would answer `413` for a payload `/info` calls acceptable.
`RATE_LIMIT_COOLDOWN` is bounded by the daily wipe: the whole ledger is
cleared every 24 hours, so a cooldown above `1440` minutes would announce a
budget through `/info` and `resets_at` that the next wipe discards, and
startup refuses it. The wipe or a restart can still end a window earlier than
`resets_at` says.

### Migrations

The server embeds the migrations and runs them automatically at startup. A
legacy database that has `secret` but no `__diesel_schema_migrations` ledger is
adopted only when its schema exactly matches migration `0001`; adoption creates
the ledger entry without creating or modifying any `secret` row. An incompatible
legacy schema stops startup. After migrations run, startup verifies the live
`secret` table against migration `0001` unconditionally: a database whose
Diesel ledger already records the migration but whose table is missing or
incompatible (a partial restore, a manual edit) is refused instead of being
announced as initialized and failing every request. This temporary bridge can be removed after all
databases have been adopted. The project requires Rust 1.98.0 (see
`rust-toolchain.toml`).

### Storage quota

Put the SQLite database, WAL and Litestream state on a dedicated volume with a
filesystem or project quota. Keep the directory private (`0700`, process umask
`0077`), alert before 70%, 85% and 95% usage, and reserve enough headroom for
WAL checkpoints and replication. Do not automatically delete recovery secrets:
when the quota is reached, new stores must fail closed until the operator adds
capacity or applies an explicit retention policy.

### Pre-deploy privacy and recovery gates

Before activation verify one systemd instance, a loopback bind, a `0700`
deployment directory, `.env` mode `0600`, and service `umask 0077`. Set
`LimitCORE=0` and configure swap/crash handling. Define retention for the
database, WAL, and Litestream copies; test restore and rollback, including the
WAL. Run canary/wipe and store/fetch/trash smoke checks before admitting traffic.
Debug logging is temporary only and must be disabled before canary exposure.

At the default `RATE_LIMIT_MAX_IDENTIFIERS=100000` with
`RATE_LIMIT_MAX_ATTEMPTS=3`, a release build measured 22.1 MB JSON,
4.01 MB gzip, and **117 MB peak RSS** (1121 bytes per entry). An earlier
audit recorded about 254 MiB peak on a different host with the same 4.01 MB
gzip body; the snapshot no longer copies the ledger's CandidateTag sets,
which removed 27% of the peak at this candidate budget and about half of it
at larger ones. These are measurements on specific hosts, not a universal
guarantee: set service memory and capacity with headroom, and re-measure
after changing `RATE_LIMIT_MAX_ATTEMPTS`, which is the term that dominates
per-entry cost.

### Run the app

```sh
cargo run
```

### Usage

```sh
# Info
curl -X GET http://localhost:3000/info

# Store
curl -i -X POST http://localhost:3000/store \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635", "encrypted_secret": "4a1dl1T8cxcP2pnvxwYWDwm/I68vVd9oWMY0nTOmBSNbonEN/mfBjkPWkSNlxjWacsS2lRVzoGUQ4guZArKf415dLvbObReqWNtzmA4vaB9/feJapmgWAssVI9EbhJFf"}'

# Fetch
curl -i -X POST http://localhost:3000/fetch \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635"}'

# Trash
curl -i -X POST http://localhost:3000/trash \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635"}'

# Attempts (lookup telemetry snapshot, gzip-compressed, identifiers are SHA-256 hashed)
curl --compressed -X GET http://localhost:3000/attempts

# Attempts, conditional revalidation (returns 304 when unchanged)
curl --compressed -X GET http://localhost:3000/attempts -H 'If-None-Match: "<etag>"'
```

## Tests

### End to end
The suite is safe to run with the default parallel test runner — per-test
database isolation is handled by the test harness — and matches CI:
```sh
cargo test --locked
```
Tests that exercise rate limits install their own token buckets rather than
relying on environment-provided values, so the suite passes with any `.env`
(see [SECURITY.md](SECURITY.md), "Test-writing traps").

### Coverage
```sh
cargo install cargo-tarpaulin

cargo tarpaulin
```



## Note on rust-analyzer

Rust analyser may throw some errors in main regarding procMacro.

To fix this add the following to codium's settings.json

```json
  "rust-analyzer.procMacro.enable": true,
```
