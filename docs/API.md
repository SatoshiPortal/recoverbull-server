# RecoverBull server API

This is the wire contract of the server: what a client sends and what it gets back. The normative protocol is the [RecoverBull specification](https://github.com/SatoshiPortal/recoverbull-whitepaper/blob/master/SPECIFICATION.md); the security model and its accepted risks are in [SECURITY.md](../SECURITY.md).

## Definitions
- `secret` The cleartext secret of the user.
- `password` A user-chosen password (may be weak).
- `authentication_key` A deterministic hash derived from `password` used server-side to compute an internal `secret_id`.
- `encryption_key` A deterministic hash derived from `password` used client-side to **encrypt** the `secret` **before** storage on the server.
- `identifier` random secure octets (e.g., in a local file), required to retrieve the `encrypted_secret`.
- `secret_id` = `hash(identifier + authentication_key)` Unique record key in the server’s database. This is also the unit the rate limiter counts: what the specification calls a *candidate* is a distinct `secret_id`, and this document and the code use only the latter name. Concretely: **SHA-256 over the concatenation of the two lowercase hex *strings*** (128 ASCII bytes) — not over the decoded raw bytes. This differs from the `/attempts` `id_hash`, which hashes the raw identifier bytes; client implementations must not mix the two.
- `encrypted_secret` = `encrypt(private_key: encryption_key, payload: secret)` The ciphertext of the secret using `encryption_key`.

## Request diagnostics and security counters

Every response includes a server-generated `X-Request-ID`. Client-provided
`x-request-id` headers are removed before routing and are never reused. The
value is opaque and deliberately not the request counter, which would let any
client subtract two IDs and read the server's request volume.

Request logging is one rule: **a server error produces one `WARN` line, and
nothing else produces any**. That line carries only the request ID, the static
route enum (`store`, `fetch`, `trash`, `info`, `attempts`, `other`) and the
numeric status; an unknown path collapses to `other`, so a request target
never reaches a log as text. A `503` is pressure, not a fault: it is the one
`5xx` a client can trigger at will, so it is counted rather than logged.

Everything else is aggregate. The security counter reporter emits one summary
line every five minutes at `info`, including `request_timeout`,
`lookup_rate_limited`, `attempts_rate_limited`, `database_busy`,
`database_error` and `attempts_snapshot_failed`. That line is unconditional
and cannot be crowded out, so a signal that must survive load belongs there.
Log volume control belongs to the log daemon (see
[OPERATIONS.md](OPERATIONS.md)).

## Store

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

> **`/store` is idempotent and never overwrites.** A store for a `secret_id`
> that already exists returns `201` and keeps the existing row, exactly like a
> fresh store: this is deliberate, so the response cannot become an
> `authentication_key` existence oracle. The consequence is that the **first**
> writer of a `secret_id` owns the row. A client MUST therefore generate a
> fresh random `identifier` (and `salt`) for every `/store` and MUST NOT
> re-store under an identifier that has already left the device, otherwise a
> party that learned that identifier could have pre-planted a row and the
> real backup would be silently discarded. A client SHOULD confirm a store
> with one `/fetch` and a ciphertext comparison before declaring the backup
> complete.


## Fetch

 1. The client, must own informations needed such as `identifier`, `password`, `salt`…

 2. From the `password` we re-generate the two derived keys `authentication_key` and `encryption_key` using the same Argon2 params and `salt`.

 3. The client make a `fetch` request to the server containing:
- `identifier`
- `authentication_key`

  4. The server receives the `fetch secret` request and performs:
- Compute the `secret_id`/`key_id` from the identifier and authentication key. The per-identifier bucket is always `sha256(identifier)`.
- Retain only the derived `secret_id` in memory: never raw authentication or password material. These values are state-only, have at most `RATE_LIMIT_MAX_ATTEMPTS` slots, are wiped after the cooldown or a restart, and are never logged or included in a snapshot.
- A new `secret_id` immediately reserves one slot and counts in the budget. A duplicate `Pending` `secret_id` receives `503` before saturation rather than taking another slot.
- If the consumed slots reach `max`, return `429` before membership or database work for **every** `secret_id`, including known, `Pending`, and `Committed`, so saturation cannot be an authentication oracle.
- A `Committed` replay is free only before saturation: it increments `total_requests`, does not extend the cooldown, and does not add another attempt. `/fetch` and `/trash` share this `secret_id` set. A successful `/trash` is the one exception: the `secret_id` that authenticated the deletion keeps its consumed slot but stops being recognizable, so presenting it again afterwards consumes a new slot like any other value. Otherwise its free replay would tell a Backup File holder which PIN had been used for the deletion.
- Finalization is detached and generation-safe. A hit or miss commits the `secret_id`; a miss increments `failed_attempts` exactly once. A database error or cancellation before database work removes `Pending`; a trash race returning `202`/`401` does not create a false failed `secret_id`.

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
> - `total_attempts` is the number of slots consumed in the current cooldown window: one per distinct `secret_id` admitted, never refunded by a successful `/trash`. After a deletion the `secret_id` that performed it is no longer recognizable, so it consumes a new slot if presented again. A hit does not prove ownership, because a public `/store` caller can plant a matching row.
> - `failed_attempts` counts distinct `secret_id` values for which no database row existed, incremented once when that `secret_id` is finalized as a miss.
> - `remaining_attempts` is `rate_limit_max_attempts - total_attempts`, saturating at zero.
> - `total_requests` counts every `/fetch` and `/trash` request attached to this identifier's active entry, including replays, pending duplicates, and saturation rejections. Requests rejected because the global identifier map is already full have no per-identifier entry and are not included. The global lookup bucket remains the defense against floods of identical replays.
> - `previous_attempt_at` is the admitted attempt immediately preceding this request (`null` when this request opened the window), and `resets_at` is when the budget expires.
> - A successful lookup never resets the counters; they expire only after the configured cooldown.

> **Retrying a `/trash` whose `202` was lost.** A successful `/trash` deletes
> the row and forgets the `secret_id` that authenticated it, so that a later
> replay cannot reveal which PIN performed the deletion. As a result, if the
> `202` response is lost in transit and the client retries the same request,
> the retry is a brand-new `secret_id` that finds no row: it returns `401`,
> consumes a slot, and counts as a `failed_attempts`. A client SHOULD treat a
> `401` following a `/trash` whose response it never received as "possibly
> already deleted", and MUST NOT retry a `/trash` more than once, so a lost
> acknowledgement does not spend the identifier's budget or look like an attack
> in its own telemetry.

### Timestamp precision by response

Timestamp precision follows the knowledge gradient — the more a caller must already know, the more precise the timestamps it receives:

- **Successful `/fetch` and `/trash` (`attempt_status`)**: exact, second-precision timestamps. Reachable by anyone holding the `identifier` (a hit can always be manufactured by planting a row through `/store`), so exact precision here widens no audience.
- **Failed lookup (`401`)**: `requested_at` is the time of the caller's own request — it reveals nothing about anyone else.
- **Lockout (`429`)**: `requested_at` is the **exact** time of the last *admitted* attempt, which may be the victim's. Anyone holding the `identifier` can read it once the budget is exhausted. This is accepted: the same caller already gets hour precision from the public snapshot, and the exact value is what a client needs to compute its retry time.
- **Public `/attempts` snapshot**: hour-truncated timestamps, because the audience is everyone — exact timestamps would ease correlation without requiring any knowledge of the `identifier`.

## Error responses

Clients classify errors **only by HTTP status**. Application error responses are
JSON objects containing at least an `error` field. The `error` text is for
humans and logs; it is not contractual and must never be matched to make a
retry or security decision.

| HTTP status | Meaning | Client treatment |
|---|---|---|
| `400` | Invalid request data. | Fix the request. |
| `401` | Invalid credentials. | Treat as an authentication failure. |
| `429` | The targeted identifier's `secret_id` budget is locked. This is the only security alarm. | Surface the targeted lockout and honor `Retry-After`. |
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

## Attempts

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
- `total_attempts`: number of slots consumed in the current cooldown window (distinct `secret_id` values admitted; a `secret_id` presented again after it deleted the row through `/trash` counts as a new one).
- `failed_attempts`: number of distinct `secret_id` values for which no database row existed.
- `total_requests`: every `/fetch` and `/trash` request attached to this identifier's active entry, including replays; map-capacity rejections for previously unseen identifiers cannot be attributed to an entry. It is telemetry, not the `secret_id` budget.
- `window_started_at` / `last_attempt_at`: hour-truncated timestamps of the current window; `last_attempt_at` is the last distinct `secret_id` timestamp, not the latest replay request. The JSON field name is retained for compatibility.
- `collection_started_at`: hour-truncated start of the in-memory collection. It changes at startup and after each global 24-hour wipe; clients must reset their baseline.

Identifiers are kept and published hashed, never raw. The entire identifier map, including the retained `secret_id` values, is wiped every 24 hours from map startup and the attempt budget resets at that boundary. Individual entries disappear earlier, as soon as their cooldown has elapsed: expiry is applied to an entry when it is next used, to the whole map whenever it is full, and to the whole map before every snapshot build, so an expired entry is never published and never causes a refusal. Nothing is persisted.

The body is **always gzip-compressed JSON** (`Content-Encoding: gzip`); clients must be gzip-capable. This initial telemetry contract, version `1`, reports distinct-`secret_id` counters plus `total_requests` and never exposes a `secret_id`. The snapshot is rebuilt at most once per minute and served as immutable shared bytes with a strong `ETag`: send `If-None-Match` to receive a bodyless `304` when nothing changed. `Cache-Control: public, max-age=<remaining seconds>` reflects the real freshness. A dedicated global token bucket (`ATTEMPTS_RATE_LIMIT_*`) bounds cache-bypass traffic; production deployments must additionally cache and rate-limit this route at the reverse proxy (see [OPERATIONS.md](OPERATIONS.md)). `deploy/nginx/` is the CI-tested, operator-adapted example.

**Proactive detection is the client's responsibility.** The server publishes
the snapshot and cannot notify anyone; only a wallet that polls it can turn an
entry into a warning. Server deployment and wallet rollout are therefore two
stages of the same detection feature. Bull Mobile does not currently poll
`/attempts`, so deploying this server alone leaves proactive detection
incomplete until a compatible Bull Mobile release ships; until then the server
side offers rate limiting, `attempt_status` on lookups, and `429`, but no early
warning. That release should poll regularly while the app is in the foreground
and use best-effort background scheduling where the operating system permits
it. Requests should
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
- **`attempt_status` on a successful fetch is the freshest signal**: it needs no extra request and stays available even when `/attempts` is overloaded. Failures older than the cooldown expire and are forgotten when the entry is next used, when the full map is checked, or before a snapshot build; a success never resets the counters early.
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

The canary from the dotenv file is re-read at most once every ten minutes,
and `/info` advertises what remains of that freshness in `Cache-Control`, so
a client or proxy cache cannot make the signal older than one interval. The
file semantics are unchanged and are the signal itself: a readable file
without `CANARY` returns an empty string, and an unavailable file falls back
to the startup value. A process-environment `CANARY` is authoritative, skips
file access entirely, and is advertised with `max-age=0` because only a
restart can change it. `/info` is never rate-limited, so an operator editing
the file sees the change within the interval without a restart.

The global wipe is a process-memory boundary, not guaranteed erasure: a
suspended process, swap, or core dump may retain old pages. The 24-hour timer
does not advance while the process is stopped or suspended; restart begins a
new collection.

## Sensitive POST response floor

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
listed in [SECURITY.md](../SECURITY.md).



## Example requests

Against a local development server (`cp .env.example .env && cargo run`, listening on `127.0.0.1:3000`):


```sh
# Info
curl -X GET http://127.0.0.1:3000/info

# Store
curl -i -X POST http://127.0.0.1:3000/store \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635", "encrypted_secret": "4a1dl1T8cxcP2pnvxwYWDwm/I68vVd9oWMY0nTOmBSNbonEN/mfBjkPWkSNlxjWacsS2lRVzoGUQ4guZArKf415dLvbObReqWNtzmA4vaB9/feJapmgWAssVI9EbhJFf"}'

# Fetch
curl -i -X POST http://127.0.0.1:3000/fetch \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635"}'

# Trash
curl -i -X POST http://127.0.0.1:3000/trash \
-H "Content-Type: application/json" \
-d '{"identifier":"bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a","authentication_key":"4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635"}'

# Attempts (lookup telemetry snapshot, gzip-compressed, identifiers are SHA-256 hashed)
curl --compressed -X GET http://127.0.0.1:3000/attempts

# Attempts, conditional revalidation (returns 304 when unchanged)
curl --compressed -X GET http://127.0.0.1:3000/attempts -H 'If-None-Match: "<etag>"'
```

