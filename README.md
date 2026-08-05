# Secret Server

The server provides secret storage without relying on traditional credentials systems (account based).

## Description

### Definitions
- `secret` The cleartext secret of the user.
- `password` A user-chosen password (may be weak).
- `authentication_key` A deterministic hash derived from `password` used server-side to compute an internal `secret_id`.
- `encryption_key` A deterministic hash derived from `password` used client-side to **encrypt** the `secret` **before** storage on the server.
- `identifier` random secure octets (e.g., in a local file), required to retrieve the `encrypted_secret`.
- `secret_id` = `hash(identifier + authentication_key)` Unique record key in the server’s database.
- `encrypted_secret` = `encrypt(private_key: encryption_key, payload: secret)` The ciphertext of the secret using `encryption_key`.

### Store

 1. On the client side, generate a random secure `identifier`, that you can store securely in a file, and let the user define a `password`.

 2. Since the `password` is probably weak, we use a password hashing function such as Argon2 to derive a 64 octets (512 bits) key splitted in two keys:
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

4. The server receive the `fetch secret` request an perform:
- Reserve one lookup in an in-memory counter keyed by `sha256(identifier)`. Every `/fetch` and `/trash` lookup counts, whether or not a matching database row exists.
- If the identifier has reached its lookup budget, return `429` before querying the database. Otherwise compute `secret_id` = `hash(identifier + authentication_key)` and fetch the entry.
- Never reset the lookup budget after a database hit: because `/store` is public, an attacker can create a matching row for a guessed key, so finding a row does not prove ownership. The budget expires only after the configured cooldown.

 5. The user can fetch his `secret` by deciphering `encrypted_secret` using his `encryption_key` as encryption key.

> On success, the response also contains an `attempt_status` object: the attempt counters recorded for this `identifier` during the current cooldown window.
>
> ```json
> {
>   "attempt_status": {
>     "total_attempts": 3,
>     "failed_attempts": 1,
>     "remaining_attempts": 0,
>     "window_started_at": "2026-08-05T12:17:41Z",
>     "previous_attempt_at": "2026-08-05T14:37:22Z",
>     "resets_at": "2026-08-06T15:04:13Z"
>   }
> }
> ```
>
> - `total_attempts` includes the request carrying the response and counts database hits as well as misses: a hit does not prove ownership, because a public `/store` caller can plant a matching row. A client should warn the user when the total is higher than the user's own operations.
> - `failed_attempts` counts only lookups for which no database row existed.
> - `previous_attempt_at` is the admitted attempt immediately preceding this request (`null` when this request opened the window), and `resets_at` is when the budget expires.
> - A successful lookup never resets the counters; they expire only after the configured cooldown.

### Stats

`GET /stats` returns public lookup telemetry for the current cooldown window, with for each entry:

- `id_hash`: SHA-256 of the raw `identifier` bytes
- `attempts`: total number of `/fetch` and `/trash` lookups, including database hits
- `failed_attempts`: number of lookups for which no database row existed
- `last_attempt_at`: timestamp of the last lookup

Identifiers are kept and published hashed, never raw: a client can recognize its own identifier by computing `sha256(identifier)` locally, but nobody can recover a raw identifier from the list (pre-image resistance), which keeps the list useless for griefing or targeted lockout. Entries live in the same in-memory map as the rate-limiter, so they expire with it (cooldown or server reboot): nothing is persisted.

Detection semantics a client should implement:
- **Poll `/stats` proactively** (e.g. at app start): if your identifier hash appears with attempts you did not make, someone is probing your backup.
- **Treat a per-identifier `429` (`"Too many attempts"`, with an `attempts` field) as an alarm**: the separate global overload response (`"Too many lookup requests"`) indicates service-wide pressure instead.
- **`failed_attempts` on a successful fetch is a best-effort signal within the current rate-limit window**: failures older than the cooldown expire (entries are swept and forgotten), but a success never resets the value early.



### Privacy and security goals

A user can store multiple secrets and the server is not able to link any secret to a specific user. Each secret has a random `identifier`. The `secret_id` is built from the hash of the `identifier` and `authentication_key`.

If the `identifier` is found and used by a malicious person, the server is not able to link it to a specific `secret`.
**To mitigate targeted brute-force on a specific `secret`, the server temporarily caches only `sha256(identifier)` in memory. The data does not persist and is cleared on each server reboot.**

The server cannot read users secrets because they are encrypted client-side using the `encryption_key` derived from `password`, the secret encryption mitigate the risk of database leak, attackers would have access to: `secret_id`, `created_at` and `encrypted_secret`.

If an attacker can steal informations to a targeted user such as `salt` and have access to a database leak or `encrypted_secret`, the encryption of the `encrypted_secret` will be as weak as the user `password`.

### Recovery lockout (known design tension)

The rate-limit counter is keyed on `sha256(identifier)` and checked **before** credentials are verified: the server cannot distinguish the legitimate owner from an attacker before the database lookup. Every lookup counts, including successful ones, because a public `/store` caller can plant a row for a guessed key. An attacker holding a victim's Backup File can therefore consume that identifier's lookup budget and keep it locked out, delaying — or with discipline, preventing — the victim's recovery. Other identifiers retain independent budgets.

Mitigations available today:
- **Detection**: clients should poll `/stats` — an identifier under attack shows attempts the user did not make, and an unexpected `429` is itself an alarm. A user who still has wallet access should rotate keys immediately.
- **Redundancy** (client-side): an exported copy of the Backup Key, social recovery, or a second independent Key Server makes the lockout of a single server non-fatal.

Protocol roadmap: escalating backoff (delay without permanent denial), client proof-of-work (cost per guess instead of a hard cap), or multi-server storage.


## Deployment

### Tor onion service (the supported deployment)

The server is designed to be reached exclusively through a **Tor onion service**: it protects the transport confidentiality of the `authentication_key` and the IP anonymity of clients. **Never expose it directly on a public interface** — the server refuses to stay silent about it and prints a startup warning when `SERVER_ADDRESS` is not loopback. Production deployments must put a reverse proxy between Tor and Axum because Axum's route timeout starts after HTTP headers have been read.

1. Keep Axum on a private loopback port: `SERVER_ADDRESS=127.0.0.1:3001`
2. Configure nginx on `127.0.0.1:3000` with strict header/body timeouts and connection limits:

```nginx
limit_conn_zone $binary_remote_addr zone=recoverbull_connections:10m;

server {
    listen 127.0.0.1:3000;
    client_max_body_size 1k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 35s;
    limit_conn recoverbull_connections 100;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_connect_timeout 2s;
        proxy_read_timeout 35s;
    }
}
```

All Tor connections reach nginx from loopback, so this connection limit is intentionally global.

3. Configure the onion service in `torrc` to reach nginx:

```
HiddenServiceDir /var/lib/tor/recoverbull/
HiddenServicePort 80 127.0.0.1:3000
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
echo "TEST_DATABASE_URL=test_db.sqlite3" >> .env && \
echo "SERVER_ADDRESS=127.0.0.1:3001" >> .env && \
echo "SECRET_MAX_LENGTH=128" >> .env && \
echo "CANARY='🐦'" >> .env && \
echo "RATE_LIMIT_COOLDOWN=1440" >> .env && \
echo "RATE_LIMIT_MAX_FAILED_ATTEMPTS=3" >> .env && \
echo "MIGRATIONS_DIR=$(pwd)/migrations" >> .env
```

Optional, with defaults shown — a global token bucket dampening unauthenticated `/store` writes (per-IP is useless behind an onion service):

```sh
echo "STORE_RATE_LIMIT_BURST=10" >> .env && \
echo "STORE_RATE_LIMIT_REFILL_PER_SECOND=2" >> .env && \
echo "LOOKUP_RATE_LIMIT_BURST=100" >> .env && \
echo "LOOKUP_RATE_LIMIT_REFILL_PER_SECOND=5" >> .env && \
echo "RATE_LIMIT_MAX_IDENTIFIERS=100000" >> .env && \
echo "DATABASE_MAX_CONCURRENCY=16" >> .env
```
This configuration admits two `/store` requests per second (172,800 per day)
in steady state. After startup, or after five seconds without a `/store`
request, the bucket holds an initial burst of ten requests, so the first day
can admit at most 172,810 requests. Every admitted request consumes a token,
including an idempotent duplicate that does not create a new row. If every
request has a new identifier and a maximum-size secret, SQLite grows by about
43 to 86 MB/day, depending on page and index overhead.
`RATE_LIMIT_MAX_FAILED_ATTEMPTS` is the legacy configuration name for the
per-identifier lookup budget; database hits consume it as well as misses.
The lookup bucket is a separate global safety limit for `/fetch` and `/trash`.
The identifier cap bounds memory without evicting active security entries;
new identifiers receive `503` while the cap is full. SQLite work is limited to
16 concurrent blocking operations, and requests waiting more than one second
for a slot receive `503` without consuming their per-identifier attempt.
> `SECRET_MAX_LENGTH=128` represents the size of a 96 octets encrypted secret encoded using base64
> 96 octets =  `nonce` (16 octets) | `ciphertext` (32 octets) | `hmac` (32 octets) + 16 octets padding to round up to 32 octets blocks

### execute migrations

```sh
diesel migration run
```

### Storage quota

Put the SQLite database, WAL and Litestream state on a dedicated volume with a
filesystem or project quota. Keep the directory private (`0700`, process umask
`0077`), alert before 70%, 85% and 95% usage, and reserve enough headroom for
WAL checkpoints and replication. Do not automatically delete recovery secrets:
when the quota is reached, new stores must fail closed until the operator adds
capacity or applies an explicit retention policy.

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

# Stats (brute-force telemetry, identifiers are SHA-256 hashed)
curl -X GET http://localhost:3000/stats
```

## Tests

### End to End
Do not run tests in parallel
```sh
cargo test -- --test-threads=1 --nocapture
```

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
