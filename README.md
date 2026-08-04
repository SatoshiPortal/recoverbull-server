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
- Look-up in an in-memory cache `Map<identifier, DateTime?>` to check if this `identifier` has already been requested recently. If not enough time elapsed, the user remains rate-limited. –> Mitigate targeted brute-force.
- If the user is not rate-limited, the server compute `secret_id` = `hash(identifier + authentication_key)` and fetch the entry in the database. If something is found it returns the `encrypted_secret` else it add the `identifier` to the in-memory cache to the map to limit further attempts.

 5. The user can fetch his `secret` by deciphering `encrypted_secret` using his `encryption_key` as encryption key.

> On success, the response also contains a `failed_attempts` field: the number of failed attempts recorded for this `identifier` since the last successful fetch (or trash). The counter is reset on success, since a successful authentication proves ownership of the secret. A client should warn the user when this number is higher than the user's own mistakes, as it may indicate a brute-force or lockout attempt against his backup.

### Stats

`GET /stats` returns public brute-force telemetry: the list of identifiers currently rate-limited for failed fetch/trash attempts, with for each entry:

- `id_hash`: SHA-256 of the raw `identifier` bytes
- `attempts`: number of failed attempts recorded
- `last_failed_at`: timestamp of the last failed attempt

Identifiers are published hashed, never raw: a client can recognize its own identifier by computing `sha256(identifier)` locally, but nobody can recover a raw identifier from the list (pre-image resistance), which keeps the list useless for griefing or targeted lockout. Entries live in the same in-memory map as the rate-limiter, so they expire with it (cooldown reset or server reboot): nothing is persisted.

Detection semantics a client should implement:
- **Poll `/stats` proactively** (e.g. at app start): if your identifier hash appears with attempts you did not make, someone is probing your backup.
- **Treat an unexpected `429` as an alarm**: if you did not make failed attempts, someone else locked your identifier.
- **`failed_attempts` on a successful fetch is a best-effort signal within the current rate-limit window**: failures older than the cooldown expire (entries are swept and forgotten), so the count reflects the current window and restarts from zero afterwards.



### Privacy and security goals

A user can store multiple secrets and the server is not able to link any secret to a specific user. Each secret has a random `identifier`. The `secret_id` is built from the hash of the `identifier` and `authentication_key`.

If the `identifier` is found and used by a malicious person, the server is not able to link it to a specific `secret`.
**To mitigate targeted brute-force on a specific `secret`, the server cache temporarily the `identifier` in-memory. The data does not persist and is cleared on each server reboot. The in-memory cache is exposed only if an attacker take the control of the server and dump the memory.**

The server cannot read users secrets because they are encrypted client-side using the `encryption_key` derived from `password`, the secret encryption mitigate the risk of database leak, attackers would have access to: `secret_id`, `created_at` and `encrypted_secret`.

If an attacker can steal informations to a targeted user such as `salt` and have access to a database leak or `encrypted_secret`, the encryption of the `encrypted_secret` will be as weak as the user `password`.

### Recovery lockout (known design tension)

The rate-limit counter is keyed on `identifier` and checked **before** credentials are verified: the server cannot distinguish the legitimate owner from an attacker before the database lookup. An attacker holding a victim's Backup File can therefore keep that identifier locked out (a few failed attempts per cooldown window), delaying — or with discipline, preventing — the victim's recovery. Any scheme that lets the owner through before verification also lets the attacker through: there is no server-only fix.

Mitigations available today:
- **Detection**: clients should poll `/stats` — an identifier under attack shows attempts the user did not make, and an unexpected `429` is itself an alarm. A user who still has wallet access should rotate keys immediately.
- **Redundancy** (client-side): an exported copy of the Backup Key, social recovery, or a second independent Key Server makes the lockout of a single server non-fatal.

Protocol roadmap: escalating backoff (delay without permanent denial), client proof-of-work (cost per guess instead of a hard cap), or multi-server storage.


## Deployment

### Tor onion service (the supported deployment)

The server is designed to be reached exclusively through a **Tor onion service**: it protects the transport confidentiality of the `authentication_key` and the IP anonymity of clients. **Never expose it directly on a public interface** — the server refuses to stay silent about it and prints a startup warning when `SERVER_ADDRESS` is not loopback.

1. Keep the server on loopback: `SERVER_ADDRESS=127.0.0.1:3000`
2. Configure the onion service in `torrc`:

```
HiddenServiceDir /var/lib/tor/recoverbull/
HiddenServicePort 80 127.0.0.1:3000
```

3. Reload Tor and read the onion hostname:

```sh
sudo systemctl reload tor
sudo cat /var/lib/tor/recoverbull/hostname
```

A reverse proxy (e.g. nginx) may sit between Tor and the app for global request-rate limiting and timeouts. Note that behind an onion service **all connections arrive from 127.0.0.1**, so per-IP rules are useless: use a single global bucket.

### dotenv

```sh
echo "DATABASE_URL=production_db.sqlite3" >> .env && \
echo "TEST_DATABASE_URL=test_db.sqlite3" >> .env && \
echo "SERVER_ADDRESS=127.0.0.1:3000" >> .env && \
echo "SECRET_MAX_LENGTH=128" >> .env && \
echo "CANARY='🐦'" >> .env && \
echo "RATE_LIMIT_COOLDOWN=1440" >> .env && \
echo "RATE_LIMIT_MAX_FAILED_ATTEMPTS=3" >> .env && \
echo "MIGRATIONS_DIR=$(pwd)/migrations" >> .env
```
> `SECRET_MAX_LENGTH=128` represents the size of a 96 octets encrypted secret encoded using base64
> 96 octets =  `nonce` (16 octets) | `ciphertext` (32 octets) | `hmac` (32 octets) + 16 octets padding to round up to 32 octets blocks

### execute migrations

```sh
diesel migration run
```

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
