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



### Privacy and security goals

A user can store multiple secrets and the server is not able to link any secret to a specific user. Each secret has a random `identifier`. The `secret_id` is built from the hash of the `identifier` and `authentication_key`.

If the `identifier` is found and used by a malicious person, the server is not able to link it to a specific `secret`.
**To mitigate targeted brute-force on a specific `secret`, the server cache temporarily the `identifier` in-memory. The data does not persist and is cleared on each server reboot. The in-memory cache is exposed only if an attacker take the control of the server and dump the memory.**

The server cannot read users secrets because they are encrypted client-side using the `encryption_key` derived from `password`, the secret encryption mitigate the risk of database leak, attackers would have access to: `secret_id`, `created_at` and `encrypted_secret`.

If an attacker can steal informations to a targeted user such as `salt` and have access to a database leak or `encrypted_secret`, the encryption of the `encrypted_secret` will be as weak as the user `password`.


## Deployment
### dotenv

```sh
echo "DATABASE_URL=production_db.sqlite3" >> .env && \
echo "TEST_DATABASE_URL=test_db.sqlite3" >> .env && \
echo "SERVER_ADDRESS=0.0.0.0:3000" >> .env && \
echo "REQUEST_COOLDOWN=720" >> .env && \
echo "SECRET_MAX_LENGTH=128" >> .env && \
echo "CANARY='🐦'" >> .env && \
echo "SECRET_KEY='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" >> .env && \
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
# Decrypted Store
# {
#         "identifier": "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a", sha256(111111)
#         "authentication_key": "4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635", sha256(222222)
#         "encrypted_secret": "4a1dl1T8cxcP2pnvxwYWDwm/I68vVd9oWMY0nTOmBSNbonEN/mfBjkPWkSNlxjWacsS2lRVzoGUQ4guZArKf415dLvbObReqWNtzmA4vaB9/feJapmgWAssVI9EbhJFf",
# }

# Store
curl -i -X POST http://localhost:3000/store \
-H "Content-Type: application/json" \
-d '{"public_key":"68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5","encrypted_body":"AkSEBOdaL+dv6R53u/dhUqLjOiAjTMSxmfc0Olha5JNtjTnT8Wh53s7rQtstISIdzpJYGiEfSWQ26dzWZoJXLyJE7xx2CQomoz4u31XENVLXo68P/EDF9BkbsZup5cQDN4SA0vdYr88qOnwzbf3jJp/3yiPYhOJDAMct15J3R8MhYKlBnZJ20czrG3lfXLgDN/9YbV/pmBMrsUvzC8Vz7cfLb0fLpSUW60RJFUasUEHeN0kPOTcNt6gBlsMQx230vzmyDDJUCtve+cpaqw8X5rniG5FKTC8M5YXAvmeltK3taqh0FVps21tvRcgn0W5rKt3qc/y+502ktuMnXmq4ZMk7v5AEfQrCTtxLh16x9AnxEkSE2qPU8efAvl8IUGG8Sd9hsO10hO1tZaONF/ZkASGCQs/TSzEhPS101ktzJ/uDsq+adLoKJboc2CWYxFngziJvcERhmrJrrA2GS9RkeoWVboQMdRHg3kHfCS6hp/bfea83PEhjXfHAL0XVLL4RUItB"}'

# Decrypted Fetch
# {
#         "identifier": "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a",
#         "authentication_key": "4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635",
# }

# Fetch
curl -i -X POST http://localhost:3000/fetch \
-H "Content-Type: application/json" \
-d '{"public_key":"68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5","encrypted_body":"AnyDwJEOhwBFS2nYxt6o2baA4hAUV4ji5vuPAGfGF4AM//jd2OeE/pcWqhy4U0hwAY45HTpkr/aj5idP9zvHeq23E5aK+tHCEirK86sywuequ//7EkNDUVDEOdzmr824KF38mGMEejymyhUe4gtrVFfzATT1+BI9YVeZ9FDWSzTxisBSf4WyhNrhbxUlADqv4Ie2ptgl/oqNLUXkaMsstzZA4ls1kpd1dlu+hyjnSkSaUM1WjroZIQyj3voPQcrmM3wlDemUJF+fb+G4syT2W+tEruankJD89VAd/5nlGg9AdpNOrbD0CZjy6gqSu43xOo9puU9R1aOQmTp2uitbm6gVhQ=="}'
# id is the sha256 of my_backup_key
```

## Tests

### End to End
Do not run tests in parallel
```sh
cargo test -- --test-threads=1
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
