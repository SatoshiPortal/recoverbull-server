# Keychain

## Setup dotenv

```sh
echo "DATABASE_URL=mydb.sqlite3" > .env && \
echo "MIGRATIONS_DIR=$(pwd)/migrations" >> .env
```

## execute migrations

```sh
diesel migration run
```

## Run the app

```sh
cargo run
```

## Test

```sh
# Create a new entry
curl -X POST http://localhost:3000/key \
-H "Content-Type: application/json" \
-d '{"secret_hash": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "backup_key": "my_backup_key"}'

# secret_hash is the sha256 of 123456

# Recover
curl -X POST http://localhost:3000/recover \
-H "Content-Type: application/json" \
-d '{"id": "a5d1320aab2aef2570449ee3af767bcb541d1b62f01a1b19be3ad9ae131dc0a1", "secret_hash": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"}
'
# id is the sha256 of my_backup_key
```

## Note on rust-analyzer

Rust analyser may throw some errors in main regarding procMacro.

To fix this add the following to codium's settings.json

```json
  "rust-analyzer.procMacro.enable": true,
```
