# Keychain

## Setup dotenv

```sh
echo "DATABASE_URL=keychain_db.sqlite3" > .env && \
echo "TEST_DATABASE_URL=test_db.sqlite3" > .env && \
echo "KEYCHAIN_ADDRESS=0.0.0.0:3000" > .env && \
echo "REQUEST_COOLDOWN=720" > .env && \
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

## Usage

```sh
# Create a new entry
curl -i -X POST http://localhost:3000/store_key \
-H "Content-Type: application/json" \
-d '{"secret": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "backup_key": "my_backup_key"}'

# secret is the sha256 of 123456

# Recover
curl -i -X POST http://localhost:3000/recover_key \
-H "Content-Type: application/json" \
-d '{"id": "a5d1320aab2aef2570449ee3af767bcb541d1b62f01a1b19be3ad9ae131dc0a1", "secret": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"}
'
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
cargo tarpaulin
```



## Note on rust-analyzer

Rust analyser may throw some errors in main regarding procMacro.

To fix this add the following to codium's settings.json

```json
  "rust-analyzer.procMacro.enable": true,
```
