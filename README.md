# RecoverBull server

A key server for wallet backups without accounts. A client stores a secret it has already encrypted; getting it back takes a random identifier kept by the user plus their password, and the server limits how many passwords can be tried per identifier. It is reachable only as a Tor onion service.

The protocol is described in the [RecoverBull whitepaper and specification](https://github.com/SatoshiPortal/recoverbull-whitepaper).

## Where to start

| You want to… | Read |
|---|---|
| Run a server, upgrade it, back it up | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Write a client | [docs/API.md](docs/API.md) |
| Review or audit the security model | [SECURITY.md](SECURITY.md) |

## Run a server in short

On a fresh Debian 13 host with Rust installed, as your user:

```sh
git clone https://github.com/SatoshiPortal/recoverbull-server.git
cd recoverbull-server
cargo build --release --locked
sudo deploy/recoverbull install     # asks for the warrant canary, prints the onion address
```

To upgrade, keeping the database, run the same command after updating the checkout:

```sh
git pull && cargo build --release --locked && sudo deploy/recoverbull install
```

Check it with `sudo deploy/recoverbull status` and `sudo deploy/recoverbull logs`. To move an existing server here with its data and onion address, add `--database <file> --onion-keys <dir>` to the first install. Before going live, read the six rules at the top of [docs/OPERATIONS.md](docs/OPERATIONS.md). The one that costs the most to forget: **back up the onion keys off the host**, they are the server address.

## Develop

Requires Rust 1.98 (pinned in `rust-toolchain.toml`, installed automatically by rustup).

```sh
cp .env.example .env      # test values, not for production
cargo run                 # serves on 127.0.0.1:3000
cargo test --locked       # same as CI; safe to run in parallel
```

`.env.example` holds the values CI uses. Production values are in [deploy/recoverbull.env.example](deploy/recoverbull.env.example).

The database schema is migrated automatically at startup from the embedded migrations in `migrations/`.

## License

MIT
