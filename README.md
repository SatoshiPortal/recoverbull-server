# RecoverBull server

A key server for wallet backups without accounts. A client stores a secret it has already encrypted; getting it back takes a random identifier kept by the user plus their password, and the server limits how many passwords can be tried per identifier. It is reachable only as a Tor onion service.

The protocol is described in the [RecoverBull whitepaper and specification](https://github.com/SatoshiPortal/recoverbull-whitepaper).

## Where to start

| You want to… | Read |
|---|---|
| Run a server, upgrade it, back it up | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Write a client | [recoverbull-client-dart](https://github.com/SatoshiPortal/recoverbull-client-dart) and the [specification](https://github.com/SatoshiPortal/recoverbull-whitepaper/blob/master/SPECIFICATION.md); [docs/API.md](docs/API.md) for what this server adds |
| Review or audit the security model | [SECURITY.md](SECURITY.md) |

## Run a server in short

Build the server with the Rust version pinned in `rust-toolchain.toml`:

```sh
git clone https://github.com/SatoshiPortal/recoverbull-server.git
cd recoverbull-server
cargo build --release --locked
```

Follow the [manual deployment guide](docs/OPERATIONS.md) to configure the server, nginx and Tor, using your own paths, ports and services. [`.env.example`](.env.example) is the production configuration template; review its database path before starting. It supplies the public compatibility value `CANARY=🐦` expected by standard RecoverBull clients. Back up both the database and the onion keys before changing an existing installation.

## Develop

Requires Rust 1.99 (pinned in `rust-toolchain.toml`, installed automatically by rustup). For a new local configuration, copy [`.env.example`](.env.example) to `.env` and review its database path before starting. Keep an existing `.env`. Normal operation with standard clients requires `CANARY=🐦`; this is a public value, not a secret. Another value requires clients explicitly configured to expect it. An unset canary prevents startup; an explicitly empty value signals that the server is compromised. The template uses `production_db.sqlite3` in the working directory and production limits.

```sh
cargo run # serves on 127.0.0.1:3001
```

Run tests with the same explicit fixture as CI, scoped to a subshell so its permissive limits never replace `.env` or remain in your shell:

```sh
( set -a; . ./tests/fixtures/server.env; set +a; cargo test --locked )
```

Tests remain safe to run in parallel. Updating the template does not update an existing `.env`: review its values and any process-environment overrides, especially if it came from an older test-oriented example.

The database schema is migrated automatically at startup from the embedded migrations in `migrations/`.

## License

MIT
