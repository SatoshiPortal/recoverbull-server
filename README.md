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

On a fresh Debian 13 host, as a user with `sudo`:

```sh
sudo apt install build-essential git curl   # linker for the Rust build, git, and curl for rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none && . ~/.cargo/env
git clone https://github.com/SatoshiPortal/recoverbull-server.git
cd recoverbull-server
cargo build --release --locked
sudo deploy/recoverbull install     # asks for the warrant canary (or --canary '<text>' for a scripted install), prints the onion address
```

To upgrade, keeping the database, run the same command after updating the checkout:

```sh
git pull && cargo build --release --locked && sudo deploy/recoverbull install
```

Check it with `sudo deploy/recoverbull status` (the onion shows as `starting` for up to ten minutes after Tor starts) and `sudo deploy/recoverbull logs`. To move an existing server here with its data and onion address, add `--database <file> --onion-keys <dir>` to the first install. Before going live, read the six rules at the top of [docs/OPERATIONS.md](docs/OPERATIONS.md). The one that costs the most to forget: **back up the onion keys off the host**, they are the server address.

## Try it in a container

[`deploy/test/Containerfile`](deploy/test/Containerfile) builds a Debian 13 image with systemd, which the install script needs. Build it, start it privileged (the hardened unit needs device and namespace isolation), and follow the install steps inside, cloning the repository in the container:

```sh
podman build -t recoverbull-debian13 -f deploy/test/Containerfile .
podman run -d --name recoverbull-test --privileged --systemd=always --memory 2g recoverbull-debian13
podman exec -it -u op -w /home/op recoverbull-test bash -l
```

The onion becomes reachable a few minutes after Tor starts. This is a test bench; a production host is a real Debian 13 machine.

## Develop

Requires Rust 1.99 (pinned in `rust-toolchain.toml`, installed automatically by rustup). For a new local configuration, copy [`.env.example`](.env.example) to `.env`, uncomment `CANARY` and set its value before starting. Keep an existing `.env`. An unset canary prevents startup; an explicitly empty value signals that the server is compromised. The template uses `production_db.sqlite3` in the working directory and production limits.

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
