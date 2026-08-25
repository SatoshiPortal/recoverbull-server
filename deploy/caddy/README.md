# RecoverBull Caddy alternative

This directory is an alternative to the reference nginx template, not an
additional proxy. Activate exactly one of nginx or Caddy on `127.0.0.1:3000`.
Caddy must be custom-built and validated before it is admitted to onion traffic.
The audited build module is versioned in `build/`; it is the reproducible source
of the binary, not the prose xcaddy command below.

## Exact build pins

The Caddyfile targets Caddy v2.11.4 and these modules. The v2.11.4 tag is
signed: tag object `8ec11a4b7e39a5fd00da2fc5cb9b543e31fd7926` points to commit
`e2eee6a7fce366321294c9c2a79f3146891dcbdf`. Before building, verify the tag
signature and target commit separately. In the resulting `build-info`, verify
Caddy v2.11.4 with module hash
`github.com/caddyserver/caddy/v2 v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=`,
Go 1.26.7, and the runtime modules and replacements; `x/mod` remains verified
in the retained build module because it is a build dependency.

* `github.com/caddyserver/cache-handler@v0.16.0` (commit `3c8632e548fc0a68285f3cd3a28e47035c55ca34`) for strict HTTP caching;
* `github.com/darkweak/storages/otter/caddy@v0.0.15` (commit `e555fafc689a6595b9e9a2b0ba2031e82e3077c6`) for a small local in-memory store;
* `github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db` for global `/attempts` limits.

Caddy v2.11.4 requires Go >=1.25.1, but Go 1.25.1 is explicitly unsuitable for
this release build: the measured `govulncheck` v1.7.0 scan reported 55
binary-mode findings. The verified release environment is Go 1.26.7 with xcaddy
v0.4.7. The operator must provision that patched/supported toolchain and
`xcaddy` explicitly; this repository does not install tools. The versioned
`build/go.mod` and `build/go.sum` graph is the canonical build input. Any future
Go upgrade requires a fresh audit.

The canonical reproducible build is:

```sh
cd deploy/caddy/build
go build -mod=readonly -trimpath -o caddy
```

The xcaddy command remains a controlled regeneration recipe only:

```sh
xcaddy build v2.11.4 \
  --with github.com/caddyserver/cache-handler@v0.16.0 \
  --with github.com/darkweak/storages/otter/caddy@v0.0.15 \
  --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db \
  --replace github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@v5.3.0 \
  --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.18.7 \
  --replace go.opentelemetry.io/otel=go.opentelemetry.io/otel@v1.44.0 \
  --replace go.opentelemetry.io/otel/metric=go.opentelemetry.io/otel/metric@v1.44.0 \
  --replace go.opentelemetry.io/otel/trace=go.opentelemetry.io/otel/trace@v1.44.0 \
  --replace golang.org/x/net=golang.org/x/net@v0.56.0 \
  --replace golang.org/x/text=golang.org/x/text@v0.39.0 \
  --replace golang.org/x/mod=golang.org/x/mod@v0.40.0 \
  --replace google.golang.org/grpc=google.golang.org/grpc@v1.82.1
```

With `build-info`, confirm the Caddy v2.11.4 module hash, Go 1.26.7, the three
pinned primary modules, and all runtime replacements above. `x/mod` is a build
dependency and may not appear in the runtime binary's build-info; confirm it
from the retained build module instead.
From that retained build-module directory, run govulncheck v1.7.0 or newer in
source and binary modes, plus OSV Scanner v2.5.1 or newer with Go call analysis.
These are release gates, not per-PR CI checks. Any change to `build/go.mod` or
`build/go.sum` requires fresh source, binary, and OSV audits and a new audited
release-binary hash; a CI-built binary is not publishable merely because the
build and smoke pass:

```sh
govulncheck -mode=source ./...
govulncheck -mode=binary ./caddy
osv-scanner scan source --call-analysis=go .
```

No called vulnerability is admissible. These commands are required for each
release audit; a past empty result does not establish that every future scan
will be empty. The measured Go 1.26.7 build without overrides reported 10
binary-mode findings, while the override build's source-mode scan had zero
called vulnerabilities.

The binary scan remains conservative for dormant `cel-go` GO-2026-6094 and
`x/crypto` OpenPGP GO-2026-5932. Such a finding may only be resolved by
corroborating the source scan with the absence of the affected functionality
and configuration, and documenting that reasoning explicitly; it must never be
silently ignored.
`cel-go@v0.30.0` is not an available override because it does not compile with
Caddy 2.11.4 (`InterpretableV2`).

## Installation and validation

Install the binary and config atomically, using a temporary file in the same
filesystem and a controlled rename. Keep the previous pair for rollback. Do
not invent a systemd unit from this template: service ownership, restart policy,
and journald routing are operator-managed.

```sh
./caddy version
./caddy build-info
./caddy list-modules | grep -E 'cache|otter|rate_limit'
./caddy adapt --config deploy/caddy/Caddyfile --adapter caddyfile --validate
./caddy validate --config deploy/caddy/Caddyfile --adapter caddyfile
python3 deploy/caddy/smoke.py ./caddy
```

With `admin off`, there is no reload API. Stop and start the selected service
for a configuration change. Rate-limit and cache state are in memory and are
lost on restart; do not schedule daily restarts. Route Caddy's error logs to
journald and set operator-selected journald retention. There is no access log.

The Caddy listener is HTTP/1-only and host-agnostic, accepts onion and loopback
Host headers, and sends all routes to Axum on `127.0.0.1:3001`. This is safe
only because `bind 127.0.0.1` is mandatory. Only the exact `GET
/attempts` route is edge-rate-limited and cached. Its global static buckets are
20 requests/1s and 300 requests/1m. Cache state is local Otter only, TTL 30s,
strict, GET-only, using a pool of 16 internal Otter units/entries. This leaves
margin above the observed minimum of 10 for the single normalized
representation; it does not limit the cache to 16 user snapshots. Bodies remain
bounded to 8 MiB; the key is hashed, hidden, and independent of Host, query,
body, and scheme. No purge/API, metrics, stale, CDN, persistent, or distributed
storage is configured.

Before the cache decides whether to store a response, the `intercept` handler
forces upstream `4xx` and `5xx` responses to `Cache-Control: no-store` while
leaving their status and body unchanged.

The HTTP contract is deliberately standard: **429 is exclusively targeted
Axum lockout; 503 is all shared pressure**. The plugin emits 429 internally for
its global bucket, and `handle_errors 429` adapts that local error to JSON 503
while preserving `Retry-After`; it never intercepts an upstream Axum 429. Do
not introduce 418, 423, or other custom statuses: clients classify by standard
status only. Nginx `limit_req` emits 503 natively by default, so this adapter
keeps the deployment contracts aligned. No Caddy compression is enabled; the
smoke preserves and verifies Axum's deterministic precompressed gzip response.

Caddy has no native connection-count cap. Its 10-second read-header timeout and
Tor defenses reduce exposure, but operators must set and monitor a file-descriptor
and process budget appropriate for the host. Do not substitute a supposedly
portable nftables rule; connection budgeting is host and deployment specific.

## Required smoke protocol

Before switching from nginx, exercise the onion endpoint through Caddy and
record the results:

1. Run `python3 deploy/caddy/smoke.py /path/to/caddy`. It validates the config,
   required modules and build-info pins, then verifies deterministic gzip bytes,
   cache miss/hit through `Cache-Status`, stable `ETag`, conditional `304`
   without a second backend call, and host/query normalization with a local
   backend.
2. Exercise non-cache `store`, `fetch`, `trash`, and `info` requests; they must
   reach Axum without cache state or edge rate limiting.
3. Confirm an Axum-generated `429` remains `429` with its `Retry-After`.
4. Exhaust the edge `/attempts` bucket and confirm its internal `429` is a JSON
   `503` retaining `Retry-After`.
5. Confirm upstream `4xx` and `5xx` responses are not cached.

This is not perfect nginx equivalence: unlike the nginx template, this
Caddyfile has no explicit 100-connection limit and no 512 KiB/s throttle.
Global `/attempts` limits, the bounded cache, Axum buckets, and Tor defenses
remain necessary. Caddy is admissible only after its build, validation, and
these smokes succeed.
