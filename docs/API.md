# What this server adds to the protocol

To write a client, use [`recoverbull-client-dart`](https://github.com/SatoshiPortal/recoverbull-client-dart), the library the Bull app uses: it derives the keys, encrypts the backup, and talks to this server. The protocol itself, including the endpoints, `secret_id`, the attempt budget, `attempt_status` and the `/attempts` snapshot, is defined by the [RecoverBull specification](https://github.com/SatoshiPortal/recoverbull-whitepaper/blob/master/SPECIFICATION.md).

This page lists only what this server pins or adds beyond the specification. The security model behind these choices is in [SECURITY.md](../SECURITY.md).

## Endpoints and limits

| Route | Body | Limits |
|---|---|---|
| `POST /store` | `identifier`, `authentication_key`, `encrypted_secret` | `201` on success, body `null` |
| `POST /fetch` | `identifier`, `authentication_key` | `200` with the secret and `attempt_status` |
| `POST /trash` | `identifier`, `authentication_key` | `202` with `attempt_status`; the row is gone |
| `GET /info` | — | canary and the server's limits; never rate-limited |
| `GET /attempts` | — | the public snapshot, always gzip, with `ETag` |

- `identifier` and `authentication_key` are 64 lowercase hex characters; `encrypted_secret` is Base64, at most `secret_max_length` characters (128 by default, up to 832).
- Request bodies are limited to 1024 bytes; sensitive routes answer within a 30-second timeout.
- `GET /info` returns `canary`, `secret_max_length`, `rate_limit_cooldown` (minutes), `rate_limit_max_attempts` (and its legacy alias `rate_limit_max_failed_attempts`), `max_attempt_identifiers` (the snapshot's capacity, for a fill ratio) and `attempts_collection_started_at` (hour-truncated, the same value as the snapshot). The canary comes from the server's `.env`, re-read at most every ten minutes; `Cache-Control` advertises what remains of that freshness.

## Status codes and `Retry-After`

Clients classify **by HTTP status only**. Error bodies are JSON with an `error` field whose text is for humans and may change.

| Status | Meaning | Client treatment |
|---|---|---|
| `400` | Invalid request data. | Fix the request. |
| `401` | Invalid credentials. | An authentication failure. |
| `429` | The identifier's attempt budget is spent. The only security alarm. | Surface the lockout; honor `Retry-After`. |
| `503` | Pressure or unavailability: a global bucket, a full identifier map, a busy database, storage that stopped accepting writes, or the 30-second timeout. | Back off per `Retry-After`, then retry. |
| `500` | Server failure. | Report; retrying will not help. |

Every `429` and `503` carries `Retry-After` in seconds:

- from a global bucket (`/store`, lookups, `/attempts`): the server's estimate of its next token, at least 1;
- busy database, full identifier map, pending duplicate, request timeout: an advisory `1`;
- **storage pressure**: while the data volume has less free space than the server's reserve (64 MB by default), and once a `/store` has failed because storage could not be written, `/store` answers `503` with `Retry-After: 60` whether or not the `secret_id` exists; after a failure this lasts until an operator restarts the server. `/fetch` and `/trash` keep working.

Framework rejections such as `404`, `405`, `413` and `415` may not be JSON.

## Rules a client must follow

- **`/store` is idempotent and never overwrites.** A store for an existing `secret_id` answers `201` like a fresh one, so the response cannot reveal existence. The **first** writer owns the row: generate a fresh random `identifier` (and salt) for every store, never re-store under an identifier that has already left the device, and confirm a store with one `/fetch` and a ciphertext comparison before declaring the backup complete.
- **Retry a `/trash` at most once.** A successful `/trash` deletes the row and forgets the `secret_id` that authenticated it. If the `202` is lost and the request is repeated, the repeat is a brand-new `secret_id` that finds no row: `401`, one slot spent, one `failed_attempts`. Treat a `401` after a `/trash` whose answer never arrived as "possibly already deleted".
- **Detection is the client's job.** The server cannot notify anyone. `attempt_status` on a successful fetch is the freshest signal and costs nothing; polling `/attempts` (jittered, through Tor, honoring `ETag` and freshness, never faster than the snapshot TTL) is the proactive one. Compare your `id_hash`, and compare the number of entries with `max_attempt_identifiers`: a full map refuses new identifiers with `503`, and a victim then has no entry of its own. A `429` or activity you did not cause is an alarm; `503` is pressure. Telemetry is advisory: warn, never act automatically, since a compromised server can lie.
- **A failing `/attempts` means "unknown", not "quiet".** Track the last successful poll. `/info` is never rate-limited and makes a cheap liveness check:

| `/info` | `/attempts` | Meaning |
|---|---|---|
| OK | `200` / `304` | Verified: compare your `id_hash`, the counters and the fill ratio. |
| OK | `503` | Pressure: back off per `Retry-After`; the state stays unverified. |
| OK | `500` | The telemetry subsystem is failing; recovery routes are unaffected. |
| fails | any | The server or the network is unreachable. |

## Timestamp precision

The more a caller must already know, the more precise the timestamps it gets:

- successful `/fetch` and `/trash` (`attempt_status`): exact seconds, since anyone holding the `identifier` can manufacture a hit through `/store`;
- `401`: `requested_at` is the caller's own request time;
- `429`: `requested_at` is the exact time of the last admitted attempt, which may be the victim's; accepted, because the caller needs it to compute its retry time and already gets hour precision from the snapshot;
- `/attempts`: hour-truncated, because the audience is everyone.

## Response floor and request IDs

`POST /store`, `/fetch` and `/trash` never answer in less than 500 ms of server time, measured from routing (validation and body rejections included), so timing cannot separate a hit from a miss. Longer processing is not hidden, and network or Tor delay is not equalized.

Every response carries a server-generated `X-Request-ID`; a client-provided one is dropped. The value is opaque, not a counter.

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

# Attempts (gzip-compressed; identifiers are SHA-256 hashed)
curl --compressed -X GET http://127.0.0.1:3000/attempts

# Attempts, conditional revalidation (304 when unchanged)
curl --compressed -X GET http://127.0.0.1:3000/attempts -H 'If-None-Match: "<etag>"'
```
