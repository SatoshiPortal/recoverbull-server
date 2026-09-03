# Security

## Authority and evidence

The documentation hierarchy is explicit. The [RecoverBull whitepaper repository](https://github.com/SatoshiPortal/recoverbull-whitepaper) is authoritative for the protocol, its threats, and its intent; its normative `SPECIFICATION.md` is published there (RecoverBull Reference Profile 1). The README is authoritative for the client interface and the operator runbook. This document is authoritative for implementation invariants and the security-review guide. The code and tests are authoritative for implemented behavior and executable proof. If protocol documents conflict, the whitepaper prevails. Documentation, including `cargo doc`, does not become proof merely because it compiles.

## Reviewer reading map

Start with `.env.example`, then read the implementation in the order below.
Configuration is mandatory with no code defaults for the security-critical
values, so most of `cargo test` fails on a bare `SERVER_ADDRESS must be set`
panic when no `.env` is present (it is gitignored). Run `cp .env.example .env` first; the file mirrors the `env:`
block of the `test` job in `.github/workflows/ci.yml`.

1. `src/main.rs` — process lifecycle and shutdown; `src/app.rs` — `AppState` ownership and construction; `src/config.rs` — validated configuration, the capacity/memory budget model, and canary state.
2. `src/router.rs` — route, Axum middleware adapter, body-limit, timeout, and response-floor boundaries; then `src/http/contract.rs`, `src/http/error.rs`, and `src/handlers/store.rs`, `src/handlers/fetch.rs`, `src/handlers/info.rs`, and `src/handlers/attempts.rs` for the HTTP boundary and handlers.
3. `src/recovery/identifiers.rs` — identifier and candidate derivation; `src/recovery/service.rs` — recovery orchestration.
4. `src/attempts/ledger.rs` — admission and finalization FSM; `src/attempts/snapshot.rs` — deterministic public snapshot; `src/attempts/maintenance.rs` — expiry and global wipe.
5. `src/storage/sqlite.rs` — Diesel/SQLite transactions and connection checks; `src/observability/diagnostic.rs` and `src/observability/counters.rs` — privacy-safe diagnostics and aggregate counters.
6. Read tests by category: `src/tests/test_contract.rs`, `test_concurrency.rs`, `test_privacy.rs`, `test_http_boundary.rs`, `test_config.rs`, `test_rate_limit.rs`, `test_distinct_candidates.rs`, `test_attempts.rs`, `test_secure_delete.rs`, `test_db_errors.rs`, `test_logging.rs`, `test_fetch.rs`, `test_store.rs`, `test_trash.rs`, `test_info.rs`, `test_timing.rs`, `test_migrations.rs`, `test_adversarial.rs`, `test_audit_claims.rs`, and `test_server.rs`.

## Ownership and dependency map

- HTTP ownership is limited to Axum: `router.rs`, `http/*`, and `handlers/*` translate requests and responses; `router.rs` owns the request-diagnostics adapter. Domain modules, including `observability/diagnostic.rs` and `attempts/snapshot.rs`, do not depend on Axum or bytes.
- Storage ownership is limited to Diesel/SQLite: `storage/sqlite.rs` owns connections, migrations' runtime interaction, WAL/secure-delete checks, and transactions. HTTP and recovery do not issue Diesel queries directly.
- Recovery orchestration is `recovery/{identifiers,service}.rs`; it owns protocol coordination without Axum or Diesel dependencies.
- Attempts are owned by `attempts/{ledger,snapshot,maintenance}.rs`: the ledger owns the candidate FSM, the snapshot owns cache serialization, and maintenance owns expiry and wipe.
- Observability is owned by `observability/{diagnostic,counters}.rs`; it receives static categories and aggregate values, not secrets or request metadata.
- `AppState` in `app.rs` privately owns the shared service, attempts, information, and observability components; production code receives only narrow capability methods, while component seams are explicit and test-only.
- `src/schema.rs` is the Diesel-generated root imposed by `diesel.toml`; do not relocate it while preserving the configured schema path.

## Request diagnostics privacy

The five-minute `info` counter summary includes diagnostic log emission and
suppression totals. There are two quota classes, and they differ in whether the
default filter lets them through. **Detail** diagnostics (`success`,
`client_error`, `overload`) emit at DEBUG and are therefore off under the
default `RUST_LOG=info`; enable them temporarily with
`RUST_LOG=info,request_diagnostics=debug`, and do not leave debug mode on
during normal operation. **Server-error** diagnostics emit at WARN and are
consequently *on* by default, which is intended — a `500` should reach the
operator's log without reconfiguration.

Because the server-error class is live by default, its budget must not be
spendable by ordinary traffic. Each class allows a burst of 10 events and
refills at 1 event per second, and **the category and the quota class are
derived from a single table** (`observability::diagnostic::classify`) so they
cannot drift apart. That table is the only thing deciding what reaches the WARN
budget, and it must stay wrong-proof in both directions:

- `3xx` is `success`, so the `304` of a conditional `GET /attempts` — the
  caching path the README tells clients to use — raises no false alarm and
  spends no server-error token.
- `429`/`503` stay in the detail class **even though `503 >= 500`**.
  Overload responses are the most frequent failures under load; promoting them
  to WARN would starve the budget exactly as effectively as the `304` defect
  did. The `408` arm is kept in that class although the router no longer
  emits it: the request timeout answers `503`.

Every status this service can return has an explicit arm, so the
unexpected-status fallback is unreachable from a client and can keep
server-error visibility for a genuine anomaly. Guarded by
`test_only_genuine_server_errors_spend_the_warn_budget` and
`test_not_modified_is_not_a_server_error`.

Request IDs are generated by the server and returned as `X-Request-ID`;
client-supplied values are discarded.

Request events contain only the generated request ID, static route and method
enums, numeric status, static status category, and static duration bucket.
Categories are `success` (`2xx`/`3xx`), `client_error` (`4xx`), `overload`
(`429`/`503`, plus a `408` arm the router no longer produces), and
`server_error` (`5xx` and any unexpected status);
duration buckets are `lt500ms`, `500ms_1s`, `1s_5s`, and `gte5s`.
They never contain raw URIs or query strings, headers, bodies, remote IPs,
database paths, identifiers, hashes, tags, keys, ciphertexts, canary values,
or raw errors. Lifecycle messages remain rare and aggregate-only.

This document consolidates what security reviewers need to know about this
server so that each review does not start from zero: the threat model, the
risks that are **accepted by design** (do not re-report them), the
**invariants** the code must keep (each guarded by tests), the traps already
stepped into, and a checklist for future reviews.

Application log guarantees do not cover nginx or Caddy, journald, or Tor logs unless the
README runbook is applied: those logs may contain request metadata and require
strict levels, private permissions, and short retention. Five-minute global
counters retain coarse activity metadata and require the same access controls.

For deployment guardrails (single-instance, the exclusive nginx/Caddy choice,
and Tor onion), see the
README and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — they are part of the
security model, not optional hardening. Tor and single-instance operation are
required by the model but are not enforced by the binary; a public bind only
produces a warning.

## Clocks: which one decides what

Two clocks exist in this process, and confusing them was a real defect. The
distinction is worth stating once, because every future change touching expiry
or timestamps depends on it.

**`CLOCK_REALTIME` (wall clock)** — `chrono::Utc::now()`. It is the calendar
time a human reads, and it is **settable**: `clock_settime`, an administrator,
a VM resume, or an NTP daemon correcting a large drift can move it *backwards
or forwards by an arbitrary amount, instantly*. That is a step, not a drift.

**`CLOCK_MONOTONIC` (monotonic clock)** — `tokio::time::Instant`, which wraps
`std::time::Instant`. It counts elapsed time since an arbitrary origin (boot).
It **cannot be stepped**: NTP may only *slew* it, speeding it up or slowing it
down within a bounded rate, so it never jumps. Its value is meaningless
outside this process — you cannot display it, serialize it, or compare it
across restarts. On Linux it also does **not** advance while the system is
suspended (that would be `CLOCK_BOOTTIME`).

The rule this codebase follows:

> **Every decision about elapsed time uses the monotonic clock. Every value
> published to a client uses the wall clock.**

| Value | Clock | Why |
|---|---|---|
| `RateLimitInfo::last_candidate_instant` | monotonic | The single input to the expiry decision (`attempts::ledger::is_expired`). |
| Sweeper and global-wipe timers | monotonic | `tokio::time::interval_at`; same clock family as the decision they trigger. |
| Snapshot TTL (`AttemptsSnapshotCache::created_at`) | monotonic | Cache freshness is an elapsed-time decision. |
| Token buckets (`rate_limit`, `LogQuota`) | monotonic | Refill is elapsed time. |
| `window_started_at` | wall clock | It is the **generation token** compared in `finalize`/`refund`; a detached worker must not be able to mutate a replacement window. It is also published. |
| `last_candidate_at`, `resets_at`, `previous_attempt_at`, `requested_at` | wall clock | Published to clients, which need an absolute value they can display and schedule against. |
| `secret.created_at` | wall clock | Persisted and returned in the lookup response. |

Two consequences follow, both accepted and documented below as risks #14-15.
A forward wall-clock step leaves the budget correct while the published
`resets_at` becomes temporarily wrong — chosen deliberately, because a wrong
retry hint costs a client one early request whereas a wrong expiry decision
costs the victim its entire brute-force budget. And because the monotonic
clock pauses during system suspend, entries do not expire while the process is
suspended, which again keeps budgets rather than resetting them.

**If you add a timeout, a cooldown, a TTL, or a refill: use the monotonic
clock.** If you add a field a client will read: use the wall clock, and do not
let any decision depend on it.

## Threat model (summary)

The server stores `encrypted_secret` values keyed by
`secret_id = SHA-256(identifier_hex + authentication_key_hex)`. It never sees
the password, the encryption key, or the cleartext secret. Because the user
when password/PIN entropy is low, the **only** server-side
control against password brute-force is the per-identifier distinct-candidate budget
(3 attempts per cooldown in the documented `.env` and CI; the variable is
mandatory — there is no code default). Everything else
— anonymity, no accounts, Tor-only transport, daily in-memory wipe — exists
to keep that control meaningful and the server unlinkable to users.

Attacker capabilities considered: holding a victim's Backup File
(`identifier`, `salt`, encrypted mnemonic ciphertext, and metadata); a malicious or compromised Key
Server; a database leak; a malicious cloud storage provider; collusion or
legal compulsion of both providers (see the whitepaper for the full list).

## Accepted risks and design tensions (do not re-report)

## Deletion and SQLite/WAL retention

`/trash` transactionally removes the active row. The application explicitly
forces SQLite `secure_delete=ON` on every connection, covering pages rewritten
by the deletion; it does not depend on a Debian compile flag. In WAL mode, the
main database file or a copy may retain pre-checkpoint state. Backups,
Litestream replicas, and historical snapshots are not purged. A coherent
backup must include both the database and WAL, or use SQLite's backup API.
Operators are responsible for retention of those copies.

1. **Targeted lockout (audit F2).** An attacker holding the Backup File can
   submit three distinct candidates and consume the victim's candidate budget,
   delaying or preventing recovery. The bucket is always `sha256(identifier)`
   and is checked before membership or credentials are verified: the server
   cannot distinguish owner from attacker. This remains an accepted risk.
   The distinct-candidate limiter improves availability and signal for replay
   traffic; it is not a vulnerability correction. Mitigation is *detection*
   (`attempt_status`, `/attempts`, unexpected `429`), not prevention.
   **Do not "fix" this by resetting the counter on a successful lookup**:
   `/store` is public, so an attacker can plant a matching row and "succeed"
   to erase the attack signal. That was deliberately reversed in `ee9f29a`.
   Roadmap: escalating backoff, client proof-of-work, multi-server storage.
2. **A successful lookup never proves ownership.** Anyone can plant a row
   for a guessed key through `/store` and then "successfully" fetch it.
   Distinct candidate counters therefore include database hits and never reset
   on success. A committed replay is free only before saturation, increments
   `total_requests`, and does not extend cooldown.
3. **Telemetry is readable by identifier holders.** `/attempts` publishes
   `SHA-256(identifier)` only. Entries are indistinguishable: real usage,
   another device, and attacker probes produce the same entry shape. This
   relies on clients generating identifiers with 256 bits of entropy — a
   low-entropy identifier would make its hash brute-forceable.
   Proactive polling is not a Profile 1 recovery prerequisite, but it is part
   of the intended Bull Mobile detection rollout. Bull Mobile does not
   currently perform it, so deploying the server before the corresponding
   wallet release creates a temporary detection gap: rate limiting still
   applies, but there is no early warning before recovery. The wallet release
   should poll regularly in the foreground and use best-effort background
   scheduling where the platform permits it, with jitter, `ETag`, snapshot
   freshness, Tor, and the shared proxy cache. The global request does not
   disclose which identifier the client checks because matching remains local;
   its cadence nevertheless exposes additional wallet-online timing at the
   transport boundary, and the public snapshot exposes coarse activity to
   anyone already holding an identifier. A private per-identifier endpoint or
   push notification would be worse because it would reveal the target or
   require stable device/account state. Until the wallet rollout completes,
   only `attempt_status` on a lookup and an eventual `429` remain observable.
4. **Timestamp precision follows a knowledge gradient.** Exact timestamps go
   to identifier holders (direct responses), hour-truncated to everyone
   (public snapshot). An exact `requested_at` in a `429` can be the victim's
   last admitted attempt: accepted, and needed by clients to compute retry
   time.
5. **Service-state oracle via distinct `503` bodies.** Lookup-bucket
   exhaustion, map-full, and database-busy return different messages, so an
   attacker (and an operator) can tell them apart. The documented client
   contract is to classify by HTTP status only, never to match on the
   message (see README and `src/tests/test_contract.rs`).
6. **Telemetry suppression.** Flooding `/attempts` or churning the snapshot
   ETag can delay clients' snapshot reads. `attempt_status` on a successful
   fetch is the fallback signal, unaffected by that flood.
7. **Map filling.** New identifiers get `503` when the map is full
   (fail-closed); active entries are never evicted by new identifiers, so a
   victim already holding an entry keeps its budget and its signal
   (`test_full_map_does_not_evict_protected_identifier`). The denial is
   structural: the bucket is `sha256(identifier)` and is checked before any
   proof of knowledge, so the server cannot tell an owner from an attacker.
   **The earlier justification — "the attack and the alarm are the same
   event: probing creates the victim's warning entry" — is wrong for a
   flood**, and was corrected here after being disproved end to end against
   a running server. An attacker filling the map with identifiers *of its
   own* never touches the victim's identifier: a victim with no prior entry
   receives `503` and gets **no entry of its own to notice**
   (`test_map_filling_denies_a_victim_without_creating_its_warning_entry`).
   The only signal in that case is the aggregate one — the ratio of
   `/attempts` entries to the `max_attempt_identifiers` published by
   `/info`, which saturates at 100% — so clients must treat that ratio as a
   first-order alarm and not wait to recognize their own `id_hash`.
   Attacker cost at the default capacity, measured: 100,000 admitted
   `/fetch` requests, about 50 MB of traffic, and — because the map is wiped
   every 24 hours — **1.16 requests per second sustained** to keep it full,
   which is 4.3x under the default 5/s lookup-bucket refill; filling from
   empty at that ceiling takes about 5.6 hours. This is cheap, and it is
   accepted only because the alternative (evicting active entries) would
   sacrifice a locked-out victim. Roadmap: client proof-of-work,
   multi-server storage.
 8. **Offline PIN brute-force with a database leak.** A leak of
    `encrypted_secret` plus the Backup File's `salt` reduces security to the
    user's password/PIN entropy. Cloud storage plus the database permits
    offline validation; Argon2id slows guesses but does not create entropy.
    Inherent to the protocol; client-side key rotation is the mitigation.
9. **Server trust.** Telemetry is advisory: a compromised server can
   fabricate or suppress counters, and the warrant canary has the classic
   limits (an operator under compulsion may keep serving it). Clients must
   warn, never act automatically.
 10. **Global buckets can deny service to everyone.** Behind an onion service
     per-IP limiting is useless, so buckets are global; an attacker can
     exhaust them (`503` for all). Bounded by the selected reverse proxy and
     Tor defenses at the deployment layer. Caddy adapts its plugin's internal
     global-bucket `429` to this standard `503`; it does not adapt an Axum
     lockout `429`. Caddy's lack of a native connection-count cap is accepted
     only with its 10-second header timeout, Tor defenses, and an
     operator-managed FD/process budget.
11. **Temporary behavioral state.** The server retains up to the configured
    maximum of derived CandidateTags (`secret_id/key_id`) per bucket in memory.
    A CandidateTag is never raw authentication or password material, and is
    never logged or snapshotted; the complete map is wiped every 24 hours from
    map startup, with the attempt budget reset at the boundary. The cooldown
    sweep removes shorter-lived entries earlier. This is a privacy trade-off:
     non-exposed temporary state is larger than the former identifier-only
     state.
12. **Operational trade-offs.** Strict single-instance operation is required:
     the internal wipe is 24 hours and no daily restart is needed. A restart
     resets budget and collection, so it must be exceptional and non-overlapping.
     A hash protects a public observer from learning an identifier, but a Backup
     File holder already knows that identifier; `/attempts` reveals only activity
     and counters to that holder. This detection trade-off is accepted. Caches or
     archives may be used, but must not expose the Backup File. A `429` or an
     unexpected snapshot entry is an alarm: rotate/transfer while the wallet is
     accessible, rotate/transfer immediately; otherwise recovery availability
     depends on a previously exported Backup Key or a second independent server.
13. **Minimum response floor is not exact timing.** `/store`, `/fetch`, and
    `/trash` wait until at least the configured server-side floor when their
    processing is faster (500 ms in production). Body upload, network and
    proxy/Tor transfer time are not equalized; processing that already exceeds
    the floor remains observable. The wait is outside database permits and
     mutexes, but can increase concurrent connections during a flood. Token
     buckets plus the selected reverse proxy and Tor connection, request, and
     DoS defenses bound that amplification.
14. **The capacity memory model is a conservative estimate, not a guarantee.**
    `validate_capacity` refuses an over-budget `RATE_LIMIT_MAX_IDENTIFIERS` at
    startup, sizing against the **lower** of `RATE_LIMIT_MEMORY_BUDGET_MB` and
    the memory limit the kernel actually enforces on the process (cgroup v2
    `memory.max` walked up the hierarchy, or v1
    `memory.limit_in_bytes`). Detection is best-effort: with no cgroup, an
    unreadable file, or an unlimited value, only the declared budget applies,
    so a deployment without a cgroup limit is validated against a declaration
    alone. The per-entry constants were measured on one host, one allocator
    (glibc) and one dependency set, rounded up; a different allocator, target,
    or future `hashbrown`/`chrono` layout can raise the real cost, so the check
    can pass on a host where the cgroup still kills the process. The 64 MiB
    process reserve is a flat allowance covering the base process, SQLite
    connections and page cache, and worker stacks, and it is not itself
    enforced. Operators must still re-measure peak RSS (`VmHWM`, see
    [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)) after changing
    `RATE_LIMIT_MAX_ATTEMPTS`, which dominates per-entry cost. The check
    removes a guard rail that was calibrated an order of magnitude wrong; it
    does not remove the need to measure.
15. **Expiry and published timestamps use different clocks, by design.** The
    expiry decision is monotonic so a settable `CLOCK_REALTIME` cannot reset
    per-identifier budgets, while `resets_at`, `window_started_at`, and
    `previous_attempt_at` stay wall-clock because clients need absolute values
    they can display and because `window_started_at` is the generation token
    for detached finalization. After a clock step the two disagree: the budget
    is correctly preserved, but a client computing its retry time from the
    published `resets_at` can be misled until the entry expires. The
    conservative direction was chosen deliberately — a wrong retry hint costs
    a client one early request, whereas a wrong expiry decision costs the
    victim its entire brute-force budget. Relatedly, monotonic time does not
    advance while the process is stopped or suspended, so entries do not
    expire during suspension; that also keeps budgets rather than resetting
    them, and matches the existing behaviour of the 24-hour wipe timer.

## Invariants (each guarded by tests)

The table below is the minimal primary-guard index for the security invariants; it is not an exhaustive index of every test. Supplemental tests are classified here by module so an auditor can locate evidence without listing all 194 tests individually.

### Additional evidence by test module

| Registered test module | Supplemental evidence area |
|---|---|
| `test_adversarial` | malformed input and hostile sequencing |
| `test_attempts` | snapshot contract and telemetry values |
| `test_audit_claims` | historical audit findings and claim-level regressions |
| `test_concurrency` | concurrent admission and storage operations |
| `test_config` | fail-closed configuration validation |
| `test_contract` | HTTP status/body contracts |
| `test_db_errors` | database failure classification and refunds |
| `test_distinct_candidates` | candidate capacity and shared fetch/trash budget |
| `test_fetch` | fetch response mapping |
| `test_http_boundary` | routing, extraction, limits, and headers |
| `test_info` | live canary and operational metadata |
| `test_logging` | request IDs, quotas, and sensitive-value exclusion |
| `test_migrations` | schema setup and SQLite capability checks |
| `test_privacy` | snapshot and response privacy properties |
| `test_rate_limit` | bucket accounting, expiry, and wipe |
| `test_secure_delete` | SQLite secure deletion and WAL behavior |
| `test_server` | shared isolated server and database fixtures |
| `test_store` | store validation and idempotency |
| `test_timing` | sensitive POST response floor |
| `test_trash` | atomic destructive lookup behavior |

### Candidate admission and transition table

Admission is ordered and shared by `/fetch` and `/trash`: expiry and capacity are checked first, `total_requests` is then updated for an existing entry, saturation is checked before membership, and only then is candidate membership inspected. A full map rejects a new identifier fail-closed. Saturation rejects every candidate, including known candidates, before database work. A `Pending` duplicate returns `503` without another reservation; a `Committed` replay is free before saturation. A new candidate creates `Pending` and reserves one slot.

| Current state / admission | Result | Final state and accounting |
|---|---|---|
| Expired entry | Start a new window | Old entry is removed before admission. |
| Map at capacity, new identifier | `503` | No entry and no per-identifier counter. |
| `candidate_count >= max` | `429` | No membership or database lookup; `Retry-After` applies. |
| `Pending` duplicate | `503` | Existing reservation remains; no second reservation. |
| `Committed` replay | Continue lookup | Remains `Committed`; `total_requests` increments, with no new attempt or cooldown extension. |
| New candidate | Continue lookup | `Pending` owns one reserved slot. |
| Admitted hit or miss | Finalize | `Committed`; a miss increments `failed_attempts` once and a hit does not reset the budget. |
| Error or refund before commit | Refund/remove | `Pending` is removed and refunded once. |

External statuses are `400` invalid data, `401` invalid credentials, `429` targeted lockout, `503` pressure/unavailability, and `500` internal failure. `429` and `503` carry `Retry-After`; clients classify by status, not error text. `total_attempts` counts distinct admitted candidates, `failed_attempts` finalized misses, and `total_requests` requests attached to an active entry.

### Cancellation ownership

`ReservationGuard` is armed before transfer. Timeout, cancellation, or a dropped handler before transfer refunds exactly once. The database lease and permit are moved into the detached task/`spawn_blocking` work; the handler consumes the guard with `transfer` only after that transfer. A dropped handler therefore cannot abandon finalization, trash, or counters. An outer task failure performs a generation-specific refund and cannot alter a replacement window.

### Blocking bounds and lock order

SQLite admission waits at most one second for its semaphore; failure returns `503` without consuming an attempt. The permit remains owned through the blocking operation and is released on return. The canary reader uses one dedicated permit. Snapshot generation projects the map to plain counter data under lock, then sorts, serializes, and gzips outside it; it never copies a CandidateTag set, which keeps the ledger lock that gates `/fetch` and `/trash` admission short. No HTTP or network operation runs under a domain lock.

The global wipe's simultaneous lock order is exactly `snapshot cache -> ledger map -> collection timestamp`, and it advances the collection epoch while holding the cache lock. Normal snapshot generation does not hold these three simultaneously: it captures the epoch, projects ledger data under its lock, processes it afterward, and publishes under the cache lock only if the epoch is unchanged.

Breaking any of these reintroduces a fixed vulnerability. If you change the
code, keep the invariant — and run the guarding test.

| Invariant | Owner | Why | Guarding test(s) |
|---|---|---|---|
| `/store` is idempotent: fresh and duplicate return the same `201`, never overwrite | `RecoveryService::store`, `SqliteOperation::store` | F1: duplicate `403` was an unthrottled `authentication_key` oracle | `test_audit_f1_store_gives_no_existence_signal`, `test_duplicate_store_is_indistinguishable_and_does_not_overwrite`, `test_concurrent_identical_store_is_idempotent` |
| Rate-limit check-and-increment is atomic under one lock | `attempts::ledger::admit` | Concurrent requests otherwise overshoot the budget | `test_rate_limit_holds_under_concurrency` |
| Every distinct candidate consumes budget, hits and misses included; committed replays are free only before saturation and never extend cooldown | `attempts::ledger::admit` | Planted rows must not bypass the budget, while identical replays improve availability | `test_replaying_one_valid_candidate_does_not_consume_more_attempts`, `test_replaying_one_invalid_candidate_does_not_consume_more_attempts`, `test_replaying_one_candidate_does_not_slide_resets_at`, `test_audit_f1_planted_rows_cannot_reset_fetch_rate_limit` |
| `candidate_count >= max` returns `429` before membership/DB for known, Pending, and Committed candidates | `attempts::ledger::admit` | Saturation must not become an authentication oracle | `test_known_candidate_is_rejected_when_distinct_candidate_capacity_is_full`, `test_distinct_planted_candidates_consume_capacity`, `test_pending_distinct_candidates_consume_the_attempt_budget` |
| Pending reserves a slot immediately; duplicate Pending returns `503` without a second reservation; `/fetch` and `/trash` share the set | `AttemptsLedgerState::admit`, `RecoveryService::lookup` | Concurrent work must not oversubscribe or manufacture a duplicate candidate | `test_pending_duplicate_trash_is_rejected_without_a_second_reservation`, `test_fetch_and_trash_share_one_candidate_attempt` |
| Detached finalization is generation-safe; DB error/cancellation before DB removes Pending; a miss increments failed once; trash races do not create false failures | `attempts::ledger::finalize`, `recovery::service` | Late completion and cancellation must not corrupt a replacement window or telemetry | `test_old_trash_completion_cannot_update_a_replaced_rate_limit_window`, `test_database_error_returns_500_without_consuming_attempts`, `test_committed_trash_race_returns_accepted_and_unauthorized_without_failure`, `test_concurrent_trash_hit_does_not_count_the_losing_miss_as_a_guess` |
| A Pending reservation is removed exactly once on cancellation before SQLite or on internal error; after transfer to SQLite, the detached task owns finalization | `ReservationGuard`, `RecoveryService::{run_lookup,store}`, `SqliteOperation` | Budget integrity under cancellation and lost HTTP responses | `test_cancelled_request_does_not_consume_an_attempt`, `test_cancelled_trash_after_sqlite_start_keeps_attempt_reserved`, `test_concurrent_cancellation_refunds_every_reservation`, `test_deferred_refund_runs_when_drop_finds_the_lock_contended`, `test_database_error_returns_500_without_consuming_attempts` |
| Pending cleanup and detached finalization are candidate- and generation-specific; candidate removal plus empty-entry removal is atomic under one map lock | `attempts::ledger::finalize` | A stale completion must never mutate or delete a reservation in a replacement window or a newer request | `test_old_trash_completion_cannot_update_a_replaced_rate_limit_window`, `test_pending_duplicate_trash_is_rejected_without_a_second_reservation` |
| `id_hash` = SHA-256 over raw identifier bytes; `secret_id` = SHA-256 over the two hex *strings* | `recovery::identifiers` | Clients must match their entry; mixing algorithms silently breaks detection | `test_attempts_id_hash_matches_shared_client_vector`, `test_secret_id_and_id_hash_are_distinct_algorithms` |
| Logs and error responses carry counts and static strings only — never identifiers, keys, or bodies | `observability::{diagnostic,counters}`, `http::{contract,error}` | Anonymity | `test_error_responses_leak_no_secret_material`, `test_snapshot_never_contains_secret_material`, `test_500_does_not_leak_internals` |
| Hex inputs are lowercased before validation and hashing | `recovery::identifiers` | Case variants would split budgets and records | `test_audit_f12_hex_case_is_canonicalized` |
| Cheap validation before expensive: length before base64 decode, 1 kB body limit | `RecoveryService::store`, `router` | DoS via decode/parse cost | `test_store_checks_length_before_base64`, `test_store_rejects_oversized_json_before_deserialization` |
| Snapshot is deterministic (sorted entries, gzip `mtime=0`), hour-truncated, single-flight, initial telemetry contract version 1; counts distinct candidates and all requests but exposes no CandidateTags | `attempts::snapshot` | Stable ETag; precision gradient; bounded build cost and privacy | `test_attempts_snapshot_rebuild_is_deterministic`, `test_attempts_publish_hashed_identifier_with_counters`, `test_attempts_snapshot_at_full_map_scale`, `test_concurrent_attempts_polls_agree_on_etag`, `test_snapshot_never_contains_secret_material` |
| Global wipe clears identifiers and CandidateTags every 24 hours, resets the budget timestamp, and invalidates pre-wipe snapshots; the first wipe is delayed until the period elapses | `attempts::maintenance` | No pre-wipe telemetry survives the boundary and `/info` agrees with `/attempts` | `test_global_wipe_clears_candidates_resets_timestamp_and_snapshot`, `test_global_wiper_first_deadline_is_delayed_by_period`, `test_production_global_wipe_interval_is_24_hours` |
| Configuration is validated fail-closed at startup (ranges, NaN/∞/≤0 rejected) | `config::{validate_config,validate_capacity}` | A zero or absurd value would silently disable a protection | `test_validate_config_accepts_valid_values`, `test_validate_config_rejects_zero_max_attempts`, `test_validate_capacity_rejects_zero`, `test_validate_token_bucket_rejects_nan` |
| Token bursts are finite, contain at least one representable token, and subtracting one changes the `f64` | `config::validate_token_bucket` | Numerically ineffective capacities would silently disable a bucket | `test_validate_token_bucket_rejects_f64_max`, `test_validate_token_bucket_rejects_infinity`, `test_validate_token_bucket_rejects_sub_token_bursts` |
| SQLite is bundled at least 3.51.3; startup verifies runtime version and WAL, while every connection verifies WAL and secure deletion | `storage::sqlite` | Reproducible WAL-reset fix and deletion invariant without a per-connection version query | `test_application_connection_enables_secure_delete`, `test_application_connection_uses_patched_sqlite_and_wal`, `test_memory_database_fails_closed_when_wal_is_unavailable` |
| Errors are classified by HTTP status only: `429` = targeted lockout, `503` = global pressure, both with `Retry-After` | `http::{contract,error}`, `router` | Clients must not match on error text | `test_503_responses_have_no_machine_code`, `test_global_buckets_use_503_without_targeted_metadata`, `test_targeted_429_has_targeted_metadata` |
| POST requests matching `/store`, `/fetch`, and `/trash` have a uniform minimum server-side response time, including extractor rejections; `/info`, `/attempts`, 404s, 405s, other routes, and already-slow processing are excluded | `router` | Reduce fast success/failure timing differences without holding database resources or pretending to equalize network time | `production_router_applies_the_500_millisecond_floor`, `sensitive_post_success_and_failures_have_the_configured_floor`, `default_body_limit_rejection_is_also_delayed` |
| The snapshot is a projection of ledger counters, never a copy of ledger state: replacing every retained CandidateTag leaves the published bytes and the ETag identical | `AttemptsLedgerState::snapshot_entries`, `AttemptsLedgerEntry` | A CandidateTag must be unable to reach the payload, and the snapshot's peak cost must not scale with the candidate budget (measured: the snapshot's marginal cost fell from 37,530 to 199 bytes per entry at `RATE_LIMIT_MAX_ATTEMPTS=255`) | `test_snapshot_is_independent_of_candidate_tags`, `test_snapshot_never_contains_secret_material`, `test_attempts_snapshot_at_full_map_scale` |
| A global-bucket `503` carries a `Retry-After` derived from the bucket's own state at the moment of refusal: the missing fraction of a token over the configured refill rate, rounded up, at least one second | `rate_limit::{BucketDecision,TokenBucket::try_consume_at}` | A fixed `1` was only right for the default rates; with a slower refill it told clients to retry before a token could exist, turning the backoff into extra load during overload | `test_token_bucket_refill_is_deterministic_on_an_injected_clock`, `test_token_bucket_backoff_rounds_up_and_floors_at_one_second`, `test_global_bucket_retry_after_follows_the_configured_refill` |
| The non-loopback deployment warning is decided on the address the listener actually bound, not on the `SERVER_ADDRESS` text | `main::is_loopback_bind`, `main::warn_unless_loopback` | A textual prefix check accepted `localhost.attacker.example` and flagged the loopback `127.0.0.2`; the warning remains advisory, as the runbook states | `loopback_is_decided_on_the_bound_address`, `bound_localhost_is_judged_by_its_resolved_address` |
| Configuration bounds follow from other invariants: `RATE_LIMIT_COOLDOWN` is at most the 24-hour wipe interval, `SECRET_MAX_LENGTH` lies between the Profile 1 secret length (128) and the largest Base64 value the 1024-byte body limit can carry (832), and `ATTEMPTS_SNAPSHOT_TTL_SECONDS` is shorter than the cooldown | `config::{validate_config,validate_snapshot_ttl}`, `MAX_RATE_LIMIT_COOLDOWN_MINUTES`, `MAX_SECRET_LENGTH` | A longer cooldown announces a budget the wipe discards; a secret length outside the range refuses every conforming backup or advertises a length `/store` answers `413` to; a TTL at or above the cooldown lets an attempt expire between two rebuilds and never be published | `test_validate_config_rejects_a_cooldown_longer_than_the_wipe_interval`, `test_max_cooldown_is_the_global_wipe_interval`, `test_validate_config_bounds_secret_max_length_to_the_profile_and_the_body_limit`, `test_store_envelope_constant_matches_the_serialized_body`, `test_validate_snapshot_ttl_must_be_shorter_than_the_cooldown` |
| The `secret` schema is validated as an unconditional startup postcondition, against the live table and not Diesel's ledger | `storage::sqlite::validate_secret_schema` | A ledger that already records `0001` makes Diesel skip the migration, so a missing or incompatible table (partial restore, manual edit) used to pass startup and fail every request with `500` | `recorded_migration_without_secret_table_is_rejected`, `recorded_migration_with_incompatible_secret_table_is_rejected`, `recorded_migration_with_exact_secret_table_is_accepted`, `initialize_fails_closed_when_the_secret_table_is_missing` |
| The request timeout is an application response: an expired request receives `503` with `Retry-After` and the JSON error envelope, recorded by diagnostics as `overload` | `router::request_timeout_middleware` | Clients classify by status only and are told to retry `503`; the framework's bare `408` with an empty body is outside the documented status set and would not trigger the backoff the contract expects | `test_request_timeout_is_a_503_with_retry_after_and_error_body` |
| A snapshot built from a pre-wipe copy of the ledger is never published after the wipe: the wipe advances a collection epoch under the cache lock, and a build publishes only if the epoch it captured before copying is unchanged | `attempts::snapshot::{wipe_epoch,build_and_publish}` | The 24-hour wipe is a retention boundary; a build that copied the ledger before the wipe and finished after it used to refill the cache with purged entries, attached to the new `collection_started_at` | `test_wipe_during_in_flight_build_after_ledger_copy_publishes_nothing_pre_wipe`, `test_wipe_during_in_flight_build_after_collection_read_publishes_nothing_pre_wipe`, `test_global_wipe_clears_candidates_resets_timestamp_and_snapshot` |
| A snapshot build that dies without publishing releases the single-flight slot, so `/attempts` recovers on the next request | `attempts::snapshot::BuildSlotGuard` | An occupied slot whose sender is gone makes every later `/attempts` request a `500`, permanently, since a new build only starts when the slot is empty | `test_attempts_recovers_after_a_snapshot_build_dies`, `test_cancelled_attempts_request_keeps_single_rebuild_in_flight` |
| Cooldown expiry decides on the monotonic clock; wall-clock values remain the published timestamps and the finalization generation token | `attempts::ledger::is_expired`, `RateLimitInfo::last_candidate_instant` | A forward `CLOCK_REALTIME` step larger than the cooldown would otherwise expire every entry at once and reset every per-identifier budget — the server's only control against password brute-force | `test_a_forward_wall_clock_jump_does_not_reset_a_saturated_budget`, `test_a_forward_wall_clock_jump_does_not_sweep_active_entries`, `test_sweep_removes_only_expired_entries`, `test_fetch_expires_sub_threshold_entry_after_cooldown` |
| Identifier-map capacity is validated against the lower of the declared budget and the enforced cgroup limit, accounting for the candidate budget, and refuses at startup rather than deferring to the OOM killer | `config::{validate_capacity,estimated_peak_memory_bytes}` | The former fixed 10,000,000-entry ceiling rested on a per-entry cost an order of magnitude too low, so it admitted exactly the silent memory-exhaustion kill it claimed to prevent (~14.4 GiB of peak against `MemoryMax=512M`) | `test_validate_capacity_rejects_the_former_ten_million_ceiling`, `test_validate_capacity_tracks_the_candidate_budget`, `test_validate_capacity_boundary_is_exact`, `test_capacity_model_is_not_optimistic_against_the_measurement`, `test_estimated_peak_memory_does_not_wrap`, `test_effective_budget_takes_the_enforced_limit_when_lower`, `test_capacity_is_refused_against_a_lower_enforced_limit`, `test_parse_memory_limit_recognizes_unlimited_forms` |
| Only a genuine `5xx` spends the WARN-level server-error diagnostic budget; category and quota class come from one table and cannot disagree | `observability::diagnostic::classify` | The server-error class is live under the default log filter, so any benign status routed into it lets public traffic starve the budget a genuine `500` needs — `304` did this at 2 requests/second, and `503` would do it under load | `test_only_genuine_server_errors_spend_the_warn_budget`, `test_not_modified_is_not_a_server_error`, `test_status_categories_are_deterministic` |
| Dotenv CANARY is read for every `/info` without cache metadata; process-env CANARY is authoritative, missing CANARY is empty, and unavailable files use startup fallback | `config::canary_file_state`, `InfoState::current_canary` | Operators can signal edits immediately without stale cache state | `test_info_rereads_same_length_canary_when_file_metadata_is_restored`, `test_info_rereads_canary_from_file_with_startup_fallback`, `test_info_env_canary_is_authoritative_over_file` |

## Final path and verification checklist

- [ ] `src/main.rs`, `src/app.rs`, `src/config.rs`, `src/router.rs`, `src/http/`, `src/handlers/`, `src/recovery/`, `src/attempts/`, `src/storage/sqlite.rs`, and `src/observability/` exist at the paths in the reading map.
- [ ] `src/schema.rs` remains the Diesel schema path imposed by `diesel.toml`.
- [ ] The final test listing contains every test named in the invariant table: verify with `cargo test --locked -- --list` (the local listing contains 194 tests; no listing is checked in).
- [ ] CI compiles rustdocs with `cargo doc --no-deps --document-private-items --locked`; this proves only that rustdoc compiles, not that an invariant is correct or tested.
- [ ] For a documentation-only change, the local static checks are `git diff --check`, path existence checks, and exact-name checks against the final `cargo test --locked -- --list` output; do not substitute `cargo doc` for executable invariant evidence.

## Test-writing traps

- **Never depend on environment-provided rate-limit config.** The README
  defaults (`STORE_RATE_LIMIT_BURST=10`) differ from CI and the repo `.env`
  (10000): a test doing more requests than the default burst fails for a
  reason unrelated to what it guards (this exact trap broke the F1
  characterization test). Install a dedicated bucket instead — pattern:
  `test_audit_f9_store_writes_are_token_bucketed`.
- **The test environment's cooldown is one minute.** `validate_snapshot_ttl`
  requires the snapshot TTL to be shorter than the cooldown, so the CI env
  and `.env.example` set `ATTEMPTS_SNAPSHOT_TTL_SECONDS=30`; the code default
  of 60 would be refused at `config::init()` and fail every test.
- **Keep the suite parallel-safe.** Per-test database isolation is handled
  by the test harness; CI runs `cargo test --locked`. Do not reintroduce
  `--test-threads=1`.
- **Characterization tests are Red-Green.** A test documenting a
  vulnerability must fail once the fix lands; rewrite it to assert the
  secure behavior. Fixes are proven by a test verified to fail without
  them.

## Audit history

- **SECURITY-AUDIT-2026-08-04** (multi-model external review of
  `main@38b274f`): 13 findings (F1–F13) per the audit report, absorbed in
  PR #8 over three rounds. Characterized by tests: F1, F2, F9, F11 and F12
  in `src/tests/test_audit_claims.rs`, F3 in `src/tests/test_db_errors.rs`.
- **F1 (CRITICAL) proven Red-Green on live servers** (2026-08-20,
  `main@38b274f` vs this branch): on `main`, a duplicate `/store` returned
  `403` (existence oracle → unthrottled PIN brute-force, followed by `200`
  on `/fetch` with the found key); on the fix branch, the duplicate returns
  `201`, indistinguishable from a fresh store.
- **Independent re-reviews** (2026-08-20, commit `89af2b1`): full-branch
  adversarial review and delta review of the final state — no confirmed
  residual vulnerability; full suite 122/122 and `cargo audit` clean as of
  that date.
- **Distinct-candidate limiter review** (2026-08-20): the rate-limit bucket
  remains `sha256(identifier)`, while `secret_id/key_id` CandidateTags are
  retained only in bounded memory. Pending reservations, saturation-before-
  membership, replay telemetry, shared `/fetch`/`/trash` state, and detached
  generation-safe finalization are covered by the distinct-candidate tests.
  The three-distinct-candidate targeted lockout remains accepted; this is an
  availability and signal improvement, not a corrected vulnerability.

## Reviewer checklist

1. **New endpoint or response change?** Oracle check: can any response
   (status, body, timing) distinguish the existence of a `secret_id` or the
   correctness of a key without consuming the per-identifier budget?
2. **Budget accounting.** Every reserved attempt is consumed exactly once
   or refunded exactly once. Check every `.await` between reservation and
   `transfer()` for cancellation.
3. **Concurrency.** Check-and-act under a single lock; no lock held across
   database or network work; SQLite writes serialized (`busy_timeout`,
   immediate transactions for read-delete).
4. **Information.** Response shapes and timestamps identical regardless of
   identifier existence; logs carry counts only; snapshot stays
   hour-truncated and hash-only.
5. **Configuration.** New variables validated fail-closed at startup and
   documented in the README; legacy aliases keep working with a warning.
6. **Dependencies and CI.** `cargo audit` clean; CI gates intact (fmt,
   clippy `-D warnings`, `--locked` build and tests, daily audit).
7. **Documentation.** Any newly accepted risk goes to "Accepted risks"
   above; any new invariant goes to the table with its guarding test.

## Reporting

Please report suspected vulnerabilities privately (GitHub private
vulnerability reporting) rather than in public issues.
