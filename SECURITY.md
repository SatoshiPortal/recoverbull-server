# Security

This document consolidates what security reviewers need to know about this
server so that each review does not start from zero: the threat model, the
risks that are **accepted by design** (do not re-report them), the
**invariants** the code must keep (each guarded by tests), the traps already
stepped into, and a checklist for future reviews.

For deployment guardrails (single-instance, nginx, Tor onion), see the
README — they are part of the security model, not optional hardening.

## Threat model (summary)

The server stores `encrypted_secret` values keyed by
`secret_id = SHA-256(identifier_hex + authentication_key_hex)`. It never sees
the password, the encryption key, or the cleartext secret. Because the user
password is weak by design (a memorable PIN), the **only** server-side
control against password brute-force is the per-identifier lookup budget
(default 3 attempts per cooldown per `sha256(identifier)`). Everything else
— anonymity, no accounts, Tor-only transport, daily in-memory wipe — exists
to keep that control meaningful and the server unlinkable to users.

Attacker capabilities considered: holding a victim's Backup File
(`identifier` + `salt`, no ciphertext); a malicious or compromised Key
Server; a database leak; a malicious cloud storage provider; collusion or
legal compulsion of both providers (see the whitepaper for the full list).

## Accepted risks and design tensions (do not re-report)

1. **Recovery lockout (audit F2).** An attacker holding the Backup File can
   consume the victim's lookup budget and keep the identifier locked out,
   delaying or preventing recovery. The counter is keyed by
   `sha256(identifier)` and checked before credentials are verified: the
   server cannot distinguish owner from attacker. Mitigation is *detection*
   (`attempt_status`, `/attempts`, unexpected `429`), not prevention.
   **Do not "fix" this by resetting the counter on a successful lookup**:
   `/store` is public, so an attacker can plant a matching row and "succeed"
   to erase the attack signal. That was deliberately reversed in `ee9f29a`.
   Roadmap: escalating backoff, client proof-of-work, multi-server storage.
2. **A successful lookup never proves ownership.** Anyone can plant a row
   for a guessed key through `/store` and then "successfully" fetch it.
   Counters therefore include database hits and never reset on success.
3. **Telemetry is readable by identifier holders.** `/attempts` publishes
   `SHA-256(identifier)` only. Entries are indistinguishable: real usage,
   another device, and attacker probes produce the same entry shape. This
   relies on clients generating identifiers with 256 bits of entropy — a
   low-entropy identifier would make its hash brute-forceable.
4. **Timestamp precision follows a knowledge gradient.** Exact timestamps go
   to identifier holders (direct responses), hour-truncated to everyone
   (public snapshot). An exact `requested_at` in a `429` can be the victim's
   last admitted attempt: accepted, and needed by clients to compute retry
   time.
5. **Service-state oracle via distinct `503` bodies.** Lookup-bucket
   exhaustion, map-full, and database-busy are deliberately distinguishable
   (clients must react differently). An attacker reads the same states.
6. **Telemetry suppression.** Flooding `/attempts` or churning the snapshot
   ETag can delay clients' snapshot reads. `attempt_status` on a successful
   fetch is the fallback signal, unaffected by that flood.
7. **Map filling.** New identifiers get `503` when the map is full
   (fail-closed); active entries are never evicted by new identifiers. The
   attack and the alarm are the same event: probing creates the victim's
   warning entry.
8. **Offline PIN brute-force with a database leak.** A leak of
   `encrypted_secret` + the Backup File's `salt` reduces security to the PIN
   (Argon2id slows but does not prevent this). Inherent to the protocol;
   client-side key rotation is the mitigation.
9. **Server trust.** Telemetry is advisory: a compromised server can
   fabricate or suppress counters, and the warrant canary has the classic
   limits (an operator under compulsion may keep serving it). Clients must
   warn, never act automatically.
10. **Global buckets can deny service to everyone.** Behind an onion service
    per-IP limiting is useless, so buckets are global; an attacker can
    exhaust them (`503` for all). Bounded by nginx/Tor defenses at the
    deployment layer.

## Invariants (each guarded by tests)

Breaking any of these reintroduces a fixed vulnerability. If you change the
code, keep the invariant — and run the guarding test.

| Invariant | Why | Guarding test(s) |
|---|---|---|
| `/store` is idempotent: fresh and duplicate return the same `201`, never overwrite | F1: duplicate `403` was an unthrottled `authentication_key` oracle | `test_audit_f1_store_gives_no_existence_signal`, `test_duplicate_store_is_indistinguishable_and_does_not_overwrite`, `test_concurrent_identical_store_is_idempotent` |
| Rate-limit check-and-increment is atomic under one lock | Concurrent requests otherwise overshoot the budget | `test_rate_limit_holds_under_concurrency` |
| Every admitted lookup consumes budget, hits included; never reset on success | Planted rows would erase the signal or bypass the budget | `test_audit_f1_planted_rows_cannot_reset_fetch_rate_limit`, `test_success_does_not_reset_the_counter`, `test_trash_does_not_reset_the_counter` |
| A reservation is refunded exactly once, only on internal errors, and never after SQLite work has started | Budget integrity under cancellation | `test_cancelled_request_does_not_consume_an_attempt`, `test_cancelled_trash_after_sqlite_start_keeps_attempt_reserved`, `test_concurrent_cancellation_refunds_every_reservation`, `test_database_error_returns_500_without_consuming_attempts` |
| Deferred-refund temporal invariant: armed window ≤ 1s (semaphore timeout) and refund delay ≈ ms, both ≪ minimum cooldown (1 min) | Otherwise a deferred refund could decrement a recreated window's entry | Reasoning documented on `AttemptReservationGuard` in `src/handlers/fetch.rs` |
| `id_hash` = SHA-256 over raw identifier bytes; `secret_id` = SHA-256 over the two hex *strings* | Clients must match their entry; mixing algorithms silently breaks detection | `test_attempts_id_hash_matches_shared_client_vector`, `test_secret_id_and_id_hash_are_distinct_algorithms` |
| Logs and error responses carry counts and static strings only — never identifiers, keys, or bodies | Anonymity | `test_error_responses_leak_no_secret_material`, `test_snapshot_never_contains_secret_material`, `test_500_does_not_leak_internals` |
| Hex inputs are lowercased before validation and hashing | Case variants would split budgets and records | `test_audit_f12_hex_case_is_canonicalized` |
| Cheap validation before expensive: length before base64 decode, 1 kB body limit | DoS via decode/parse cost | `test_store_checks_length_before_base64`, `test_store_rejects_oversized_json_before_deserialization` |
| Snapshot is deterministic (sorted entries, gzip `mtime=0`), hour-truncated, single-flight | Stable ETag; precision gradient; bounded build cost | `test_attempts_snapshot_rebuild_is_deterministic`, `test_attempts_snapshot_at_full_map_scale`, `test_concurrent_attempts_polls_agree_on_etag` |
| Configuration is validated fail-closed at startup (ranges, NaN/∞/≤0 rejected) | A zero or absurd value would silently disable a protection | `src/tests/test_env.rs` |
| Errors are classified by HTTP status only: `429` = targeted lockout, `503` = global pressure, both with `Retry-After` | Clients must not match on error text | `src/tests/test_contract.rs` |

## Test-writing traps

- **Never depend on environment-provided rate-limit config.** The README
  defaults (`STORE_RATE_LIMIT_BURST=10`) differ from CI and the repo `.env`
  (10000): a test doing more requests than the default burst fails for a
  reason unrelated to what it guards (this exact trap broke the F1
  characterization test). Install a dedicated bucket instead — pattern:
  `test_audit_f9_store_writes_are_token_bucketed`.
- **Keep the suite parallel-safe.** Per-test database isolation is handled
  by the test harness; CI runs `cargo test --locked`. Do not reintroduce
  `--test-threads=1`.
- **Characterization tests are Red-Green.** A test documenting a
  vulnerability must fail once the fix lands; rewrite it to assert the
  secure behavior. Fixes are proven by a test verified to fail without
  them.

## Audit history

- **SECURITY-AUDIT-2026-08-04** (multi-model external review of
  `main@38b274f`): 13 findings (F1–F13), absorbed in PR #8 over three
  rounds. Characterization tests live in `src/tests/test_audit_claims.rs`.
- **F1 (CRITICAL) proven Red-Green on live servers**: on `main`, a
  duplicate `/store` returned `403` (existence oracle → unthrottled PIN
  brute-force, followed by `200` on `/fetch` with the found key); on the
  fix branch, the duplicate returns `201`, indistinguishable from a fresh
  store.
- **Independent re-reviews** (2026-08-20): full-branch adversarial review
  and delta review of the final state — no confirmed residual
  vulnerability; full suite 122/122 and `cargo audit` clean.

## Reviewer checklist

1. **New endpoint or response change?** Oracle check: can any response
   (status, body, timing) distinguish the existence of a `secret_id` or the
   correctness of a key without consuming the per-identifier budget?
2. **Budget accounting.** Every reserved attempt is consumed exactly once
   or refunded exactly once. Check every `.await` between reservation and
   `disarm()` for cancellation.
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
