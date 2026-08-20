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
control against password brute-force is the per-identifier distinct-candidate budget
(3 attempts per cooldown in the documented `.env` and CI; the variable is
mandatory — there is no code default). Everything else
— anonymity, no accounts, Tor-only transport, daily in-memory wipe — exists
to keep that control meaningful and the server unlinkable to users.

Attacker capabilities considered: holding a victim's Backup File
(`identifier` + `salt`, no ciphertext); a malicious or compromised Key
Server; a database leak; a malicious cloud storage provider; collusion or
legal compulsion of both providers (see the whitepaper for the full list).

## Accepted risks and design tensions (do not re-report)

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
11. **Temporary behavioral state.** The server retains up to the configured
    maximum of derived CandidateTags (`secret_id/key_id`) per bucket in memory.
    A CandidateTag is never raw authentication or password material, and is
    never logged or snapshotted; Pending/Committed state is wiped on cooldown
    expiry or restart. This is a privacy trade-off: non-exposed temporary
    state is larger than the former identifier-only state.

## Invariants (each guarded by tests)

Breaking any of these reintroduces a fixed vulnerability. If you change the
code, keep the invariant — and run the guarding test.

| Invariant | Why | Guarding test(s) |
|---|---|---|
| `/store` is idempotent: fresh and duplicate return the same `201`, never overwrite | F1: duplicate `403` was an unthrottled `authentication_key` oracle | `test_audit_f1_store_gives_no_existence_signal`, `test_duplicate_store_is_indistinguishable_and_does_not_overwrite`, `test_concurrent_identical_store_is_idempotent` |
| Rate-limit check-and-increment is atomic under one lock | Concurrent requests otherwise overshoot the budget | `test_rate_limit_holds_under_concurrency` |
| Every distinct candidate consumes budget, hits and misses included; committed replays are free only before saturation and never extend cooldown | Planted rows must not bypass the budget, while identical replays improve availability | `test_replaying_one_valid_candidate_does_not_consume_more_attempts`, `test_replaying_one_invalid_candidate_does_not_consume_more_attempts`, `test_replaying_one_candidate_does_not_slide_resets_at`, `test_audit_f1_planted_rows_cannot_reset_fetch_rate_limit` |
| `candidate_count >= max` returns `429` before membership/DB for known, Pending, and Committed candidates | Saturation must not become an authentication oracle | `test_known_candidate_is_rejected_when_distinct_candidate_capacity_is_full`, `test_distinct_planted_candidates_consume_capacity`, `test_pending_distinct_candidates_consume_the_attempt_budget` |
| Pending reserves a slot immediately; duplicate Pending returns `503` without a second reservation; `/fetch` and `/trash` share the set | Concurrent work must not oversubscribe or manufacture a duplicate candidate | `test_pending_duplicate_trash_is_rejected_without_a_second_reservation`, `test_fetch_and_trash_share_one_candidate_attempt` |
| Detached finalization is generation-safe; DB error/cancellation before DB removes Pending; a miss increments failed once; trash races do not create false failures | Late completion and cancellation must not corrupt a replacement window or telemetry | `test_old_trash_completion_cannot_update_a_replaced_rate_limit_window`, `test_database_error_returns_500_without_consuming_attempts`, `test_committed_trash_race_returns_accepted_and_unauthorized_without_failure`, `test_concurrent_trash_hit_does_not_count_the_losing_miss_as_a_guess` |
| A Pending reservation is removed exactly once on cancellation before SQLite or on internal error; after transfer to SQLite, the detached task owns finalization | Budget integrity under cancellation and lost HTTP responses | `test_cancelled_request_does_not_consume_an_attempt`, `test_cancelled_trash_after_sqlite_start_keeps_attempt_reserved`, `test_concurrent_cancellation_refunds_every_reservation`, `test_deferred_refund_runs_when_drop_finds_the_lock_contended`, `test_database_error_returns_500_without_consuming_attempts` |
| Pending cleanup and detached finalization are candidate- and generation-specific; candidate removal plus empty-entry removal is atomic under one map lock | A stale completion must never mutate or delete a reservation in a replacement window or a newer request | `test_old_trash_completion_cannot_update_a_replaced_rate_limit_window`, `test_pending_duplicate_trash_is_rejected_without_a_second_reservation` |
| `id_hash` = SHA-256 over raw identifier bytes; `secret_id` = SHA-256 over the two hex *strings* | Clients must match their entry; mixing algorithms silently breaks detection | `test_attempts_id_hash_matches_shared_client_vector`, `test_secret_id_and_id_hash_are_distinct_algorithms` |
| Logs and error responses carry counts and static strings only — never identifiers, keys, or bodies | Anonymity | `test_error_responses_leak_no_secret_material`, `test_snapshot_never_contains_secret_material`, `test_500_does_not_leak_internals` |
| Hex inputs are lowercased before validation and hashing | Case variants would split budgets and records | `test_audit_f12_hex_case_is_canonicalized` |
| Cheap validation before expensive: length before base64 decode, 1 kB body limit | DoS via decode/parse cost | `test_store_checks_length_before_base64`, `test_store_rejects_oversized_json_before_deserialization` |
| Snapshot is deterministic (sorted entries, gzip `mtime=0`), hour-truncated, single-flight, version 2; counts distinct candidates and all requests but exposes no CandidateTags | Stable ETag; precision gradient; bounded build cost and privacy | `test_attempts_snapshot_rebuild_is_deterministic`, `test_attempts_publish_hashed_identifier_with_counters`, `test_attempts_snapshot_at_full_map_scale`, `test_concurrent_attempts_polls_agree_on_etag`, `test_snapshot_never_contains_secret_material` |
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
