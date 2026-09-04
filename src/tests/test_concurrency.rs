use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Starts the app on a real TCP listener so requests are truly concurrent,
/// handled in parallel by the multi-threaded runtime.
async fn spawn_server() -> (std::net::SocketAddr, crate::AppState) {
    let app_state = crate::app::init();
    // Dedicated generous buckets: these tests drive 30-100 requests and must
    // not depend on the environment-provided buckets (code defaults: store
    // burst 10, lookup burst 100) — see SECURITY.md "Test-writing traps".
    app_state
        .recovery
        .set_store_bucket_for_test(crate::rate_limit::TokenBucket::new(10_000.0, 10_000.0))
        .await;
    app_state
        .recovery
        .set_lookup_bucket_for_test(crate::rate_limit::TokenBucket::new(10_000.0, 10_000.0))
        .await;
    app_state.storage.initialize().unwrap();
    let app = crate::router::new_for_tests(app_state.clone());

    let mut connection =
        crate::storage::sqlite::establish_connection(app_state.storage.database_url_for_test())
            .unwrap();
    crate::tests::test_server::clear_table_secret(&mut connection).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, app_state)
}

async fn raw_post(addr: std::net::SocketAddr, path: &str, body: String) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0)
}

/// Without a busy_timeout, concurrent writers in WAL mode fail immediately
/// with SQLITE_BUSY (measured: 46/50 concurrent stores failed with HTTP 400).
/// With the pragma set, writes are serialized and all succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_store_writes_succeed() {
    let (addr, _) = spawn_server().await;

    const N: usize = 30;
    let mut handles = Vec::new();
    for i in 0..N {
        handles.push(tokio::spawn(async move {
            let body = format!(
                "{{\"identifier\":\"{:064x}\",\"authentication_key\":\"{:064x}\",\"encrypted_secret\":\"dGVzdA==\"}}",
                i + 1,
                i + 1
            );
            raw_post(addr, "/store", body).await
        }));
    }

    let mut created = 0usize;
    let mut other = Vec::new();
    for h in handles {
        match h.await.unwrap() {
            201 => created += 1,
            code => other.push(code),
        }
    }

    assert_eq!(
        created, N,
        "concurrent stores should all succeed with busy_timeout, got failures: {:?}",
        other
    );
}

/// Regression test: the rate-limit check used to be non-atomic (read the
/// counter, release the lock, look up the database, then increment), so
/// concurrent requests could all pass the check before anyone incremented
/// (measured: 8 password guesses consumed instead of 3 with 100 concurrent
/// requests). The check-and-increment is now atomic under the same lock, so
/// exactly `max_failed_attempts` guesses are consumed, no matter the
/// concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_rate_limit_holds_under_concurrency() {
    let (addr, state) = spawn_server().await;

    let store_body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\",\"encrypted_secret\":\"dGVzdA==\"}}",
        crate::tests::SHA256_111111,
        crate::tests::SHA256_222222
    );
    assert_eq!(raw_post(addr, "/store", store_body).await, 201);

    const N: usize = 100;
    let mut handles = Vec::new();
    for index in 0..N {
        let body = format!(
            "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\"}}",
            crate::tests::SHA256_111111,
            crate::tests::distinct_authentication_key(index)
        );
        handles.push(tokio::spawn(
            async move { raw_post(addr, "/fetch", body).await },
        ));
    }

    let mut unauthorized = 0usize; // 401: a password guess was consumed
    let mut too_many = 0usize; // 429: rejected by the rate limiter
    let mut other = 0usize;
    for h in handles {
        match h.await.unwrap() {
            401 => unauthorized += 1,
            429 => too_many += 1,
            _ => other += 1,
        }
    }

    assert_eq!(other, 0, "unexpected status codes");
    assert_eq!(
        unauthorized,
        state.attempts.policy.max_attempts() as usize,
        "rate limit bypassed: more guesses consumed than allowed"
    );
    assert_eq!(too_many, N - state.attempts.policy.max_attempts() as usize);
}

/// A concurrent duplicate must not release the secret twice. The deterministic
/// Pending and Committed branches are proved by
/// `test_concurrent_trash_hit_does_not_count_the_losing_miss_as_a_guess` and
/// `test_committed_trash_race_returns_accepted_and_unauthorized_without_failure`;
/// this TCP test only checks the resulting one-release property across the
/// scheduling race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_trash_releases_secret_once() {
    let (addr, _) = spawn_server().await;

    let store_body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\",\"encrypted_secret\":\"dGVzdA==\"}}",
        crate::tests::SHA256_111111,
        crate::tests::SHA256_222222
    );
    assert_eq!(raw_post(addr, "/store", store_body).await, 201);

    let trash_body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\"}}",
        crate::tests::SHA256_111111,
        crate::tests::SHA256_222222
    );
    let first = tokio::spawn(raw_post(addr, "/trash", trash_body.clone()));
    let second = tokio::spawn(raw_post(addr, "/trash", trash_body));
    let statuses = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        statuses.iter().filter(|&&status| status == 202).count(),
        1,
        "exactly one concurrent trash request must release the secret"
    );

    let other_status = statuses
        .iter()
        .find(|&&status| status != 202)
        .copied()
        .expect("one non-success status must accompany the accepted trash");
    match other_status {
        401 => {} // the Committed replay observes the already-trashed secret
        503 => {} // the duplicate observes the first request while Pending
        status => panic!("unexpected concurrent trash status: {status}"),
    }
}

/// The F1 fix under race: 50 concurrent /store calls with the SAME payload
/// must all return 201 (indistinguishable, the oracle stays closed) and
/// create exactly one row (ON CONFLICT DO NOTHING is idempotent even when
/// SQLite serializes the writers at the last moment).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_identical_store_is_idempotent() {
    use diesel::{QueryDsl, RunQueryDsl};

    let (addr, app_state) = spawn_server().await;

    let body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\",\"encrypted_secret\":\"{}\"}}",
        crate::tests::SHA256_111111,
        crate::tests::SHA256_222222,
        crate::tests::BASE64_ENCRYPTED_SECRET
    );

    const N: usize = 50;
    let mut handles = Vec::new();
    for _ in 0..N {
        let body = body.clone();
        handles.push(tokio::spawn(
            async move { raw_post(addr, "/store", body).await },
        ));
    }

    let mut created = 0usize;
    let mut other = Vec::new();
    for h in handles {
        match h.await.unwrap() {
            201 => created += 1,
            code => other.push(code),
        }
    }
    assert_eq!(
        created, N,
        "every concurrent identical store must return 201, got: {other:?}"
    );

    let mut connection =
        crate::storage::sqlite::establish_connection(app_state.storage.database_url_for_test())
            .unwrap();
    let rows: i64 = crate::schema::secret::table
        .count()
        .get_result(&mut connection)
        .unwrap();
    assert_eq!(rows, 1, "concurrent identical stores must create one row");
}
