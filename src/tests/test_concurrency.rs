use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Starts the app on a real TCP listener so requests are truly concurrent,
/// handled in parallel by the multi-threaded runtime.
async fn spawn_server() -> (std::net::SocketAddr, crate::AppState) {
    let app_state = crate::env::init();
    crate::database::init_db(app_state.clone());
    let app = crate::router::new(app_state.clone());

    let mut connection = crate::database::establish_connection(app_state.clone().database_url);
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
