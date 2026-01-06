use super::tests::TestContext;
use rand::Rng;
use rand::SeedableRng;
use rand::prelude::StdRng;
use std::time::Duration;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread")]
async fn stress_mitm_proxy() {
    // Run for a shorter duration by default to keep CI fast, but allow manual override
    let duration = if std::env::var("STRESS_TEST_LONG").is_ok() {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(5)
    };

    // For high values make sure you increase the limits of open file descriptors via `ulimit -n 100000`
    let concurrency = std::env::var("STRESS_TEST_CONCURRENCY").map_or(50, |v| {
        v.parse()
            .expect("`STRESS_TEST_CONCURRENCY` should be a number")
    });

    println!(
        "Starting stress test with concurrency {} for {:?}",
        concurrency, duration
    );

    let ctx = TestContext::new_mitm("stress-ok").await;
    let proxy_addr = ctx.proxy.addr();
    let origin_port = ctx.origin.addr().port();
    // We need to clone the client configuration to move into tasks.
    // TestClient::new is cheap.
    let proxy_ca_cert_path = ctx.proxy_ca.ca_cert_path_str();

    let start = std::time::Instant::now();
    let mut set = JoinSet::new();

    for i in 0..concurrency {
        let proxy_addr = proxy_addr;
        let proxy_ca_cert_path = proxy_ca_cert_path.clone();

        set.spawn(async move {
            let client = crate::proxy::tests::TestClient::new(proxy_addr, Some(proxy_ca_cert_path));
            let mut rng = StdRng::from_os_rng();
            let mut req_count = 0;

            while start.elapsed() < duration {
                // Randomly sleep a bit to stagger requests
                if rng.random_bool(0.1) {
                    tokio::time::sleep(Duration::from_millis(rng.random_range(1..10))).await;
                }

                // Randomize ALPN
                let use_h2 = rng.random_bool(0.5);
                let alpn = if use_h2 {
                    vec!["h2", "http/1.1"]
                } else {
                    vec!["http/1.1"]
                };

                // Random extra headers
                let mut extra_headers = Vec::new();
                if rng.random_bool(0.3) {
                    extra_headers.push(("X-Random-Header", "random-value"));
                }

                // We only implemented HTTP/1.1 GET in TestClient for now, so we stick to that.
                // But we can vary the headers and verify the response.

                let resp = client
                    .get("localhost", origin_port, &alpn, &extra_headers)
                    .await;
                let resp_str = String::from_utf8_lossy(&resp);

                if !resp_str.starts_with("HTTP/1.1 200 OK") {
                    panic!("Task {} failed on request {}: {:?}", i, req_count, resp_str);
                }
                if !resp_str.ends_with("stress-ok") {
                    panic!(
                        "Task {} got wrong body on request {}: {:?}",
                        i, req_count, resp_str
                    );
                }

                req_count += 1;
            }
            req_count
        });
    }

    let mut total_requests = 0;
    while let Some(res) = set.join_next().await {
        total_requests += res.expect("task shouldn't panic");
    }

    println!("Stress test finished. Total requests: {}", total_requests);
}
