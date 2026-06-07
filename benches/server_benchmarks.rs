// The optional `ldap_benchmark` cfg gates a benchmark that needs a live LDAP
// server; it is not a declared Cargo feature, so allow the unknown-cfg lint here.
#![allow(unexpected_cfgs)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use radius_server::cache::{RequestCache, RequestFingerprint};
use radius_server::ratelimit::{RateLimitConfig, RateLimiter};
use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

// Cache benchmarks
fn bench_cache_duplicate_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_duplicate_check");

    let cache = RequestCache::new(Duration::from_secs(60), 10000);
    let test_authenticator = [1u8; 16];
    let test_fingerprint =
        RequestFingerprint::new("192.168.1.100".parse().unwrap(), 1, &test_authenticator);

    group.bench_function("first_request", |b| {
        b.iter(|| {
            cache.is_duplicate(
                black_box(test_fingerprint.clone()),
                black_box(test_authenticator),
            );
        });
    });

    group.finish();
}

fn bench_cache_concurrent(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent");

    for num_threads in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_threads),
            num_threads,
            |b, &num_threads| {
                let cache = Arc::new(RequestCache::new(Duration::from_secs(60), 10000));
                b.iter(|| {
                    let handles: Vec<_> = (0..num_threads)
                        .map(|i| {
                            let cache_ref = Arc::clone(&cache);
                            std::thread::spawn(move || {
                                for j in 0..100 {
                                    let auth = [i as u8; 16];
                                    let fingerprint = RequestFingerprint::new(
                                        format!("192.168.{}.{}", i, j).parse().unwrap(),
                                        j as u8,
                                        &auth,
                                    );
                                    cache_ref.is_duplicate(fingerprint, auth);
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

// Rate limiter benchmarks
fn bench_ratelimit_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_check");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let limiter = RateLimiter::new(RateLimitConfig::default());

    group.bench_function("single_client", |b| {
        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
        b.iter(|| {
            rt.block_on(limiter.check_rate_limit(black_box(test_ip)));
        });
    });

    group.finish();
}

fn bench_ratelimit_concurrent(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_concurrent");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for num_clients in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_clients),
            num_clients,
            |b, &num_clients| {
                let limiter = RateLimiter::new(RateLimitConfig::default());
                let clients: Vec<IpAddr> = (0..num_clients)
                    .map(|i| format!("192.168.{}.{}", i / 256, i % 256).parse().unwrap())
                    .collect();

                b.iter(|| {
                    rt.block_on(async {
                        for client in &clients {
                            limiter.check_rate_limit(black_box(*client)).await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_ratelimit_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_burst");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let limiter = RateLimiter::new(RateLimitConfig::default());

    group.bench_function("burst_100", |b| {
        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..100 {
                    limiter.check_rate_limit(black_box(test_ip)).await;
                }
            });
        });
    });

    group.finish();
}

// Password verification benchmarks (bcrypt)
fn bench_bcrypt_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("bcrypt_verification");
    group.sample_size(10); // Bcrypt is slow, use fewer samples
    group.measurement_time(Duration::from_secs(10));

    let password = "test_password_123";
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

    group.bench_function("verify_correct", |b| {
        b.iter(|| {
            bcrypt::verify(black_box(password), black_box(&hash)).unwrap();
        });
    });

    group.bench_function("verify_incorrect", |b| {
        b.iter(|| {
            let _ = bcrypt::verify(black_box("wrong_password"), black_box(&hash));
        });
    });

    group.finish();
}

// LDAP connection pool benchmarks
// Note: These are placeholder benchmarks that would require a real LDAP server
// They demonstrate the performance testing approach for LDAP operations

#[cfg(feature = "ldap_benchmark")]
mod ldap_benchmarks {
    use super::*;
    use radius_server::ldap_auth::{LdapAuthHandler, LdapConfig};

    fn bench_ldap_pool_acquisition(c: &mut Criterion) {
        let mut group = c.benchmark_group("ldap_pool_acquisition");
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(10));

        let config = LdapConfig {
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
            bind_password: Some("password".to_string()),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["dn".to_string(), "cn".to_string()],
            timeout: 10,
            verify_tls: false,
            max_connections: 10,
            acquire_timeout: 10,
        };

        let handler = LdapAuthHandler::new(config);

        group.bench_function("acquire_connection", |b| {
            b.iter(|| {
                // This would test connection acquisition time
                // In a real benchmark, would acquire and release connections
            });
        });

        group.finish();
    }

    fn bench_ldap_search(c: &mut Criterion) {
        let mut group = c.benchmark_group("ldap_search");
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(15));

        // Benchmark user search operations
        // Would measure the time to search for a user in LDAP

        group.finish();
    }

    fn bench_ldap_auth(c: &mut Criterion) {
        let mut group = c.benchmark_group("ldap_auth");
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(15));

        // Benchmark full authentication flow:
        // 1. Search for user
        // 2. Bind with user credentials
        // 3. Return result

        group.finish();
    }
}

criterion_group!(
    cache_benches,
    bench_cache_duplicate_check,
    bench_cache_concurrent
);

criterion_group!(
    ratelimit_benches,
    bench_ratelimit_check,
    bench_ratelimit_concurrent,
    bench_ratelimit_burst
);

criterion_group!(password_benches, bench_bcrypt_verification);

criterion_main!(cache_benches, ratelimit_benches, password_benches);
