//! Performance benchmarks for RADIUS server
//!
//! Run with: cargo bench --bench radius_server_bench
//!
//! These benchmarks measure:
//! - Packet encoding/decoding throughput
//! - Cache performance
//! - Rate limiter overhead
//! - Concurrent request handling

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use radius_proto::{
    attributes::Attribute,
    packet::{Code, Packet},
};
use radius_server::ratelimit::{RateLimitConfig, RateLimiter};
use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;

/// Benchmark packet encoding performance
fn bench_packet_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_encode");

    for num_attrs in [0, 5, 10, 20, 40] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_attrs", num_attrs)),
            &num_attrs,
            |b, &n| {
                b.iter(|| {
                    let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);

                    // Add User-Name
                    packet.add_attribute(Attribute::string(1, "testuser").unwrap());

                    // Add additional attributes
                    for i in 0..n {
                        packet.add_attribute(
                            Attribute::string(
                                31, // Calling-Station-Id
                                format!("client-{}", i),
                            )
                            .unwrap(),
                        );
                    }

                    black_box(packet.encode().unwrap())
                });
            },
        );
    }
    group.finish();
}

/// Benchmark packet decoding performance
fn bench_packet_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_decode");

    for num_attrs in [0, 5, 10, 20, 40] {
        // Pre-encode packets
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(1, "testuser").unwrap());
        for i in 0..num_attrs {
            packet.add_attribute(Attribute::string(31, format!("client-{}", i)).unwrap());
        }
        let encoded = packet.encode().unwrap();

        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_attrs", num_attrs)),
            &encoded,
            |b, data| {
                b.iter(|| black_box(Packet::decode(data).unwrap()));
            },
        );
    }
    group.finish();
}

// Note: Request cache benchmarks require Tokio runtime - skipped for now
// The cache.clear() method spawns background tasks requiring async context

/// Benchmark rate limiter performance
fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter");

    let config = RateLimitConfig {
        per_client_rps: 100,
        per_client_burst: 200,
        global_rps: 1000,
        global_burst: 2000,
        max_concurrent_connections: 100,
        max_bandwidth_bps: 10_000_000, // 10 Mbps
    };

    let limiter = Arc::new(RateLimiter::new(config));
    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    group.throughput(Throughput::Elements(1));

    // Benchmark bandwidth checking (synchronous)
    group.bench_function("check_bandwidth", |b| {
        b.iter(|| black_box(limiter.check_bandwidth(client_ip, 1500)));
    });

    // Benchmark connection tracking
    group.bench_function("track_connection", |b| {
        b.iter(|| {
            let allowed = limiter.track_connection(client_ip);
            if allowed {
                limiter.release_connection(client_ip);
            }
            black_box(allowed)
        });
    });

    group.finish();
}

// Note: Concurrent cache benchmarks require Tokio runtime - skipped for now

/// Benchmark password encryption/decryption
fn bench_password_crypto(c: &mut Criterion) {
    use radius_proto::auth::{decrypt_user_password, encrypt_user_password};

    let mut group = c.benchmark_group("password_crypto");
    group.throughput(Throughput::Elements(1));

    let password = "MySecurePassword123!";
    let secret = b"testing123";
    let authenticator = [0x42u8; 16];

    group.bench_function("encrypt", |b| {
        b.iter(|| black_box(encrypt_user_password(password, secret, &authenticator)));
    });

    let encrypted = encrypt_user_password(password, secret, &authenticator);
    group.bench_function("decrypt", |b| {
        b.iter(|| black_box(decrypt_user_password(&encrypted, secret, &authenticator)));
    });

    group.finish();
}

/// Benchmark attribute operations
fn bench_attributes(c: &mut Criterion) {
    let mut group = c.benchmark_group("attributes");

    let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);

    // Add 20 attributes
    for i in 0..20 {
        packet.add_attribute(Attribute::string(31, format!("value-{}", i)).unwrap());
    }

    group.throughput(Throughput::Elements(1));
    group.bench_function("find_attribute", |b| {
        b.iter(|| black_box(packet.find_attribute(31)));
    });

    group.bench_function("get_all_attributes", |b| {
        b.iter(|| black_box(packet.find_all_attributes(31)));
    });

    group.bench_function("add_attribute", |b| {
        b.iter(|| {
            let mut p = packet.clone();
            p.add_attribute(Attribute::string(31, "test").unwrap());
            black_box(p)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_packet_encode,
    bench_packet_decode,
    bench_rate_limiter,
    bench_password_crypto,
    bench_attributes,
);
criterion_main!(benches);
