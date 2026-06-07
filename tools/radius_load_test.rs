//! RADIUS Load Testing Tool
//!
//! Simulates realistic RADIUS authentication traffic patterns.
//!
//! Usage:
//!   cargo run --release --bin radius_load_test -- \
//!     --server 127.0.0.1:1812 \
//!     --secret testing123 \
//!     --clients 10 \
//!     --duration 60 \
//!     --rps 100

use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(name = "radius_load_test")]
#[command(about = "RADIUS server load testing tool", long_about = None)]
struct Args {
    /// RADIUS server address (IP:PORT)
    #[arg(short, long, default_value = "127.0.0.1:1812")]
    server: SocketAddr,

    /// Shared secret
    #[arg(short = 'S', long, default_value = "testing123")]
    secret: String,

    /// Number of concurrent clients
    #[arg(short, long, default_value_t = 10)]
    clients: usize,

    /// Test duration in seconds
    #[arg(short, long, default_value_t = 60)]
    duration: u64,

    /// Target requests per second (per client)
    #[arg(short, long, default_value_t = 100)]
    rps: u64,

    /// Request timeout in milliseconds
    #[arg(short, long, default_value_t = 3000)]
    timeout: u64,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Default)]
struct Stats {
    total_sent: AtomicU64,
    total_received: AtomicU64,
    total_timeouts: AtomicU64,
    total_errors: AtomicU64,
    total_accept: AtomicU64,
    total_reject: AtomicU64,
    total_bytes_sent: AtomicU64,
    total_bytes_received: AtomicU64,
    latencies_us: Arc<dashmap::DashMap<u64, u64>>,
}

impl Stats {
    fn record_sent(&self, bytes: usize) {
        self.total_sent.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn record_received(&self, bytes: usize, latency_us: u64, is_accept: bool) {
        self.total_received.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);

        if is_accept {
            self.total_accept.fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_reject.fetch_add(1, Ordering::Relaxed);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        self.latencies_us.insert(timestamp, latency_us);
    }

    fn record_timeout(&self) {
        self.total_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn print_summary(&self, elapsed: Duration) {
        let sent = self.total_sent.load(Ordering::Relaxed);
        let received = self.total_received.load(Ordering::Relaxed);
        let timeouts = self.total_timeouts.load(Ordering::Relaxed);
        let errors = self.total_errors.load(Ordering::Relaxed);
        let accepts = self.total_accept.load(Ordering::Relaxed);
        let rejects = self.total_reject.load(Ordering::Relaxed);
        let bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.total_bytes_received.load(Ordering::Relaxed);

        let elapsed_secs = elapsed.as_secs_f64();
        let rps = received as f64 / elapsed_secs;
        let throughput_mbps_sent = (bytes_sent as f64 * 8.0) / (elapsed_secs * 1_000_000.0);
        let throughput_mbps_recv = (bytes_received as f64 * 8.0) / (elapsed_secs * 1_000_000.0);

        // Calculate latency percentiles
        let mut latencies: Vec<u64> = self.latencies_us.iter().map(|r| *r.value()).collect();
        latencies.sort_unstable();

        println!("\n=== Load Test Results ===");
        println!("Duration: {:.2}s", elapsed_secs);
        println!("\nRequests:");
        println!("  Sent:     {}", sent);
        println!("  Received: {}", received);
        println!("  Timeouts: {}", timeouts);
        println!("  Errors:   {}", errors);
        println!("\nResponses:");
        if received > 0 {
            println!(
                "  Accept:   {} ({:.1}%)",
                accepts,
                (accepts as f64 / received as f64) * 100.0
            );
            println!(
                "  Reject:   {} ({:.1}%)",
                rejects,
                (rejects as f64 / received as f64) * 100.0
            );
        }
        println!("\nPerformance:");
        println!("  RPS:      {:.2}", rps);
        if sent > 0 {
            println!(
                "  Success:  {:.2}%",
                (received as f64 / sent as f64) * 100.0
            );
        }
        println!("\nThroughput:");
        println!(
            "  Sent:     {:.2} Mbps ({} bytes)",
            throughput_mbps_sent, bytes_sent
        );
        println!(
            "  Received: {:.2} Mbps ({} bytes)",
            throughput_mbps_recv, bytes_received
        );

        if !latencies.is_empty() {
            println!("\nLatency (microseconds):");
            println!("  Min:  {}", latencies[0]);
            println!("  P50:  {}", latencies[latencies.len() / 2]);
            println!("  P95:  {}", latencies[(latencies.len() * 95) / 100]);
            println!("  P99:  {}", latencies[(latencies.len() * 99) / 100]);
            println!("  Max:  {}", latencies[latencies.len() - 1]);
            println!(
                "  Avg:  {:.2}",
                latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
            );
        }
    }
}

/// Send a simple Access-Request packet (manually crafted)
fn send_access_request(
    socket: &UdpSocket,
    server: SocketAddr,
    _secret: &[u8],
    identifier: u8,
    username: &str,
) -> std::io::Result<usize> {
    // Build minimal RADIUS packet manually
    // Format: Code(1) + Identifier(1) + Length(2) + Authenticator(16) + Attributes

    let mut packet = vec![
        1,          // Code: Access-Request
        identifier, // Identifier
        0,          // Length placeholder (high byte)
        0,          // Length placeholder (low byte)
    ];

    // Request Authenticator (random)
    let authenticator: [u8; 16] = rand::random();
    packet.extend_from_slice(&authenticator);

    // User-Name attribute (Type=1)
    let username_bytes = username.as_bytes();
    packet.push(1); // Type
    packet.push(2 + username_bytes.len() as u8); // Length
    packet.extend_from_slice(username_bytes);

    // NAS-IP-Address attribute (Type=4)
    packet.push(4); // Type
    packet.push(6); // Length
    packet.extend_from_slice(&[192, 168, 1, 1]); // 192.168.1.1

    // Update length field
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xFF) as u8;

    socket.send_to(&packet, server)?;
    Ok(packet.len())
}

/// Parse response code from RADIUS packet
fn parse_response_code(data: &[u8]) -> Option<u8> {
    if data.len() >= 20 {
        Some(data[0])
    } else {
        None
    }
}

/// Client worker task
async fn client_worker(
    client_id: usize,
    args: Arc<Args>,
    stats: Arc<Stats>,
    stop_signal: Arc<std::sync::atomic::AtomicBool>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Client {} failed to bind socket: {}", client_id, e);
            return;
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(args.timeout))) {
        eprintln!("Client {} failed to set timeout: {}", client_id, e);
        return;
    }

    let secret = args.secret.as_bytes();
    let mut identifier: u8 = 0;
    let interval = Duration::from_micros(1_000_000 / args.rps);

    loop {
        // Check if we should stop
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }

        let start = Instant::now();
        identifier = identifier.wrapping_add(1);

        let username = format!("user{}", client_id);

        // Send authentication request
        match send_access_request(&socket, args.server, secret, identifier, &username) {
            Ok(sent_bytes) => {
                stats.record_sent(sent_bytes);

                // Wait for response
                let mut buf = [0u8; 4096];
                match socket.recv_from(&mut buf) {
                    Ok((len, _)) => {
                        let latency = start.elapsed().as_micros() as u64;

                        // Parse response code: 2 = Access-Accept, 3 = Access-Reject
                        let is_accept = parse_response_code(&buf[..len])
                            .map(|code| code == 2)
                            .unwrap_or(false);

                        stats.record_received(len, latency, is_accept);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        stats.record_timeout();
                    }
                    Err(_) => {
                        stats.record_error();
                    }
                }
            }
            Err(_) => {
                stats.record_error();
            }
        }

        // Rate limiting
        let elapsed = start.elapsed();
        if elapsed < interval {
            sleep(interval - elapsed).await;
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Arc::new(Args::parse());
    let stats = Arc::new(Stats::default());
    let stop_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));

    println!("=== RADIUS Load Test ===");
    println!("Server:      {}", args.server);
    println!("Clients:     {}", args.clients);
    println!("Duration:    {}s", args.duration);
    println!(
        "Target RPS:  {} per client ({} total)",
        args.rps,
        args.rps * args.clients as u64
    );
    println!("Timeout:     {}ms", args.timeout);
    println!("\nStarting test...\n");

    let start = Instant::now();

    // Spawn client workers
    let mut handles = vec![];
    for client_id in 0..args.clients {
        let args = Arc::clone(&args);
        let stats = Arc::clone(&stats);
        let stop_signal = Arc::clone(&stop_signal);

        let handle = tokio::spawn(async move {
            client_worker(client_id, args, stats, stop_signal).await;
        });
        handles.push(handle);
    }

    // Progress reporter
    let stats_clone = Arc::clone(&stats);
    let progress_handle = tokio::spawn(async move {
        let mut last_received = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let received = stats_clone.total_received.load(Ordering::Relaxed);
            let rps = (received - last_received) as f64 / 5.0;
            last_received = received;

            println!(
                "[{:>3}s] RPS: {:.0}, Total: {}, Timeouts: {}, Errors: {}",
                start.elapsed().as_secs(),
                rps,
                received,
                stats_clone.total_timeouts.load(Ordering::Relaxed),
                stats_clone.total_errors.load(Ordering::Relaxed),
            );
        }
    });

    // Wait for test duration
    sleep(Duration::from_secs(args.duration)).await;

    // Signal stop
    stop_signal.store(true, Ordering::Relaxed);

    // Wait for all clients to finish
    for handle in handles {
        let _ = handle.await;
    }

    // Stop progress reporter
    progress_handle.abort();

    let elapsed = start.elapsed();
    stats.print_summary(elapsed);
}
