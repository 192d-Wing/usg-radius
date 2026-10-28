//! Retry and timeout handling
//!
//! This module implements retry logic and timeout detection for proxy requests.
//!
//! ## Retry Strategy
//! - Detects timed-out requests by scanning ProxyCache
//! - Retries with same server or fails over to different server
//! - Sends Access-Reject to NAS after max retries exhausted
//!
//! ## Timeout Monitoring
//! - Background task periodically scans for timed-out requests
//! - Configurable scan interval (default: every 5 seconds)
//! - Removes expired entries and triggers retries

use crate::proxy::cache::{ProxyCache, ProxyCacheEntry};
use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::handler::ProxyHandler;
use crate::proxy::home_server::{HomeServer, HomeServerTransport};
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::calculate_response_authenticator;
use radius_proto::{Code, Packet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    /// Retry interval in seconds (how often to check for timeouts)
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,
    /// Failover to different server on timeout
    #[serde(default = "default_failover_on_timeout")]
    pub failover_on_timeout: bool,
}

fn default_max_retries() -> u8 {
    3
}

fn default_retry_interval() -> u64 {
    5
}

fn default_failover_on_timeout() -> bool {
    true
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_retries: default_max_retries(),
            retry_interval: default_retry_interval(),
            failover_on_timeout: default_failover_on_timeout(),
        }
    }
}

/// Retry manager for timeout and retry orchestration
pub struct RetryManager {
    /// Proxy cache for finding timed-out requests
    cache: Arc<ProxyCache>,
    /// Proxy handler for re-forwarding requests
    handler: Arc<ProxyHandler>,
    /// Retry configuration
    config: RetryConfig,
    /// Request timeout duration
    timeout: Duration,
    /// Running flag for background task
    running: Arc<AtomicBool>,
}

impl RetryManager {
    /// Create a new retry manager
    pub fn new(
        cache: Arc<ProxyCache>,
        handler: Arc<ProxyHandler>,
        config: RetryConfig,
        timeout: Duration,
    ) -> Self {
        RetryManager {
            cache,
            handler,
            config,
            timeout,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start background retry/timeout monitoring task
    ///
    /// This task periodically scans the cache for timed-out requests
    /// and either retries them or sends Access-Reject if max retries exceeded.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let handler = Arc::clone(&self.handler);
        let config = self.config.clone();
        let timeout = self.timeout;
        let running = Arc::clone(&self.running);

        running.store(true, Ordering::Relaxed);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(config.retry_interval));

            info!(
                retry_interval = config.retry_interval,
                max_retries = config.max_retries,
                failover_on_timeout = config.failover_on_timeout,
                timeout_secs = timeout.as_secs(),
                "Retry manager started"
            );

            while running.load(Ordering::Relaxed) {
                interval.tick().await;

                // Get all timed-out entries
                let timed_out = cache.get_timed_out(timeout);

                debug!(
                    timed_out_count = timed_out.len(),
                    "Checking for timed-out requests"
                );

                for entry in timed_out {
                    if let Err(e) = Self::handle_timeout(&cache, &handler, &config, entry).await {
                        warn!(error = %e, "Failed to handle timeout");
                    }
                }
            }

            info!("Retry manager stopped");
        })
    }

    /// Stop the background retry task
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Handle a timed-out request: resend it over the home server's transport
    /// (UDP socket or RadSec link), or reject it to the NAS once `max_retries`
    /// is exhausted.
    ///
    /// The cache entry (bumped `retry_count`, fresh `sent_at`) is written and
    /// the request counted as outstanding **before** the resend, so a failed
    /// send — a RadSec link that is down, a socket error — still counts as an
    /// attempt and the request still reaches the reject after `max_retries`.
    /// (The earlier code returned on the send error before updating the
    /// entry, so a request to an unreachable server was retried forever.)
    async fn handle_timeout(
        cache: &Arc<ProxyCache>,
        handler: &Arc<ProxyHandler>,
        config: &RetryConfig,
        mut entry: ProxyCacheEntry,
    ) -> ProxyResult<()> {
        // Check if max retries exceeded
        if entry.retry_count >= config.max_retries {
            warn!(
                nas = %entry.original_source,
                identifier = entry.original_request.identifier,
                retry_count = entry.retry_count,
                max_retries = config.max_retries,
                "Max retries exceeded, sending Access-Reject"
            );

            // Send Access-Reject to NAS, from the socket it sent to.
            Self::send_reject(&handler.nas_socket(), &entry).await?;

            // Remove from cache
            cache.remove(&entry.proxy_state);

            // Record timeout in home server stats
            entry.home_server.stats().record_timeout();

            return Ok(());
        }

        // Increment retry count
        entry.retry_count += 1;

        info!(
            nas = %entry.original_source,
            identifier = entry.original_request.identifier,
            retry_count = entry.retry_count,
            home_server = %entry.home_server.name,
            "Retrying timed-out request"
        );

        // Determine if we should failover to a different server
        let home_server = if config.failover_on_timeout {
            // Try to select a different server from the pool
            // For now, use the same server (pool selection would need pool reference)
            // This is a limitation - full failover requires Router integration
            entry.home_server.clone()
        } else {
            entry.home_server.clone()
        };

        // Record timeout for old server
        entry.home_server.stats().record_timeout();

        // RFC 6613 §2.6.1: "Clients MUST NOT retransmit RADIUS request packets
        // over a given TCP connection"; a request on a connection that was
        // broken or closed MAY go out over a new one. Over UDP every retry is
        // a retransmission. Over RadSec the request is written again only
        // when the link is down (the send then fails fast and the entry just
        // waits) or when it is on a different connection from the one the
        // request was last written on; otherwise the deadline keeps running
        // and the Access-Reject follows after `max_retries` as before.
        let resend = Self::may_resend(&home_server, entry.sent_on_connection);

        // Update entry with new home server and timestamp, and re-insert it
        // before the resend (see the method docs).
        entry.home_server = home_server.clone();
        entry.sent_at = std::time::Instant::now();
        if resend {
            entry.sent_on_connection = home_server.link_generation();
        }
        let request_data = entry.original_request.encode()?;
        cache.insert(entry)?;

        // In the cache ⇒ in flight, whatever the send below does (and
        // whether or not it happens): balances the `record_timeout` above.
        home_server.stats().record_request();

        if !resend {
            debug!(
                home_server = %home_server.name,
                "not retransmitting over the same RadSec connection (RFC 6613 §2.6.1)"
            );
            return Ok(());
        }

        // Re-forward the request (keeping the same Proxy-State; it is already
        // in the packet, as is the re-keying for the home server secret).
        if let Err(e) = handler
            .send_to_home_server(&request_data, &home_server)
            .await
        {
            debug!(
                home_server = %home_server.name,
                error = %e,
                "Resend failed; the request will time out again"
            );
        }

        Ok(())
    }

    /// Whether a timed-out request to `home_server`, last written on link
    /// connection `sent_on`, may be written again now (RFC 6613 §2.6.1): always
    /// over UDP; over RadSec only when the link is down or has moved to a new
    /// connection since.
    fn may_resend(home_server: &HomeServer, sent_on: Option<u64>) -> bool {
        match home_server.transport() {
            HomeServerTransport::Udp => true,
            HomeServerTransport::Radsec => {
                #[cfg(feature = "tls")]
                {
                    match home_server.link() {
                        // No link: the send fails with `LinkDown`, as today.
                        None => true,
                        Some(link) => !link.is_connected() || Some(link.connections()) != sent_on,
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = sent_on;
                    true
                }
            }
        }
    }

    /// Send Access-Reject to NAS
    async fn send_reject(socket: &Arc<UdpSocket>, entry: &ProxyCacheEntry) -> ProxyResult<()> {
        let mut reject = Packet::new(
            Code::AccessReject,
            entry.original_request.identifier,
            entry.original_request.authenticator,
        );

        // Add Reply-Message explaining timeout
        reject.add_attribute(
            Attribute::string(
                AttributeType::ReplyMessage as u8,
                "Request timed out after maximum retries",
            )
            .map_err(|e| {
                ProxyError::Configuration(format!("Failed to create Reply-Message: {}", e))
            })?,
        );

        // Sign under the NAS's shared secret: the NAS verifies the Response
        // Authenticator with the secret it shares with us, so a reject signed
        // with anything else is silently discarded and the NAS keeps waiting.
        let response_auth = calculate_response_authenticator(
            &reject,
            &entry.original_request.authenticator,
            &entry.client_secret,
        );
        reject.authenticator = response_auth;

        // Send to NAS
        let reject_data = reject.encode()?;
        socket.send_to(&reject_data, entry.original_source).await?;

        info!(
            nas = %entry.original_source,
            identifier = entry.original_request.identifier,
            "Sent Access-Reject due to timeout"
        );

        Ok(())
    }
}

impl Drop for RetryManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use radius_proto::auth::verify_response_authenticator;
    use std::net::SocketAddr;
    use std::time::Instant;

    const CLIENT_SECRET: &[u8] = b"test_secret";
    const REQUEST_AUTH: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    fn create_test_config() -> RetryConfig {
        RetryConfig {
            max_retries: 2,
            retry_interval: 1, // 1 second for faster tests
            failover_on_timeout: true,
        }
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_interval, 5);
        assert!(config.failover_on_timeout);
    }

    #[test]
    fn test_retry_config_serialization() {
        let config = create_test_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RetryConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.max_retries, config.max_retries);
        assert_eq!(deserialized.retry_interval, config.retry_interval);
        assert_eq!(deserialized.failover_on_timeout, config.failover_on_timeout);
    }

    #[tokio::test]
    async fn test_retry_manager_creation() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(30), 100));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let config = create_test_config();
        let timeout = Duration::from_secs(30);

        let manager = RetryManager::new(cache, Arc::new(handler), config, timeout);
        assert_eq!(manager.config.max_retries, 2);
        assert_eq!(manager.config.retry_interval, 1);
        assert_eq!(manager.timeout, timeout);
    }

    #[tokio::test]
    async fn test_retry_manager_start_stop() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(30), 100));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let config = create_test_config();
        let timeout = Duration::from_secs(30);

        let manager = RetryManager::new(cache, Arc::new(handler), config, timeout);

        // Start background task
        let handle = manager.start();
        assert!(manager.running.load(Ordering::Relaxed));

        // Give it a moment to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop it
        manager.stop();
        assert!(!manager.running.load(Ordering::Relaxed));

        // Wait for task to finish
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// Cache entry for a request the proxy forwarded on behalf of `source`,
    /// authenticated by `REQUEST_AUTH` under `CLIENT_SECRET`.
    fn create_test_entry(source: SocketAddr) -> ProxyCacheEntry {
        let config = HomeServerConfig {
            name: Some("Test Server".to_string()),
            ..HomeServerConfig::udp("127.0.0.1:11812", "home_secret")
        };
        entry_for(source, Arc::new(HomeServer::new(config).unwrap()))
    }

    fn entry_for(source: SocketAddr, home_server: Arc<HomeServer>) -> ProxyCacheEntry {
        let mut request = Packet::new(Code::AccessRequest, 7, REQUEST_AUTH);
        request
            .add_attribute(Attribute::string(AttributeType::UserName as u8, "testuser").unwrap());
        ProxyCacheEntry {
            original_request: request,
            original_source: source,
            home_server,
            sent_at: Instant::now(),
            retry_count: 0,
            proxy_state: [0x50; 16],
            client_secret: CLIENT_SECRET.to_vec(),
            sent_on_connection: None,
        }
    }

    /// Drive `handle_timeout` for `entry`'s home server until the NAS gets its
    /// Access-Reject: `max_retries` resends (each of which fails, since nothing
    /// answers at `home_server`) and then the reject. Checks the counters at
    /// every step and returns the reject the NAS received.
    async fn retry_to_exhaustion(home_server: Arc<HomeServer>, max_retries: u8) -> Packet {
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 100));
        let handler = Arc::new(
            ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let config = RetryConfig {
            max_retries,
            retry_interval: 1,
            failover_on_timeout: true,
        };

        // As forward_request leaves it: cached and counted once.
        let entry = entry_for(nas.local_addr().unwrap(), Arc::clone(&home_server));
        let proxy_state = entry.proxy_state;
        cache.insert(entry).unwrap();
        home_server.stats().record_request();
        assert_eq!(home_server.stats().outstanding(), 1);

        for expected_retry in 1..=max_retries {
            let entry = cache.get(&proxy_state).expect("entry still cached");
            RetryManager::handle_timeout(&cache, &handler, &config, entry)
                .await
                .unwrap();
            let entry = cache.get(&proxy_state).expect("entry re-inserted");
            assert_eq!(
                entry.retry_count, expected_retry,
                "retry_count must advance even though the resend failed"
            );
            assert_eq!(
                home_server.stats().outstanding(),
                1,
                "one request in flight throughout"
            );
            assert_eq!(home_server.stats().timeouts(), expected_retry as u64);
        }

        // One more timeout: max_retries reached ⇒ reject, entry gone.
        let entry = cache.get(&proxy_state).unwrap();
        RetryManager::handle_timeout(&cache, &handler, &config, entry)
            .await
            .unwrap();
        assert!(cache.get(&proxy_state).is_none(), "entry removed");
        assert_eq!(home_server.stats().outstanding(), 0, "gauge back to zero");
        assert_eq!(home_server.stats().timeouts(), max_retries as u64 + 1);

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), nas.recv_from(&mut buf))
            .await
            .expect("reject within 5s")
            .unwrap();
        Packet::decode(&buf[..len]).unwrap()
    }

    #[tokio::test]
    async fn failed_udp_resend_still_counts_as_a_retry_and_ends_in_a_reject() {
        // An IPv6 home server behind an IPv4 upstream socket: every send_to
        // fails synchronously, the way an unroutable address does. Before the
        // fix the error returned before the entry was updated, so
        // retry_count never advanced and the request was retried forever.
        let home_server = Arc::new(
            HomeServer::new(HomeServerConfig {
                name: Some("unroutable".to_string()),
                ..HomeServerConfig::udp("[::1]:1812", "home_secret")
            })
            .unwrap(),
        );
        let reject = retry_to_exhaustion(home_server, 2).await;
        assert_eq!(reject.code, Code::AccessReject);
        assert_eq!(reject.identifier, 7);
        assert!(verify_response_authenticator(
            &reject,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn timed_out_request_on_a_down_radsec_link_ends_in_a_signed_reject() {
        use crate::proxy::home_server::HomeServerTlsConfig;

        // A RadSec home server with no link attached: every resend is
        // `LinkDown`, nothing is queued, and after max_retries the NAS gets
        // an Access-Reject signed with its own secret.
        let home_server = Arc::new(
            HomeServer::new(HomeServerConfig {
                name: Some("home-radsec".to_string()),
                ..HomeServerConfig::radsec(
                    "127.0.0.1:12083",
                    HomeServerTlsConfig {
                        ca_path: "/nonexistent/ca.pem".to_string(),
                        cert_path: "/nonexistent/proxy.pem".to_string(),
                        key_path: "/nonexistent/proxy.key".to_string(),
                        server_name: "home.test".to_string(),
                        revocation: None,
                    },
                )
            })
            .unwrap(),
        );
        let reject = retry_to_exhaustion(home_server, 3).await;
        assert_eq!(reject.code, Code::AccessReject);
        assert_eq!(reject.identifier, 7);
        assert!(
            verify_response_authenticator(&reject, &REQUEST_AUTH, CLIENT_SECRET),
            "reject must verify under the NAS's shared secret"
        );
        assert!(!verify_response_authenticator(
            &reject,
            &REQUEST_AUTH,
            b"radsec"
        ));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn timed_out_request_is_not_retransmitted_over_the_same_radsec_connection() {
        // RFC 6613 §2.6.1: a request MUST NOT be retransmitted over the TCP
        // connection it was sent on, and MAY be sent over a new one. The fake
        // home server counts the frames it receives and never answers.
        use crate::proxy::home_server::HomeServerTlsConfig;
        use crate::proxy::radsec_client::{LinkParams, spawn_link};
        use crate::test_pki::{FakeAction, gen_chain, spawn_fake_tls_home};
        use std::sync::atomic::AtomicUsize;

        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let frames = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&frames);
        let addr = spawn_fake_tls_home(&chain, move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            FakeAction::Reply(vec![])
        })
        .await;
        let home_server = Arc::new(
            HomeServer::new(HomeServerConfig {
                name: Some("home-radsec".to_string()),
                timeout: 2,
                ..HomeServerConfig::radsec(
                    addr.to_string(),
                    HomeServerTlsConfig {
                        ca_path: paths.ca.clone(),
                        cert_path: paths.client_cert.clone(),
                        key_path: paths.client_key.clone(),
                        server_name: "localhost".to_string(),
                        revocation: None,
                    },
                )
            })
            .unwrap(),
        );
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let params = LinkParams {
            connect_timeout: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(40),
            max_backoff: Duration::from_millis(160),
            ..LinkParams::default()
        };
        let link = spawn_link(Arc::clone(&home_server), tx, params).unwrap();
        home_server.attach_link(link.clone());
        async fn wait_for(mut cond: impl FnMut() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cond() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        wait_for(|| link.is_connected()).await;
        assert_eq!(link.connections(), 1);

        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 100));
        let handler = Arc::new(
            ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let config = RetryConfig {
            max_retries: 5,
            retry_interval: 1,
            failover_on_timeout: true,
        };

        // As forward_request left it: written on connection 1, cached, counted.
        let mut entry = entry_for(nas.local_addr().unwrap(), Arc::clone(&home_server));
        entry.sent_on_connection = Some(link.connections());
        let proxy_state = entry.proxy_state;
        cache.insert(entry).unwrap();
        home_server.stats().record_request();

        // Timed out on the same connection: the attempt is counted, nothing
        // is written.
        let entry = cache.get(&proxy_state).unwrap();
        RetryManager::handle_timeout(&cache, &handler, &config, entry)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            frames.load(Ordering::SeqCst),
            0,
            "no retransmission over the connection the request went out on"
        );
        let entry = cache.get(&proxy_state).expect("entry re-inserted");
        assert_eq!(entry.retry_count, 1);
        assert_eq!(entry.sent_on_connection, Some(1));
        assert_eq!(home_server.stats().outstanding(), 1);

        // The link moves to a new connection: the next timeout resends once.
        link.reset("test");
        wait_for(|| link.connections() == 2 && link.is_connected()).await;
        assert_eq!(link.connections(), 2);
        RetryManager::handle_timeout(&cache, &handler, &config, entry)
            .await
            .unwrap();
        wait_for(|| frames.load(Ordering::SeqCst) == 1).await;
        assert_eq!(
            frames.load(Ordering::SeqCst),
            1,
            "resent on the new connection"
        );
        let entry = cache.get(&proxy_state).unwrap();
        assert_eq!(entry.retry_count, 2);
        assert_eq!(entry.sent_on_connection, Some(2));

        // And not again while the link stays on connection 2.
        RetryManager::handle_timeout(&cache, &handler, &config, entry)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(frames.load(Ordering::SeqCst), 1);
        assert_eq!(cache.get(&proxy_state).unwrap().retry_count, 3);
        assert_eq!(home_server.stats().outstanding(), 1);
    }

    #[tokio::test]
    async fn send_reject_signs_with_client_secret() {
        // A loopback socket stands in for the NAS.
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let nas_addr = nas.local_addr().unwrap();
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let entry = create_test_entry(nas_addr);

        RetryManager::send_reject(&proxy, &entry).await.unwrap();

        let mut buf = [0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), nas.recv_from(&mut buf))
            .await
            .expect("reject within 5s")
            .unwrap();
        assert_eq!(from, proxy.local_addr().unwrap());
        let reject = Packet::decode(&buf[..len]).unwrap();

        assert_eq!(reject.code, Code::AccessReject);
        assert_eq!(reject.identifier, 7);
        assert!(
            verify_response_authenticator(&reject, &REQUEST_AUTH, CLIENT_SECRET),
            "reject must verify under the NAS's shared secret"
        );
        assert!(
            !verify_response_authenticator(&reject, &REQUEST_AUTH, b""),
            "reject must not be signed with an empty secret"
        );
    }
}
