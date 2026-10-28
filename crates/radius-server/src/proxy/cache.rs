//! Proxy cache for request/response correlation
//!
//! Tracks in-flight proxied requests using Proxy-State attributes for correlation.
//! Similar to RequestCache but designed specifically for proxy operations.

use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::home_server::HomeServer;
use dashmap::DashMap;
use radius_proto::Packet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::time;
use tracing::debug;

/// Proxy-State key for correlation (16 bytes)
pub type ProxyStateKey = [u8; 16];

/// Generate a unique Proxy-State key
pub fn generate_proxy_state_key() -> ProxyStateKey {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&now.to_be_bytes());
    key[8..16].copy_from_slice(&counter.to_be_bytes());
    key
}

/// Proxy cache entry
#[derive(Clone)]
pub struct ProxyCacheEntry {
    /// The request as forwarded to the home server: the NAS's packet with our
    /// Proxy-State appended and User-Password / Message-Authenticator re-keyed
    /// for the home server secret (see `rewrite_request_for_home_server`). Its
    /// Request Authenticator is the NAS's, unchanged, so the response leg can
    /// use it for both hops. Retries resend this packet as is.
    pub original_request: Packet,
    /// Original source address (NAS)
    pub original_source: SocketAddr,
    /// Home server this request was sent to
    pub home_server: Arc<HomeServer>,
    /// When the request was sent
    pub sent_at: Instant,
    /// Number of retry attempts
    pub retry_count: u8,
    /// Proxy-State key for correlation
    pub proxy_state: ProxyStateKey,
    /// Client secret for response authentication
    pub client_secret: Vec<u8>,
}

/// Proxy cache for tracking in-flight requests
///
/// Thread-safe cache that stores proxied requests and correlates responses
/// using Proxy-State attributes. Automatically expires old entries via background task.
pub struct ProxyCache {
    /// Cache storage (Proxy-State → Entry)
    cache: Arc<DashMap<ProxyStateKey, ProxyCacheEntry>>,
    /// Maximum age of cache entries before expiry
    ttl: Duration,
    /// Maximum number of entries
    max_entries: usize,
    /// Flag to stop background cleanup task
    cleanup_running: Arc<AtomicBool>,
}

impl ProxyCache {
    /// Create a new proxy cache
    ///
    /// # Arguments
    /// * `ttl` - Time-to-live for cache entries (typically 30-60 seconds)
    /// * `max_entries` - Maximum number of in-flight requests (prevents memory exhaustion)
    ///
    /// Starts a background task that periodically cleans up expired entries.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self::new_internal(ttl, max_entries, true)
    }

    /// Create a new proxy cache without background cleanup (for testing)
    #[cfg(test)]
    pub fn new_no_background(ttl: Duration, max_entries: usize) -> Self {
        Self::new_internal(ttl, max_entries, false)
    }

    /// Internal constructor with optional background task
    fn new_internal(ttl: Duration, max_entries: usize, start_background: bool) -> Self {
        let cache: Arc<DashMap<ProxyStateKey, ProxyCacheEntry>> = Arc::new(DashMap::new());
        let cleanup_running = Arc::new(AtomicBool::new(start_background));

        // Spawn background cleanup task
        if start_background {
            let cache_clone = Arc::clone(&cache);
            let cleanup_flag = Arc::clone(&cleanup_running);
            let cleanup_interval = ttl / 4; // Run cleanup 4x per TTL period

            tokio::spawn(async move {
                let mut interval = time::interval(cleanup_interval);
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

                while cleanup_flag.load(Ordering::Relaxed) {
                    interval.tick().await;

                    let now = Instant::now();
                    let mut removed = 0;

                    // Collect expired keys
                    let expired_keys: Vec<ProxyStateKey> = cache_clone
                        .iter()
                        .filter(|entry| now.duration_since(entry.value().sent_at) > ttl)
                        .map(|entry| *entry.key())
                        .collect();

                    // Remove expired entries
                    for key in expired_keys {
                        if let Some((_, entry)) = cache_clone.remove(&key) {
                            // Record timeout in home server stats
                            entry.home_server.stats().record_timeout();
                            removed += 1;
                        }
                    }

                    if removed > 0 {
                        debug!(
                            removed = removed,
                            remaining = cache_clone.len(),
                            "Proxy cache cleanup completed (timeouts recorded)"
                        );
                    }
                }

                debug!("Proxy cache cleanup task stopped");
            });
        }

        ProxyCache {
            cache,
            ttl,
            max_entries,
            cleanup_running,
        }
    }

    /// Insert a new entry into the cache, or replace the entry with the same
    /// Proxy-State (the retry manager re-inserts timed-out entries).
    ///
    /// Returns error if cache is full (at max capacity) and the entry is new.
    pub fn insert(&self, entry: ProxyCacheEntry) -> ProxyResult<()> {
        // Check capacity (a replacement does not grow the cache)
        if self.cache.len() >= self.max_entries && !self.cache.contains_key(&entry.proxy_state) {
            return Err(ProxyError::CacheFull(self.cache.len()));
        }

        self.cache.insert(entry.proxy_state, entry);
        Ok(())
    }

    /// Lookup and remove an entry by Proxy-State key
    ///
    /// Returns None if not found or expired
    pub fn remove(&self, proxy_state: &ProxyStateKey) -> Option<ProxyCacheEntry> {
        self.cache.remove(proxy_state).map(|(_, entry)| entry)
    }

    /// Lookup an entry without removing it
    pub fn get(&self, proxy_state: &ProxyStateKey) -> Option<ProxyCacheEntry> {
        self.cache.get(proxy_state).map(|entry| entry.clone())
    }

    /// Get all timed-out entries (for retry logic)
    pub fn get_timed_out(&self, timeout: Duration) -> Vec<ProxyCacheEntry> {
        let now = Instant::now();
        self.cache
            .iter()
            .filter(|entry| now.duration_since(entry.value().sent_at) > timeout)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get number of entries in cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> ProxyCacheStats {
        ProxyCacheStats {
            entries: self.cache.len(),
            max_entries: self.max_entries,
            ttl_seconds: self.ttl.as_secs(),
        }
    }
}

impl Drop for ProxyCache {
    fn drop(&mut self) {
        // Signal background cleanup task to stop
        self.cleanup_running.store(false, Ordering::Relaxed);
        debug!("Proxy cache dropped, cleanup task will stop");
    }
}

/// Proxy cache statistics
#[derive(Debug, Clone)]
pub struct ProxyCacheStats {
    /// Current number of in-flight requests
    pub entries: usize,
    /// Maximum capacity
    pub max_entries: usize,
    /// TTL in seconds
    pub ttl_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use radius_proto::Code;

    fn create_test_home_server() -> Arc<HomeServer> {
        let config = HomeServerConfig {
            name: Some("Test Server".to_string()),
            ..HomeServerConfig::udp("192.168.1.1:1812", "test_secret")
        };
        Arc::new(HomeServer::new(config).unwrap())
    }

    fn create_test_packet() -> Packet {
        Packet::new(Code::AccessRequest, 1, [0u8; 16])
    }

    fn create_test_entry(home_server: Arc<HomeServer>) -> ProxyCacheEntry {
        ProxyCacheEntry {
            original_request: create_test_packet(),
            original_source: "192.168.1.100:12345".parse().unwrap(),
            home_server,
            sent_at: Instant::now(),
            retry_count: 0,
            proxy_state: generate_proxy_state_key(),
            client_secret: b"test_secret".to_vec(),
        }
    }

    #[test]
    fn test_generate_proxy_state_key_uniqueness() {
        let key1 = generate_proxy_state_key();
        let key2 = generate_proxy_state_key();
        assert_ne!(key1, key2, "Proxy-State keys should be unique");
    }

    #[tokio::test]
    async fn test_proxy_cache_insert_and_remove() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 1000);
        let home_server = create_test_home_server();
        let entry = create_test_entry(home_server);
        let proxy_state = entry.proxy_state;

        // Insert entry
        assert!(cache.insert(entry.clone()).is_ok());
        assert_eq!(cache.len(), 1);

        // Lookup and remove
        let retrieved = cache.remove(&proxy_state);
        assert!(retrieved.is_some());
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_proxy_cache_get_without_remove() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 1000);
        let home_server = create_test_home_server();
        let entry = create_test_entry(home_server);
        let proxy_state = entry.proxy_state;

        cache.insert(entry.clone()).unwrap();

        // Get without removing
        let retrieved = cache.get(&proxy_state);
        assert!(retrieved.is_some());
        assert_eq!(cache.len(), 1); // Still in cache
    }

    #[tokio::test]
    async fn test_proxy_cache_full() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 2);
        let home_server = create_test_home_server();

        // Fill cache
        assert!(cache.insert(create_test_entry(home_server.clone())).is_ok());
        assert!(cache.insert(create_test_entry(home_server.clone())).is_ok());

        // Try to exceed capacity
        let result = cache.insert(create_test_entry(home_server));
        assert!(result.is_err());
        match result {
            Err(ProxyError::CacheFull(count)) => assert_eq!(count, 2),
            _ => panic!("Expected CacheFull error"),
        }
    }

    #[tokio::test]
    async fn test_proxy_cache_expiry() {
        // Use real background task for this test
        let cache = ProxyCache::new(Duration::from_millis(100), 1000);
        let home_server = create_test_home_server();
        let entry = create_test_entry(home_server);
        let proxy_state = entry.proxy_state;

        cache.insert(entry).unwrap();

        // Should be in cache immediately
        assert!(cache.get(&proxy_state).is_some());

        // Wait for expiry + cleanup
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should be expired and removed
        assert!(cache.get(&proxy_state).is_none());
    }

    #[tokio::test]
    async fn test_proxy_cache_get_timed_out() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 1000);
        let home_server = create_test_home_server();

        // Add entry with modified sent_at (simulating old entry)
        let mut entry = create_test_entry(home_server);
        entry.sent_at = Instant::now() - Duration::from_secs(5);
        cache.insert(entry).unwrap();

        // Get entries timed out after 3 seconds
        let timed_out = cache.get_timed_out(Duration::from_secs(3));
        assert_eq!(timed_out.len(), 1);

        // Get entries timed out after 10 seconds (should be empty)
        let timed_out = cache.get_timed_out(Duration::from_secs(10));
        assert_eq!(timed_out.len(), 0);
    }

    #[tokio::test]
    async fn test_proxy_cache_stats() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 1000);
        let home_server = create_test_home_server();

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 1000);
        assert_eq!(stats.ttl_seconds, 60);

        cache.insert(create_test_entry(home_server)).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn test_proxy_cache_clear() {
        let cache = ProxyCache::new_no_background(Duration::from_secs(60), 1000);
        let home_server = create_test_home_server();

        cache
            .insert(create_test_entry(home_server.clone()))
            .unwrap();
        cache.insert(create_test_entry(home_server)).unwrap();
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
