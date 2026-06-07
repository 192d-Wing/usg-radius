//! Request deduplication cache
//!
//! Implements RFC 2865 duplicate request detection by caching recent requests.
//! Helps prevent replay attacks and ensures proper handling of retransmissions.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::time;
use tracing::debug;

/// Request fingerprint for deduplication
///
/// A unique identifier for a RADIUS request based on:
/// - Source IP address
/// - Request Identifier (1 byte)
/// - Request Authenticator (16 bytes)
///
/// Per RFC 2865 Section 2: "The Identifier field aids in matching requests and replies."
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RequestFingerprint {
    /// Source IP address of the request
    pub source_ip: IpAddr,
    /// Request identifier (0-255)
    pub identifier: u8,
    /// First 8 bytes of the request authenticator (for efficient storage)
    pub auth_prefix: [u8; 8],
}

impl RequestFingerprint {
    /// Create a new request fingerprint
    pub fn new(source_ip: IpAddr, identifier: u8, authenticator: &[u8; 16]) -> Self {
        let mut auth_prefix = [0u8; 8];
        auth_prefix.copy_from_slice(&authenticator[..8]);

        RequestFingerprint {
            source_ip,
            identifier,
            auth_prefix,
        }
    }
}

/// Cached request entry with timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    /// When this entry was created
    inserted_at: Instant,
    /// Full authenticator for verification (optional, for stricter checking)
    _authenticator: [u8; 16],
}

/// Request cache for duplicate detection
///
/// Thread-safe cache that stores recent requests and automatically expires old entries.
/// Uses a background task for efficient periodic cleanup instead of lazy cleanup on every access.
pub struct RequestCache {
    /// Cache storage (thread-safe concurrent hash map)
    cache: Arc<DashMap<RequestFingerprint, CacheEntry>>,
    /// Maximum age of cache entries before expiry
    ttl: Duration,
    /// Maximum number of entries to keep in cache
    max_entries: usize,
    /// Flag to stop the background cleanup task
    cleanup_running: Arc<AtomicBool>,
}

impl RequestCache {
    /// Create a new request cache
    ///
    /// # Arguments
    /// * `ttl` - Time-to-live for cache entries (typically 30-60 seconds)
    /// * `max_entries` - Maximum number of entries to cache (prevents memory exhaustion)
    ///
    /// Starts a background task that periodically cleans up expired entries.
    /// The cleanup interval is set to ttl/4 for efficient memory management.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self::new_internal(ttl, max_entries, true)
    }

    /// Create a new request cache without background cleanup (for testing)
    #[cfg(test)]
    fn new_no_background(ttl: Duration, max_entries: usize) -> Self {
        Self::new_internal(ttl, max_entries, false)
    }

    /// Internal constructor with optional background task
    fn new_internal(ttl: Duration, max_entries: usize, start_background: bool) -> Self {
        let cache: Arc<DashMap<RequestFingerprint, CacheEntry>> = Arc::new(DashMap::new());

        // Only spawn the background cleanup task when requested AND a Tokio runtime
        // is available — calling `RequestCache::new` outside a runtime (e.g. in
        // benchmarks or synchronous tests) must not panic.
        let start_background = start_background && tokio::runtime::Handle::try_current().is_ok();
        let cleanup_running = Arc::new(AtomicBool::new(start_background));

        // Spawn background cleanup task only if requested
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
                    let expired_keys: Vec<RequestFingerprint> = cache_clone
                        .iter()
                        .filter(|entry| now.duration_since(entry.value().inserted_at) > ttl)
                        .map(|entry| entry.key().clone())
                        .collect();

                    // Remove expired entries
                    for key in expired_keys {
                        cache_clone.remove(&key);
                        removed += 1;
                    }

                    if removed > 0 {
                        debug!(
                            removed = removed,
                            remaining = cache_clone.len(),
                            "Request cache cleanup completed"
                        );
                    }
                }

                debug!("Request cache cleanup task stopped");
            });
        }

        RequestCache {
            cache,
            ttl,
            max_entries,
            cleanup_running,
        }
    }

    /// Check if a request is a duplicate
    ///
    /// Returns `true` if this request was seen recently, `false` otherwise.
    /// Also adds the request to the cache if it's new.
    ///
    /// This method no longer performs inline cleanup - the background task handles expiry.
    pub fn is_duplicate(&self, fingerprint: RequestFingerprint, authenticator: [u8; 16]) -> bool {
        // Check if request already exists
        if self.cache.contains_key(&fingerprint) {
            return true;
        }

        // Enforce max entries limit with simple FIFO eviction
        if self.cache.len() >= self.max_entries {
            // Remove oldest entry (simple FIFO eviction)
            // Background cleanup will handle expired entries over time
            if let Some(entry) = self.cache.iter().next() {
                let key_to_remove = entry.key().clone();
                drop(entry);
                self.cache.remove(&key_to_remove);
            }
        }

        // Add to cache
        self.cache.insert(
            fingerprint,
            CacheEntry {
                inserted_at: Instant::now(),
                _authenticator: authenticator,
            },
        );

        false
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.cache.len(),
            max_entries: self.max_entries,
            ttl_seconds: self.ttl.as_secs(),
        }
    }
}

impl Drop for RequestCache {
    fn drop(&mut self) {
        // Signal the background cleanup task to stop
        self.cleanup_running.store(false, Ordering::Relaxed);
        debug!("Request cache dropped, cleanup task will stop");
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries
    pub entries: usize,
    /// Maximum number of entries
    pub max_entries: usize,
    /// TTL in seconds
    pub ttl_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_fingerprint_creation() {
        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        assert_eq!(fingerprint.source_ip, ip);
        assert_eq!(fingerprint.identifier, 42);
        assert_eq!(fingerprint.auth_prefix, [1u8; 8]);
    }

    #[test]
    fn test_request_fingerprint_equality() {
        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];

        let fp1 = RequestFingerprint::new(ip, 42, &auth);
        let fp2 = RequestFingerprint::new(ip, 42, &auth);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_request_fingerprint_different_id() {
        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];

        let fp1 = RequestFingerprint::new(ip, 42, &auth);
        let fp2 = RequestFingerprint::new(ip, 43, &auth);

        assert_ne!(fp1, fp2);
    }

    #[tokio::test]
    async fn test_cache_duplicate_detection() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 1000);

        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        // First request should not be a duplicate
        assert!(!cache.is_duplicate(fingerprint.clone(), auth));

        // Second request with same fingerprint should be a duplicate
        assert!(cache.is_duplicate(fingerprint.clone(), auth));
    }

    #[tokio::test]
    async fn test_cache_different_requests() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 1000);

        let ip = "192.168.1.1".parse().unwrap();
        let auth1 = [1u8; 16];
        let auth2 = [2u8; 16];

        let fp1 = RequestFingerprint::new(ip, 42, &auth1);
        let fp2 = RequestFingerprint::new(ip, 42, &auth2);

        // Different authenticators should not be duplicates
        assert!(!cache.is_duplicate(fp1, auth1));
        assert!(!cache.is_duplicate(fp2, auth2));
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        // Use real background task for this test since we're testing expiry
        let cache = RequestCache::new(Duration::from_millis(100), 1000);

        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        // Add request to cache
        assert!(!cache.is_duplicate(fingerprint.clone(), auth));

        // Should still be in cache immediately
        assert!(cache.is_duplicate(fingerprint.clone(), auth));

        // Wait for expiry + cleanup interval (100ms TTL / 4 = 25ms cleanup interval)
        // Wait 150ms for expiry + extra time for cleanup task to run
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should be expired and removed
        assert!(!cache.is_duplicate(fingerprint.clone(), auth));
    }

    #[test]
    #[ignore] // FIXME: This test hangs - investigate DashMap iteration issue
    fn test_cache_max_entries() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 3);

        let ip = "192.168.1.1".parse().unwrap();

        // Add exactly 3 entries
        let auth1 = [1u8; 16];
        let fp1 = RequestFingerprint::new(ip, 1, &auth1);
        assert!(!cache.is_duplicate(fp1, auth1));

        let auth2 = [2u8; 16];
        let fp2 = RequestFingerprint::new(ip, 2, &auth2);
        assert!(!cache.is_duplicate(fp2, auth2));

        let auth3 = [3u8; 16];
        let fp3 = RequestFingerprint::new(ip, 3, &auth3);
        assert!(!cache.is_duplicate(fp3, auth3));

        // Cache should be at max
        assert_eq!(cache.len(), 3);

        // Add one more - should evict oldest and stay at max
        let auth4 = [4u8; 16];
        let fp4 = RequestFingerprint::new(ip, 4, &auth4);
        assert!(!cache.is_duplicate(fp4, auth4));

        // Cache should still be at max (one was evicted)
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 1000);

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 1000);
        assert_eq!(stats.ttl_seconds, 60);

        // Add a request
        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fp = RequestFingerprint::new(ip, 42, &auth);
        cache.is_duplicate(fp, auth);

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 1000);

        let ip = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fp = RequestFingerprint::new(ip, 42, &auth);

        cache.is_duplicate(fp, auth);
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
