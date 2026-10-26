//! CRL caching with TTL
//!
//! This module provides efficient caching of CRLs with time-to-live (TTL)
//! to avoid repeated HTTP fetches and parsing overhead.
//!
//! # Overview
//!
//! The cache uses DashMap for thread-safe concurrent access without locks.
//! Each cached CRL has:
//!
//! - **TTL (Time-To-Live)**: Configurable expiration time
//! - **Cached timestamp**: When the CRL was cached
//! - **LRU eviction**: When cache is full, oldest entries are evicted
//!
//! # Thread Safety
//!
//! The cache is fully thread-safe and can be shared across multiple threads
//! without additional synchronization. DashMap provides lock-free reads and
//! fine-grained write locking.
//!
//! # Example
//!
//! (`ignore`: this module is crate-private; the example is illustrative)
//! ```ignore
//! use radius_proto::revocation::cache::CrlCache;
//! use std::time::Duration;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create cache with max 100 entries
//! let cache = CrlCache::new(100);
//!
//! // Cache is wrapped in Arc for sharing across threads
//! let cache_clone = Arc::clone(&cache);
//!
//! // Get cached CRL (returns None if expired or not present)
//! if let Some(crl_info) = cache.get("http://ca.example.com/crl.der") {
//!     println!("Found cached CRL: {}", crl_info.issuer);
//! }
//! # Ok(())
//! # }
//! ```

#![allow(dead_code)] // Cache helpers are staged for future integration

use super::crl::CrlInfo;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// CRL cache entry with TTL metadata
#[derive(Debug, Clone)]
struct CachedCrl {
    /// Parsed CRL information
    crl_info: CrlInfo,

    /// Time when this CRL was cached
    cached_at: Instant,

    /// Time-to-live for this cache entry
    ttl: Duration,
}

impl CachedCrl {
    /// Check if this cache entry has expired
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// Thread-safe CRL cache with TTL and LRU eviction
///
/// This cache provides:
/// - Thread-safe concurrent access via DashMap
/// - TTL-based automatic expiration
/// - LRU eviction when max_entries is reached
/// - O(1) lookups, inserts, and removals
///
/// # Example
///
/// (`ignore`: this module is crate-private; the example is illustrative)
/// ```ignore
/// use radius_proto::revocation::cache::CrlCache;
/// use std::time::Duration;
///
/// let cache = CrlCache::new(100);
///
/// // Insert is handled by CrlFetcher, but you can also insert manually
/// // cache.insert("http://ca.example.com/crl.der", crl_info, Duration::from_secs(3600));
///
/// // Get cached CRL
/// if let Some(crl) = cache.get("http://ca.example.com/crl.der") {
///     println!("Cache hit!");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CrlCache {
    /// The actual cache storage (URL -> CachedCrl)
    cache: Arc<DashMap<String, CachedCrl>>,

    /// Maximum number of cache entries
    max_entries: usize,
}

impl CrlCache {
    /// Create a new CRL cache
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of CRLs to cache (LRU eviction when full)
    ///
    /// # Returns
    ///
    /// Arc-wrapped cache ready for sharing across threads
    pub fn new(max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            cache: Arc::new(DashMap::new()),
            max_entries,
        })
    }

    /// Get a CRL from cache by distribution point URL
    ///
    /// Returns `None` if:
    /// - CRL not in cache
    /// - CRL has expired (TTL exceeded)
    ///
    /// # Arguments
    ///
    /// * `url` - CRL distribution point URL
    ///
    /// # Returns
    ///
    /// * `Some(CrlInfo)` - Cached CRL (not expired)
    /// * `None` - Not cached or expired
    pub fn get(&self, url: &str) -> Option<CrlInfo> {
        // Get entry from cache
        let entry = self.cache.get(url)?;

        // Check if expired
        if entry.is_expired() {
            // Drop the read lock before removing
            drop(entry);
            // Remove expired entry
            self.cache.remove(url);
            return None;
        }

        // Return cloned CrlInfo
        Some(entry.crl_info.clone())
    }

    /// Insert a CRL into the cache
    ///
    /// If the cache is at max capacity, the oldest entry will be evicted
    /// to make room for the new entry.
    ///
    /// # Arguments
    ///
    /// * `url` - CRL distribution point URL (cache key)
    /// * `crl_info` - Parsed CRL information
    /// * `ttl` - Time-to-live for this cache entry
    pub fn insert(&self, url: String, crl_info: CrlInfo, ttl: Duration) {
        // If cache is at capacity, evict oldest entry
        if self.cache.len() >= self.max_entries {
            self.evict_oldest();
        }

        // Insert new entry
        let entry = CachedCrl {
            crl_info,
            cached_at: Instant::now(),
            ttl,
        };

        self.cache.insert(url, entry);
    }

    /// Remove expired entries from the cache
    ///
    /// This method scans the entire cache and removes expired entries.
    /// It's useful for periodic cleanup, though expired entries are also
    /// removed lazily during `get()` operations.
    pub fn cleanup_expired(&self) {
        // Collect expired URLs
        let expired_urls: Vec<String> = self
            .cache
            .iter()
            .filter_map(|entry| {
                if entry.value().is_expired() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        for url in expired_urls {
            self.cache.remove(&url);
        }
    }

    /// Clear all cache entries
    ///
    /// Useful for testing or forcing a cache refresh.
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get the current number of cached CRLs
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Evict the oldest cache entry (LRU eviction)
    ///
    /// This finds the entry with the oldest `cached_at` timestamp
    /// and removes it to make room for new entries.
    fn evict_oldest(&self) {
        // Find the oldest entry
        let oldest_url = self
            .cache
            .iter()
            .min_by_key(|entry| entry.value().cached_at)
            .map(|entry| entry.key().clone());

        // Remove it
        if let Some(url) = oldest_url {
            self.cache.remove(&url);
        }
    }

    /// Get cache statistics (for monitoring/debugging)
    ///
    /// Returns tuple of (total_entries, expired_entries)
    pub fn stats(&self) -> (usize, usize) {
        let total = self.cache.len();
        let expired = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired())
            .count();

        (total, expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashSet;
    use std::thread;
    use std::time::Duration;

    // Helper to create a test CrlInfo
    fn create_test_crl(issuer: &str) -> CrlInfo {
        CrlInfo {
            issuer: issuer.to_string(),
            this_update: Utc::now(),
            next_update: Some(Utc::now() + chrono::Duration::days(7)),
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(1),
        }
    }

    #[test]
    fn test_cache_new() {
        let cache = CrlCache::new(100);
        assert_eq!(cache.max_entries, 100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = CrlCache::new(10);
        let crl = create_test_crl("CN=Test CA");
        let url = "http://ca.example.com/crl.der";

        // Insert CRL with 1 hour TTL
        cache.insert(url.to_string(), crl.clone(), Duration::from_secs(3600));

        // Should be retrievable
        let cached = cache.get(url);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().issuer, "CN=Test CA");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_get_nonexistent() {
        let cache = CrlCache::new(10);
        assert!(cache.get("http://nonexistent.com/crl.der").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = CrlCache::new(10);
        let crl = create_test_crl("CN=Test CA");
        let url = "http://ca.example.com/crl.der";

        // Insert CRL with very short TTL (1 millisecond)
        cache.insert(url.to_string(), crl, Duration::from_millis(1));

        // Wait for expiration
        thread::sleep(Duration::from_millis(10));

        // Should be None (expired)
        assert!(cache.get(url).is_none());

        // Cache should have auto-removed the expired entry
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_update() {
        let cache = CrlCache::new(10);
        let url = "http://ca.example.com/crl.der";

        // Insert first version
        let crl1 = create_test_crl("CN=Test CA v1");
        cache.insert(url.to_string(), crl1, Duration::from_secs(3600));

        // Update with second version
        let crl2 = create_test_crl("CN=Test CA v2");
        cache.insert(url.to_string(), crl2, Duration::from_secs(3600));

        // Should get the updated version
        let cached = cache.get(url).unwrap();
        assert_eq!(cached.issuer, "CN=Test CA v2");
        assert_eq!(cache.len(), 1); // Still only one entry
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = CrlCache::new(3); // Max 3 entries

        // Insert 3 CRLs
        cache.insert(
            "http://ca1.com/crl.der".to_string(),
            create_test_crl("CA1"),
            Duration::from_secs(3600),
        );
        thread::sleep(Duration::from_millis(10)); // Ensure different timestamps

        cache.insert(
            "http://ca2.com/crl.der".to_string(),
            create_test_crl("CA2"),
            Duration::from_secs(3600),
        );
        thread::sleep(Duration::from_millis(10));

        cache.insert(
            "http://ca3.com/crl.der".to_string(),
            create_test_crl("CA3"),
            Duration::from_secs(3600),
        );

        assert_eq!(cache.len(), 3);

        // Insert 4th CRL - should evict CA1 (oldest)
        cache.insert(
            "http://ca4.com/crl.der".to_string(),
            create_test_crl("CA4"),
            Duration::from_secs(3600),
        );

        assert_eq!(cache.len(), 3);
        assert!(cache.get("http://ca1.com/crl.der").is_none()); // Evicted
        assert!(cache.get("http://ca2.com/crl.der").is_some());
        assert!(cache.get("http://ca3.com/crl.der").is_some());
        assert!(cache.get("http://ca4.com/crl.der").is_some());
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let cache = CrlCache::new(10);

        // Insert CRLs with different TTLs
        cache.insert(
            "http://short-ttl.com/crl.der".to_string(),
            create_test_crl("Short TTL"),
            Duration::from_millis(1),
        );

        cache.insert(
            "http://long-ttl.com/crl.der".to_string(),
            create_test_crl("Long TTL"),
            Duration::from_secs(3600),
        );

        assert_eq!(cache.len(), 2);

        // Wait for short TTL to expire
        thread::sleep(Duration::from_millis(10));

        // Check stats before cleanup
        let (total, expired) = cache.stats();
        assert_eq!(total, 2);
        assert_eq!(expired, 1);

        // Run cleanup
        cache.cleanup_expired();

        // Should have removed expired entry
        assert_eq!(cache.len(), 1);
        assert!(cache.get("http://short-ttl.com/crl.der").is_none());
        assert!(cache.get("http://long-ttl.com/crl.der").is_some());
    }

    #[test]
    fn test_cache_clear() {
        let cache = CrlCache::new(10);

        // Insert multiple CRLs
        for i in 0..5 {
            cache.insert(
                format!("http://ca{}.com/crl.der", i),
                create_test_crl(&format!("CA{}", i)),
                Duration::from_secs(3600),
            );
        }

        assert_eq!(cache.len(), 5);

        // Clear cache
        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_thread_safety() {
        let cache = CrlCache::new(100);
        let cache_clone = Arc::clone(&cache);

        // Spawn multiple threads that insert and read
        let mut handles = vec![];

        for i in 0..10 {
            let cache_ref = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                let url = format!("http://ca{}.com/crl.der", i);
                cache_ref.insert(
                    url.clone(),
                    create_test_crl(&format!("CA{}", i)),
                    Duration::from_secs(3600),
                );

                // Read it back
                assert!(cache_ref.get(&url).is_some());
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All entries should be present
        assert_eq!(cache_clone.len(), 10);
    }

    #[test]
    fn test_cache_stats() {
        let cache = CrlCache::new(10);

        // Insert mix of short and long TTL entries
        cache.insert(
            "http://expired.com/crl.der".to_string(),
            create_test_crl("Expired"),
            Duration::from_millis(1),
        );

        cache.insert(
            "http://valid.com/crl.der".to_string(),
            create_test_crl("Valid"),
            Duration::from_secs(3600),
        );

        // Wait for expiration
        thread::sleep(Duration::from_millis(10));

        let (total, expired) = cache.stats();
        assert_eq!(total, 2);
        assert_eq!(expired, 1);
    }
}
