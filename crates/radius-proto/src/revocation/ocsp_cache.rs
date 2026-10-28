//! OCSP response caching with TTL
//!
//! This module provides efficient caching of OCSP responses with time-to-live (TTL)
//! to avoid repeated HTTP requests to OCSP responders.
//!
//! # Overview
//!
//! The cache uses DashMap for thread-safe concurrent access without locks.
//! Each cached OCSP response has:
//!
//! - **TTL (Time-To-Live)**: Based on nextUpdate or configurable default
//! - **Cached timestamp**: When the response was cached
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
//! ```no_run
//! use radius_proto::revocation::ocsp_cache::OcspCache;
//! use std::time::Duration;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create cache with max 100 entries
//! let cache = OcspCache::new(100);
//!
//! // Cache is wrapped in Arc for sharing across threads
//! let cache_clone = Arc::clone(&cache);
//!
//! // Get cached OCSP response (returns None if expired or not present)
//! if let Some(response) = cache.get(b"certificate_serial_number") {
//!     println!("Found cached OCSP response");
//! }
//! # Ok(())
//! # }
//! ```

use super::ocsp::OcspResponse;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// OCSP response cache entry with TTL metadata
#[derive(Debug, Clone)]
struct CachedOcspResponse {
    /// Parsed OCSP response
    response: OcspResponse,

    /// Time when this response was cached
    cached_at: Instant,

    /// Time-to-live for this cache entry
    ttl: Duration,
}

impl CachedOcspResponse {
    /// Check if this cache entry has expired
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// Thread-safe OCSP response cache with TTL and LRU eviction
///
/// This cache provides:
/// - Thread-safe concurrent access via DashMap
/// - TTL-based automatic expiration (from OCSP nextUpdate)
/// - LRU eviction when max_entries is reached
/// - O(1) lookups, inserts, and removals
///
/// # Cache Key
///
/// OCSP responses are cached by certificate serial number (as bytes).
/// This allows fast lookup when checking a specific certificate.
///
/// # Example
///
/// ```no_run
/// use radius_proto::revocation::ocsp_cache::OcspCache;
/// use std::time::Duration;
///
/// let cache = OcspCache::new(100);
///
/// // Insert is handled by OCSP client, but you can also insert manually
/// // cache.insert(serial_number, response);
///
/// // Get cached response
/// if let Some(response) = cache.get(b"serial") {
///     println!("Cache hit!");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OcspCache {
    /// The actual cache storage (serial number -> CachedOcspResponse)
    cache: Arc<DashMap<Vec<u8>, CachedOcspResponse>>,

    /// Maximum number of cache entries
    max_entries: usize,

    /// Upper bound on how long any response is cached (the configured
    /// `cache_ttl_secs`); `None` = until nextUpdate
    max_ttl: Option<Duration>,
}

impl OcspCache {
    /// Create a new OCSP response cache
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of OCSP responses to cache (LRU eviction when full)
    ///
    /// # Returns
    ///
    /// Arc-wrapped cache ready for sharing across threads
    pub fn new(max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            cache: Arc::new(DashMap::new()),
            max_entries,
            max_ttl: None,
        })
    }

    /// Like [`OcspCache::new`], but no response is cached for longer than
    /// `max_ttl`, even if its nextUpdate is later.
    pub fn with_max_ttl(max_entries: usize, max_ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            cache: Arc::new(DashMap::new()),
            max_entries,
            max_ttl: Some(max_ttl),
        })
    }

    /// Get an OCSP response from cache by certificate serial number
    ///
    /// Returns `None` if:
    /// - Response not in cache
    /// - Response has expired (TTL exceeded)
    /// - Response is no longer fresh (past nextUpdate)
    ///
    /// # Arguments
    ///
    /// * `serial` - Certificate serial number (as bytes)
    ///
    /// # Returns
    ///
    /// * `Some(OcspResponse)` - Cached response (not expired and fresh)
    /// * `None` - Not cached, expired, or stale
    pub fn get(&self, serial: &[u8]) -> Option<OcspResponse> {
        // Get entry from cache
        let entry = self.cache.get(serial)?;

        // Check if expired (TTL)
        if entry.is_expired() {
            // Drop the read lock before removing
            drop(entry);
            // Remove expired entry
            self.cache.remove(serial);
            return None;
        }

        // Check if response is still fresh (not past nextUpdate)
        if !entry.response.is_fresh() {
            // Drop the read lock before removing
            drop(entry);
            // Remove stale entry
            self.cache.remove(serial);
            return None;
        }

        // Return cloned response
        Some(entry.response.clone())
    }

    /// Insert an OCSP response into the cache
    ///
    /// The TTL is automatically calculated from the response's nextUpdate field.
    /// If the cache is full, the oldest entry (by insertion time) is evicted.
    ///
    /// # Arguments
    ///
    /// * `serial` - Certificate serial number (cache key)
    /// * `response` - OCSP response to cache
    ///
    /// # Cache Eviction
    ///
    /// When the cache reaches max_entries, this performs a simple scan to find
    /// and remove the oldest entry. This is O(n) but only happens when the cache
    /// is full, which should be rare with appropriate sizing.
    pub fn insert(&self, serial: Vec<u8>, response: OcspResponse) {
        // Evict oldest entry if cache is full
        if self.cache.len() >= self.max_entries {
            self.evict_oldest();
        }

        // Until nextUpdate (or the default), capped by the configured TTL
        let ttl = match self.max_ttl {
            Some(max) => response.cache_ttl().min(max),
            None => response.cache_ttl(),
        };

        let cached = CachedOcspResponse {
            response,
            cached_at: Instant::now(),
            ttl,
        };

        self.cache.insert(serial, cached);
    }

    /// Evict the oldest cache entry (LRU)
    ///
    /// This scans all entries to find the one with the oldest cached_at timestamp.
    /// While O(n), this only runs when the cache is full.
    fn evict_oldest(&self) {
        let mut oldest_serial: Option<Vec<u8>> = None;
        let mut oldest_time = Instant::now();

        // Find the oldest entry
        for entry in self.cache.iter() {
            if entry.value().cached_at < oldest_time {
                oldest_time = entry.value().cached_at;
                oldest_serial = Some(entry.key().clone());
            }
        }

        // Remove the oldest entry
        if let Some(serial) = oldest_serial {
            self.cache.remove(&serial);
        }
    }

    /// Evict all expired entries from the cache
    ///
    /// This performs a full scan of the cache to remove expired entries.
    /// Useful for periodic cleanup to free memory.
    ///
    /// # Returns
    ///
    /// Number of entries evicted
    pub fn evict_expired(&self) -> usize {
        let mut evicted = 0;

        // Collect keys to remove (can't remove while iterating)
        let to_remove: Vec<Vec<u8>> = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired() || !entry.value().response.is_fresh())
            .map(|entry| entry.key().clone())
            .collect();

        // Remove expired entries
        for serial in to_remove {
            if self.cache.remove(&serial).is_some() {
                evicted += 1;
            }
        }

        evicted
    }

    /// Get current cache size
    ///
    /// # Returns
    ///
    /// Number of entries currently in cache (including expired)
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::ocsp::{CertificateStatus, OcspResponseStatus};
    use std::time::SystemTime;

    fn create_test_response(next_update_secs: Option<u64>) -> OcspResponse {
        let next_update =
            next_update_secs.map(|secs| SystemTime::now() + Duration::from_secs(secs));

        OcspResponse {
            status: OcspResponseStatus::Successful,
            cert_status: Some(CertificateStatus::Good),
            produced_at: SystemTime::now(),
            this_update: SystemTime::now(),
            next_update,
            nonce: None,
            raw_bytes: vec![],
        }
    }

    #[test]
    fn test_ocsp_cache_insert_and_get() {
        let cache = OcspCache::new(10);
        let serial = vec![0x01, 0x02, 0x03];
        let response = create_test_response(Some(3600));

        // Insert response
        cache.insert(serial.clone(), response);

        // Get response
        let cached = cache.get(&serial);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().status, OcspResponseStatus::Successful);
    }

    #[test]
    fn test_ocsp_cache_expiry() {
        let cache = OcspCache::new(10);
        let serial = vec![0x01, 0x02, 0x03];

        // Create response with very short TTL (nextUpdate in the past)
        let response = create_test_response(None); // No nextUpdate = 1 hour default

        cache.insert(serial.clone(), response);

        // Should be cached
        assert!(cache.get(&serial).is_some());

        // Manually expire by creating a response with past nextUpdate
        let expired_response = OcspResponse {
            status: OcspResponseStatus::Successful,
            cert_status: Some(CertificateStatus::Good),
            produced_at: SystemTime::now() - Duration::from_secs(7200),
            this_update: SystemTime::now() - Duration::from_secs(7200),
            next_update: Some(SystemTime::now() - Duration::from_secs(3600)), // 1 hour ago
            nonce: None,
            raw_bytes: vec![],
        };

        cache.insert(serial.clone(), expired_response);

        // Should not be cached (expired)
        assert!(cache.get(&serial).is_none());
    }

    #[test]
    fn test_ocsp_cache_max_entries() {
        let cache = OcspCache::new(3);

        // Insert 4 responses (exceeds max)
        for i in 0..4 {
            let serial = vec![i];
            let response = create_test_response(Some(3600));
            cache.insert(serial, response);
        }

        // Cache should have exactly 3 entries (oldest evicted)
        assert_eq!(cache.size(), 3);

        // First entry should have been evicted
        assert!(cache.get(&[0]).is_none());

        // Others should be present
        assert!(cache.get(&[1]).is_some());
        assert!(cache.get(&[2]).is_some());
        assert!(cache.get(&[3]).is_some());
    }

    #[test]
    fn test_ocsp_cache_evict_expired() {
        let cache = OcspCache::new(10);

        // Insert fresh response
        let serial1 = vec![0x01];
        let response1 = create_test_response(Some(3600));
        cache.insert(serial1.clone(), response1);

        // Insert expired response
        let serial2 = vec![0x02];
        let expired_response = OcspResponse {
            status: OcspResponseStatus::Successful,
            cert_status: Some(CertificateStatus::Good),
            produced_at: SystemTime::now() - Duration::from_secs(7200),
            this_update: SystemTime::now() - Duration::from_secs(7200),
            next_update: Some(SystemTime::now() - Duration::from_secs(3600)),
            nonce: None,
            raw_bytes: vec![],
        };
        cache.insert(serial2.clone(), expired_response);

        assert_eq!(cache.size(), 2);

        // Evict expired
        let evicted = cache.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(cache.size(), 1);

        // Fresh response should still be there
        assert!(cache.get(&serial1).is_some());

        // Expired should be gone
        assert!(cache.get(&serial2).is_none());
    }

    #[test]
    fn test_ocsp_cache_clear() {
        let cache = OcspCache::new(10);

        // Insert multiple responses
        for i in 0..5 {
            let serial = vec![i];
            let response = create_test_response(Some(3600));
            cache.insert(serial, response);
        }

        assert_eq!(cache.size(), 5);

        // Clear cache
        cache.clear();
        assert_eq!(cache.size(), 0);
    }
}
