//! Request deduplication cache
//!
//! Implements RFC 2865 duplicate request detection by caching recent requests.
//! Helps prevent replay attacks and ensures proper handling of retransmissions.

use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time;
use tracing::debug;

/// Process-wide count of retransmitted Access-Requests answered with the
/// cached reply (exported as `radius_retransmissions_replayed_total`).
pub static RETRANSMISSIONS_REPLAYED: AtomicU64 = AtomicU64::new(0);

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

/// How many times one cached reply is sent again. A NAS retransmits a few
/// times (typically 3 to 5); the cap bounds what a captured request can
/// reflect toward its NAS.
pub const MAX_REPLAYS_PER_REQUEST: u8 = 8;

/// Cached request entry with timestamp
#[derive(Clone)]
struct CacheEntry {
    /// When this entry was created
    inserted_at: Instant,
    /// [`request_digest`] of the request: a later packet under the same
    /// fingerprint is a retransmission only if it is byte-identical and
    /// arrived under the same shared secret.
    request_digest: [u8; 32],
    /// Address the request came from and its reply went to. A cached reply
    /// is only ever sent there again.
    source: SocketAddr,
    /// The encoded reply, once one was sent and is replayable (RFC 5080
    /// §2.2.2). `None` while the request is being processed, when it got no
    /// reply, or when its replies are not cached.
    reply: Option<Arc<[u8]>>,
    /// Times `reply` has been sent again (see [`MAX_REPLAYS_PER_REQUEST`]).
    replays: u8,
}

/// Prints the reply's length only: a cached Access-Accept carries MS-MPPE
/// and Tunnel-Password values.
impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry")
            .field("inserted_at", &self.inserted_at)
            .field("source", &self.source)
            .field("reply_len", &self.reply.as_ref().map(|r| r.len()))
            .field("replays", &self.replays)
            .finish_non_exhaustive()
    }
}

/// What [`RequestCache::admit`] decided about a request.
#[derive(Clone, PartialEq, Eq)]
pub enum Admission {
    /// Not seen within the TTL: process it. It is now recorded as in progress.
    New,
    /// A byte-identical copy is being processed, was processed without a
    /// replayable reply, came from another address than the original, or
    /// has had its reply replayed [`MAX_REPLAYS_PER_REQUEST`] times: drop it.
    InProgress,
    /// A byte-identical retransmission of a request already answered, from
    /// the same address and under the same secret: send this reply again,
    /// unchanged (RFC 5080 §2.2.2).
    Replay(Arc<[u8]>),
    /// Same source, Identifier and Request Authenticator prefix as a recent
    /// request but different content (or another shared secret): drop it.
    Conflict,
}

/// Prints the replayed reply's length only (see [`CacheEntry`]'s `Debug`).
impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Admission::New => f.write_str("New"),
            Admission::InProgress => f.write_str("InProgress"),
            Admission::Replay(reply) => write!(f, "Replay(<{} octets>)", reply.len()),
            Admission::Conflict => f.write_str("Conflict"),
        }
    }
}

/// Identity of a retransmission: SHA-256 over the shared secret in force
/// for the transport (length-prefixed) and the request's bytes. A cached
/// reply's Response Authenticator, Message-Authenticator and MS-MPPE keys
/// are bound to that secret, so the same bytes arriving under another
/// secret (UDP vs. RadSec from one address) never match.
pub fn request_digest(secret: &[u8], request: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((secret.len() as u64).to_be_bytes());
    h.update(secret);
    h.update(request);
    h.finalize().into()
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

                    // Remove expired entries, unless `admit` replaced one
                    // with a fresh entry in the meantime.
                    for key in expired_keys {
                        if cache_clone
                            .remove_if(&key, |_, e| now.duration_since(e.inserted_at) > ttl)
                            .is_some()
                        {
                            removed += 1;
                        }
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
    /// Returns `true` if a request with this fingerprint was seen recently,
    /// `false` otherwise (and records it). Kept for callers that only need
    /// duplicate detection; the server uses [`Self::admit`], which also
    /// replays cached replies.
    pub fn is_duplicate(&self, fingerprint: RequestFingerprint, authenticator: [u8; 16]) -> bool {
        let source = SocketAddr::new(fingerprint.source_ip, 0);
        self.admit(fingerprint, source, request_digest(&[], &authenticator)) != Admission::New
    }

    /// Decide what to do with a request from `source` whose
    /// [`request_digest`] is `digest`, atomically with respect to concurrent
    /// copies of it.
    ///
    /// RFC 5080 §2.2.2: a server that receives a duplicate of a request it
    /// has answered sends the same reply again instead of processing the
    /// request a second time, and drops duplicates of a request still being
    /// processed. A packet is treated as a retransmission only when it is
    /// byte-identical to the recorded request under the same shared secret
    /// (same Identifier and Request Authenticator, and the same attributes,
    /// so the same State and EAP-Message): a replay sends bytes already
    /// computed for exactly that request and acts on nothing new. The reply
    /// is replayed only to the address the original came from, at most
    /// [`MAX_REPLAYS_PER_REQUEST`] times, so a captured request cannot be
    /// used to reflect replies elsewhere or without bound. Entries older
    /// than the TTL are replaced as if absent.
    pub fn admit(
        &self,
        fingerprint: RequestFingerprint,
        source: SocketAddr,
        digest: [u8; 32],
    ) -> Admission {
        use dashmap::mapref::entry::Entry;

        let now = Instant::now();

        // Make room first by dropping an arbitrary entry (expired ones go
        // with the background cleanup). Pick the victim in its own
        // statement: an iterator still alive across `remove` holds its
        // shard's lock and deadlocks.
        if self.cache.len() >= self.max_entries && !self.cache.contains_key(&fingerprint) {
            let victim = self.cache.iter().next().map(|e| e.key().clone());
            if let Some(key) = victim {
                self.cache.remove(&key);
            }
        }

        let fresh = CacheEntry {
            inserted_at: now,
            request_digest: digest,
            source,
            reply: None,
            replays: 0,
        };
        match self.cache.entry(fingerprint) {
            Entry::Vacant(slot) => {
                slot.insert(fresh);
                Admission::New
            }
            Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                if now.duration_since(entry.inserted_at) > self.ttl {
                    slot.insert(fresh);
                    Admission::New
                } else if entry.request_digest != digest {
                    Admission::Conflict
                } else if entry.source != source || entry.replays >= MAX_REPLAYS_PER_REQUEST {
                    Admission::InProgress
                } else {
                    match &entry.reply {
                        Some(reply) => {
                            entry.replays += 1;
                            Admission::Replay(Arc::clone(reply))
                        }
                        None => Admission::InProgress,
                    }
                }
            }
        }
    }

    /// Record `reply` as the answer to the request admitted under
    /// `fingerprint` with `digest`, so that a retransmission of it within the
    /// TTL gets it again. Does nothing if the entry has since expired, been
    /// evicted or been replaced by different content. The cache holds at
    /// most `max_entries` replies, each at most one RADIUS packet (4096
    /// octets).
    pub fn store_reply(&self, fingerprint: &RequestFingerprint, digest: &[u8; 32], reply: &[u8]) {
        if let Some(mut entry) = self.cache.get_mut(fingerprint)
            && entry.request_digest == *digest
        {
            entry.reply = Some(Arc::from(reply));
        }
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

    /// Filling the cache evicts an entry instead of deadlocking on the
    /// iterator's shard lock (this test used to hang and was ignored).
    #[test]
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

    fn fp(id: u8) -> RequestFingerprint {
        RequestFingerprint::new("192.0.2.1".parse().unwrap(), id, &[7u8; 16])
    }

    fn nas() -> SocketAddr {
        "192.0.2.1:40000".parse().unwrap()
    }

    fn digest(request: &[u8]) -> [u8; 32] {
        request_digest(b"client-secret", request)
    }

    /// RFC 5080 §2.2.2: a byte-identical retransmission is dropped while the
    /// original is in progress and gets the same reply once one was sent.
    #[test]
    fn admit_replays_the_reply_to_a_byte_identical_retransmission() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 100);
        let request = digest(b"access-request bytes");

        assert_eq!(cache.admit(fp(1), nas(), request), Admission::New);
        assert_eq!(cache.admit(fp(1), nas(), request), Admission::InProgress);

        cache.store_reply(&fp(1), &request, b"access-challenge bytes");
        assert_eq!(
            cache.admit(fp(1), nas(), request),
            Admission::Replay(Arc::from(&b"access-challenge bytes"[..]))
        );
        // Still replayable for further retransmissions.
        assert!(matches!(
            cache.admit(fp(1), nas(), request),
            Admission::Replay(_)
        ));
    }

    /// Same fingerprint, different content: never answered from the cache,
    /// and a reply is never stored against a request it does not answer.
    #[test]
    fn admit_refuses_different_content_under_the_same_fingerprint() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 100);
        assert_eq!(
            cache.admit(fp(2), nas(), digest(b"original")),
            Admission::New
        );
        cache.store_reply(&fp(2), &digest(b"original"), b"reply");
        assert_eq!(
            cache.admit(fp(2), nas(), digest(b"forged")),
            Admission::Conflict
        );

        cache.store_reply(&fp(2), &digest(b"forged"), b"other reply");
        assert_eq!(
            cache.admit(fp(2), nas(), digest(b"original")),
            Admission::Replay(Arc::from(&b"reply"[..]))
        );
    }

    /// The same bytes under another shared secret (RadSec's "radsec" vs. a
    /// UDP client secret, from one address) are not a retransmission: the
    /// cached reply's authenticators and MS-MPPE keys belong to the other
    /// secret.
    #[test]
    fn admit_binds_the_reply_to_the_shared_secret() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 100);
        let over_radsec = request_digest(b"radsec", b"same bytes");
        assert_eq!(cache.admit(fp(3), nas(), over_radsec), Admission::New);
        cache.store_reply(&fp(3), &over_radsec, b"accept");
        let over_udp = request_digest(b"client-secret", b"same bytes");
        assert_eq!(cache.admit(fp(3), nas(), over_udp), Admission::Conflict);
        // Length-prefixed: moving octets between secret and request changes the digest.
        assert_ne!(request_digest(b"ab", b"c"), request_digest(b"a", b"bc"));
    }

    /// A cached reply goes only back to the address the original came from,
    /// and at most MAX_REPLAYS_PER_REQUEST times: a captured request cannot
    /// reflect it to other ports or without bound.
    #[test]
    fn admit_replays_only_to_the_original_address_and_a_bounded_number_of_times() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 100);
        let request = digest(b"req");
        assert_eq!(cache.admit(fp(4), nas(), request), Admission::New);
        cache.store_reply(&fp(4), &request, b"reply");

        let other_port: SocketAddr = "192.0.2.1:40001".parse().unwrap();
        assert_eq!(
            cache.admit(fp(4), other_port, request),
            Admission::InProgress
        );

        for _ in 0..MAX_REPLAYS_PER_REQUEST {
            assert!(matches!(
                cache.admit(fp(4), nas(), request),
                Admission::Replay(_)
            ));
        }
        assert_eq!(cache.admit(fp(4), nas(), request), Admission::InProgress);
    }

    /// A reply is not replayed after the TTL: the packet is new again.
    #[test]
    fn admit_treats_an_expired_entry_as_new() {
        let cache = RequestCache::new_no_background(Duration::from_millis(20), 100);
        let request = digest(b"req");
        assert_eq!(cache.admit(fp(5), nas(), request), Admission::New);
        cache.store_reply(&fp(5), &request, b"reply");
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(cache.admit(fp(5), nas(), request), Admission::New);
        assert_eq!(cache.admit(fp(5), nas(), request), Admission::InProgress);
    }

    /// Storing a reply for a request that was evicted in the meantime does
    /// nothing, and the cache stays within `max_entries` while full.
    #[test]
    fn store_reply_after_eviction_is_a_no_op_and_the_bound_holds() {
        let cache = RequestCache::new_no_background(Duration::from_secs(60), 2);
        assert_eq!(cache.admit(fp(6), nas(), digest(b"a")), Admission::New);
        assert_eq!(cache.admit(fp(7), nas(), digest(b"b")), Admission::New);
        assert_eq!(cache.admit(fp(8), nas(), digest(b"c")), Admission::New);
        assert_eq!(cache.len(), 2);
        let evicted = [6u8, 7]
            .into_iter()
            .find(|id| !cache.cache.contains_key(&fp(*id)))
            .expect("one of the first two entries was evicted");
        cache.store_reply(&fp(evicted), &digest(b"x"), b"reply");
        assert!(!cache.cache.contains_key(&fp(evicted)));
        assert_eq!(cache.len(), 2);
    }

    /// Debug output never contains a cached reply's bytes.
    #[test]
    fn debug_output_shows_reply_length_only() {
        let reply: Arc<[u8]> = Arc::from(&b"\x1a\x0csecret-mppe"[..]);
        let shown = format!("{:?}", Admission::Replay(Arc::clone(&reply)));
        assert_eq!(shown, format!("Replay(<{} octets>)", reply.len()));
        let entry = CacheEntry {
            inserted_at: Instant::now(),
            request_digest: [0; 32],
            source: nas(),
            reply: Some(reply),
            replays: 0,
        };
        let shown = format!("{entry:?}");
        assert!(!shown.contains("secret-mppe") && !shown.contains("115, 101"));
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
