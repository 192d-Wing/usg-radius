//! Shared session manager for distributed state

use super::{StateBackend, StateError};
use crate::accounting::Session;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached session entry with local TTL
#[derive(Debug, Clone)]
struct CachedSession<T> {
    session: T,
    cached_at: Instant,
}

impl<T> CachedSession<T> {
    fn new(session: T) -> Self {
        Self {
            session,
            cached_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }
}

/// Shared session manager with two-tier caching
///
/// This manager provides session storage with two levels:
/// 1. **Local cache**: Fast in-memory cache (DashMap)
/// 2. **Backend storage**: Backend storage (in-memory)
///
/// # Write-Through Caching
///
/// All writes go to both cache and backend simultaneously.
/// Reads check cache first, then fall back to backend.
///
/// # Use Cases
///
/// - **EAP sessions**: Track multi-round authentication across cluster
/// - **Accounting sessions**: Share session state for RADIUS accounting
/// - **Rate limiting**: Coordinate rate limits across servers
///
/// # Example
///
/// ```no_run
/// use radius_server::state::{SharedSessionManager, MemoryStateBackend};
/// use radius_server::accounting::Session;
/// use std::sync::Arc;
/// use std::time::{Duration, SystemTime};
/// use std::net::IpAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let backend = Arc::new(MemoryStateBackend::new());
/// let manager = SharedSessionManager::new(backend);
///
/// // Create a session
/// let session = Session {
///     session_id: "session-123".to_string(),
///     username: "testuser".to_string(),
///     nas_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
///     framed_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
///     start_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
///     last_update: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
///     input_octets: 1000,
///     output_octets: 2000,
///     input_packets: 10,
///     output_packets: 20,
///     session_time: 300,
///     terminate_cause: None,
/// };
///
/// // Store session
/// manager.store_accounting("session-123", &session, Some(Duration::from_secs(300))).await?;
///
/// // Retrieve session
/// let retrieved = manager.get_accounting("session-123").await?;
/// # Ok(())
/// # }
/// ```
pub struct SharedSessionManager {
    pub backend: Arc<dyn StateBackend>,
    local_cache: Arc<dashmap::DashMap<String, CachedSession<Vec<u8>>>>,
    cache_ttl: Duration,
}

impl SharedSessionManager {
    /// Create a new shared session manager
    ///
    /// # Arguments
    ///
    /// * `backend` - Storage backend (in-memory)
    pub fn new(backend: Arc<dyn StateBackend>) -> Self {
        Self {
            backend,
            local_cache: Arc::new(dashmap::DashMap::new()),
            cache_ttl: Duration::from_secs(30), // 30 second local cache TTL
        }
    }

    /// Create a new shared session manager with custom cache TTL
    pub fn with_cache_ttl(backend: Arc<dyn StateBackend>, cache_ttl: Duration) -> Self {
        Self {
            backend,
            local_cache: Arc::new(dashmap::DashMap::new()),
            cache_ttl,
        }
    }

    /// Store an accounting session (write-through to backend + local cache)
    pub async fn store_accounting(
        &self,
        session_id: &str,
        session: &Session,
        ttl: Option<Duration>,
    ) -> Result<(), StateError> {
        // Serialize session
        let bytes = serde_json::to_vec(session).map_err(|e| {
            StateError::SerializationError(format!("Failed to serialize accounting session: {}", e))
        })?;

        // Store in backend
        let key = format!("acct_session:{}", session_id);
        self.backend.set(&key, &bytes, ttl).await?;

        // Update local cache
        self.local_cache.insert(key, CachedSession::new(bytes));

        Ok(())
    }

    /// Get an accounting session (check local cache first, then backend)
    pub async fn get_accounting(&self, session_id: &str) -> Result<Option<Session>, StateError> {
        let key = format!("acct_session:{}", session_id);

        // 1. Check local cache first (fast path)
        if let Some(cached) = self.local_cache.get(&key) {
            if !cached.is_expired(self.cache_ttl) {
                // Cache hit - deserialize and return
                let session = serde_json::from_slice(&cached.session).map_err(|e| {
                    StateError::SerializationError(format!(
                        "Failed to deserialize accounting session: {}",
                        e
                    ))
                })?;
                return Ok(Some(session));
            } else {
                // Expired - remove from cache
                drop(cached);
                self.local_cache.remove(&key);
            }
        }

        // 2. Cache miss - fetch from backend
        if let Some(bytes) = self.backend.get(&key).await? {
            let session = serde_json::from_slice(&bytes).map_err(|e| {
                StateError::SerializationError(format!(
                    "Failed to deserialize accounting session: {}",
                    e
                ))
            })?;

            // 3. Update local cache
            self.local_cache.insert(key, CachedSession::new(bytes));

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    /// Delete an accounting session (from both cache and backend)
    pub async fn delete_accounting(&self, session_id: &str) -> Result<(), StateError> {
        let key = format!("acct_session:{}", session_id);

        // Remove from backend
        self.backend.delete(&key).await?;

        // Remove from local cache
        self.local_cache.remove(&key);

        Ok(())
    }

    /// Check if a request is a duplicate (cluster-wide deduplication)
    ///
    /// Uses atomic SET NX to ensure cluster-wide uniqueness.
    pub async fn is_duplicate_request(
        &self,
        fingerprint: &str,
        ttl: Duration,
    ) -> Result<bool, StateError> {
        let key = format!("req_cache:{}", fingerprint);

        // Atomic SET NX (only set if not exists)
        // Returns true if key was created (not duplicate)
        // Returns false if key already existed (duplicate)
        let was_created = self.backend.set_nx(&key, b"1", Some(ttl)).await?;

        Ok(!was_created)
    }

    /// Check rate limit for a client (cluster-wide rate limiting)
    ///
    /// Uses atomic INCR to coordinate rate limits across cluster.
    pub async fn check_rate_limit(
        &self,
        client_key: &str,
        max_requests: u32,
        window: Duration,
    ) -> Result<bool, StateError> {
        let key = format!("ratelimit:{}", client_key);

        // Atomic increment
        let count = self.backend.incr(&key).await?;

        if count == 1 {
            // First request in window - set TTL
            self.backend.expire(&key, window).await?;
        }

        Ok(count <= max_requests as i64)
    }

    /// Clean up expired entries from local cache
    ///
    /// This should be called periodically to prevent memory leaks.
    pub fn cleanup_expired_cache(&self) {
        let ttl = self.cache_ttl;
        self.local_cache.retain(|_, cached| !cached.is_expired(ttl));
    }

    /// Get local cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            entries: self.local_cache.len(),
        }
    }

    /// Health check - verify backend is accessible
    pub async fn health_check(&self) -> Result<(), StateError> {
        self.backend.ping().await
    }
}

impl std::fmt::Debug for SharedSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSessionManager")
            .field("cache_ttl", &self.cache_ttl)
            .field("cache_entries", &self.local_cache.len())
            .finish()
    }
}

/// Local cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in local cache
    pub entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MemoryStateBackend;
    use std::{net::IpAddr, time::SystemTime};

    fn create_test_session() -> Session {
        Session {
            session_id: "test-session".to_string(),
            username: "testuser".to_string(),
            nas_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            framed_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            start_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_update: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            input_octets: 1000,
            output_octets: 2000,
            input_packets: 10,
            output_packets: 20,
            session_time: 300,
            terminate_cause: None,
        }
    }

    #[tokio::test]
    async fn test_store_and_get_accounting() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend);

        let session = create_test_session();

        // Store session
        manager
            .store_accounting("test-session", &session, Some(Duration::from_secs(60)))
            .await
            .unwrap();

        // Retrieve session
        let retrieved = manager.get_accounting("test-session").await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.session_id, session.session_id);
        assert_eq!(retrieved.username, session.username);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend.clone());

        let session = create_test_session();

        // Store session
        manager
            .store_accounting("test-session", &session, Some(Duration::from_secs(60)))
            .await
            .unwrap();

        // First retrieval - should populate cache
        let _retrieved1 = manager.get_accounting("test-session").await.unwrap();

        // Second retrieval - should hit cache
        let retrieved2 = manager.get_accounting("test-session").await.unwrap();
        assert!(retrieved2.is_some());

        // Verify cache has entry
        let stats = manager.cache_stats();
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn test_delete_accounting() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend);

        let session = create_test_session();

        // Store session
        manager
            .store_accounting("test-session", &session, Some(Duration::from_secs(60)))
            .await
            .unwrap();

        // Delete session
        manager.delete_accounting("test-session").await.unwrap();

        // Verify deleted
        let retrieved = manager.get_accounting("test-session").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_duplicate_request_detection() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend);

        // First request - not duplicate
        let is_dup = manager
            .is_duplicate_request("fingerprint-123", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(!is_dup);

        // Second request - duplicate
        let is_dup = manager
            .is_duplicate_request("fingerprint-123", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(is_dup);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend);

        let max_requests = 3;
        let window = Duration::from_secs(60);

        // First 3 requests should pass
        for i in 1..=3 {
            let allowed = manager
                .check_rate_limit("client-1", max_requests, window)
                .await
                .unwrap();
            assert!(allowed, "Request {} should be allowed", i);
        }

        // 4th request should be blocked
        let allowed = manager
            .check_rate_limit("client-1", max_requests, window)
            .await
            .unwrap();
        assert!(!allowed, "Request 4 should be blocked");
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::with_cache_ttl(backend, Duration::from_millis(50));

        let session = create_test_session();

        // Store session
        manager
            .store_accounting("test-session", &session, Some(Duration::from_secs(60)))
            .await
            .unwrap();

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cleanup expired entries
        manager.cleanup_expired_cache();

        // Cache should be empty, but backend still has data
        let stats = manager.cache_stats();
        assert_eq!(stats.entries, 0);

        // Should still retrieve from backend
        let retrieved = manager.get_accounting("test-session").await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_health_check() {
        let backend = Arc::new(MemoryStateBackend::new());
        let manager = SharedSessionManager::new(backend);

        // Health check should succeed
        manager.health_check().await.unwrap();
    }
}
