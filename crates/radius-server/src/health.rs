//! Health check module
//!
//! Provides HTTP endpoints for health checking.
//! This is essential for Kubernetes/load balancer health probes.

#[cfg(feature = "observability")]
use crate::state::SharedSessionManager;
#[cfg(feature = "observability")]
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(feature = "observability")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "observability")]
use std::sync::Arc;
#[cfg(feature = "observability")]
use tower_http::trace::TraceLayer;
#[cfg(feature = "observability")]
use tracing::info;

/// Health check status
#[cfg(feature = "observability")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health status
    pub status: String,
    /// Backend connectivity
    pub backend: BackendHealth,
    /// Local cache status
    pub cache: CacheHealth,
}

/// Backend health information
#[cfg(feature = "observability")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealth {
    /// Backend type (memory)
    pub backend_type: String,
    /// Backend status (up, down)
    pub status: String,
    /// Error message if down
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Cache health information
#[cfg(feature = "observability")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheHealth {
    /// Number of entries in local cache
    pub entries: usize,
}

/// Health check server state
#[cfg(feature = "observability")]
#[derive(Clone)]
pub struct HealthCheckState {
    session_manager: Arc<SharedSessionManager>,
}

#[cfg(feature = "observability")]
impl HealthCheckState {
    /// Create new health check state
    pub fn new(session_manager: Arc<SharedSessionManager>) -> Self {
        Self { session_manager }
    }

    /// Check backend health
    async fn check_backend(&self) -> BackendHealth {
        match self.session_manager.health_check().await {
            Ok(_) => BackendHealth {
                backend_type: "memory".to_string(),
                status: "up".to_string(),
                error: None,
            },
            Err(e) => BackendHealth {
                backend_type: "memory".to_string(),
                status: "down".to_string(),
                error: Some(e.to_string()),
            },
        }
    }

    /// Get cache statistics
    fn check_cache(&self) -> CacheHealth {
        let stats = self.session_manager.cache_stats();
        CacheHealth {
            entries: stats.entries,
        }
    }

    /// Get overall health status
    async fn get_health(&self) -> HealthStatus {
        let backend = self.check_backend().await;
        let cache = self.check_cache();

        let status = if backend.status == "up" {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        };

        HealthStatus {
            status,
            backend,
            cache,
        }
    }
}

/// Health check endpoint handler
#[cfg(feature = "observability")]
async fn health_handler(State(state): State<HealthCheckState>) -> Response {
    let health = state.get_health().await;

    let status_code = if health.status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(health)).into_response()
}

/// Readiness check handler (for Kubernetes readiness probe)
#[cfg(feature = "observability")]
async fn ready_handler(State(state): State<HealthCheckState>) -> Response {
    let backend = state.check_backend().await;

    if backend.status == "up" {
        (StatusCode::OK, "ready").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("backend unavailable: {}", backend.error.unwrap_or_default()),
        )
            .into_response()
    }
}

/// Liveness check handler (for Kubernetes liveness probe)
#[cfg(feature = "observability")]
async fn live_handler() -> Response {
    // Liveness just checks if the server is running
    (StatusCode::OK, "alive").into_response()
}

/// Create health check HTTP server
#[cfg(feature = "observability")]
pub fn create_health_server(session_manager: Arc<SharedSessionManager>) -> Router {
    let state = HealthCheckState::new(session_manager);

    Router::new()
        .route("/health", get(health_handler))
        .route("/health/ready", get(ready_handler))
        .route("/health/live", get(live_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start health check HTTP server on the specified address
#[cfg(feature = "observability")]
pub async fn start_health_server(
    session_manager: Arc<SharedSessionManager>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_health_server(session_manager);

    info!("Starting health check server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(all(test, feature = "observability"))]
mod tests {
    use super::*;
    use crate::state::MemoryStateBackend;

    #[tokio::test]
    async fn test_health_check_state() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = HealthCheckState::new(session_manager);

        let health = state.get_health().await;
        assert_eq!(health.status, "healthy");
        assert_eq!(health.backend.status, "up");
    }

    #[tokio::test]
    async fn test_backend_health() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = HealthCheckState::new(session_manager);

        let backend_health = state.check_backend().await;
        assert_eq!(backend_health.status, "up");
        assert!(backend_health.error.is_none());
    }

    #[tokio::test]
    async fn test_cache_health() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = HealthCheckState::new(session_manager);

        let cache_health = state.check_cache();
        assert_eq!(cache_health.entries, 0);
    }
}
