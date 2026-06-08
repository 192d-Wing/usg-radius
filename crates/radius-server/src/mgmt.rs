//! Read-only management API (Phase 1).
//!
//! Exposes the running configuration (clients, users — secrets redacted), server
//! status, and active sessions as JSON for the operator UI. Behind the
//! `observability` feature (pulls in axum). Served on an internal port; front it
//! with mTLS + RBAC (Phase 1b) before exposing beyond the cluster.

#[cfg(feature = "observability")]
use crate::config::Config;
#[cfg(feature = "observability")]
use crate::state::SharedSessionManager;
#[cfg(feature = "observability")]
use axum::{Json, Router, extract::State, routing::get};
#[cfg(feature = "observability")]
use serde::Serialize;
#[cfg(feature = "observability")]
use std::collections::HashMap;
#[cfg(feature = "observability")]
use std::sync::Arc;
#[cfg(feature = "observability")]
use std::time::Instant;
#[cfg(feature = "observability")]
use tower_http::trace::TraceLayer;

/// Shared state for the management API.
#[cfg(feature = "observability")]
#[derive(Clone)]
pub struct MgmtState {
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
    started: Instant,
}

#[cfg(feature = "observability")]
impl MgmtState {
    pub fn new(config: Arc<Config>, session_manager: Arc<SharedSessionManager>) -> Self {
        Self {
            config,
            session_manager,
            started: Instant::now(),
        }
    }
}

#[cfg(feature = "observability")]
#[derive(Serialize)]
struct StatusDto {
    version: &'static str,
    uptime_seconds: u64,
    listen_address: String,
    listen_port: u16,
    clients: usize,
    users: usize,
    backend_up: bool,
}

/// Client without the shared secret.
#[cfg(feature = "observability")]
#[derive(Serialize)]
struct ClientDto {
    address: String,
    name: Option<String>,
    enabled: bool,
    nas_identifier: Option<String>,
}

/// User without the password.
#[cfg(feature = "observability")]
#[derive(Serialize)]
struct UserDto {
    username: String,
    attributes: HashMap<String, String>,
}

#[cfg(feature = "observability")]
async fn status(State(st): State<MgmtState>) -> Json<StatusDto> {
    let backend_up = st.session_manager.health_check().await.is_ok();
    Json(StatusDto {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: st.started.elapsed().as_secs(),
        listen_address: st.config.listen_address.clone(),
        listen_port: st.config.listen_port,
        clients: st.config.clients.len(),
        users: st.config.users.len(),
        backend_up,
    })
}

#[cfg(feature = "observability")]
async fn clients(State(st): State<MgmtState>) -> Json<Vec<ClientDto>> {
    Json(
        st.config
            .clients
            .iter()
            .map(|c| ClientDto {
                address: c.address.clone(),
                name: c.name.clone(),
                enabled: c.enabled,
                nas_identifier: c.nas_identifier.clone(),
            })
            .collect(),
    )
}

#[cfg(feature = "observability")]
async fn users(State(st): State<MgmtState>) -> Json<Vec<UserDto>> {
    Json(
        st.config
            .users
            .iter()
            .map(|u| UserDto {
                username: u.username.clone(),
                attributes: u.attributes.clone(),
            })
            .collect(),
    )
}

/// Active sessions. The request path does not yet maintain a queryable live-session
/// index, so this returns an empty list for now (populated in a later phase).
#[cfg(feature = "observability")]
async fn sessions(State(_st): State<MgmtState>) -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

/// Build the management API router.
#[cfg(feature = "observability")]
pub fn create_mgmt_server(
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
) -> Router {
    Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/users", get(users))
        .route("/api/v1/sessions", get(sessions))
        .layer(TraceLayer::new_for_http())
        .with_state(MgmtState::new(config, session_manager))
}

/// Start the management API server on `addr`.
#[cfg(feature = "observability")]
pub async fn start_mgmt_server(
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_mgmt_server(config, session_manager);
    tracing::info!("Starting management API on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
