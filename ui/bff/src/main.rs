// SPDX-License-Identifier: Apache-2.0
//! Backend-for-frontend for the usg-radius operator UI.
//!
//! Serves the Cloudscape SPA and aggregates the RADIUS server's health/metrics
//! into a small JSON API. Authentication is enforced upstream by oauth2-proxy
//! (Keycloak OIDC); the identity is read from forwarded `X-Auth-Request-*` headers.

mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub http: reqwest::Client,
    /// Base URL of the RADIUS server metrics port, e.g.
    /// `http://usg-radius-internal.radius.svc:3812`.
    pub radius_metrics_url: String,
    /// Base URL of the RADIUS server health port, e.g.
    /// `http://usg-radius-internal.radius.svc:2812`.
    pub radius_health_url: String,
    /// Base URL of the RADIUS server management API, e.g.
    /// `http://usg-radius-internal.radius.svc:4812`.
    pub radius_api_url: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,radius_ui_bff=debug".into()),
        )
        .init();

    let state = AppState {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
        radius_metrics_url: env_or(
            "RADIUS_METRICS_URL",
            "http://usg-radius-internal.radius.svc:3812",
        ),
        radius_health_url: env_or(
            "RADIUS_HEALTH_URL",
            "http://usg-radius-internal.radius.svc:2812",
        ),
        radius_api_url: env_or("RADIUS_API_URL", "http://usg-radius-internal.radius.svc:4812"),
    };
    let listen: SocketAddr = env_or("BFF_LISTEN", "0.0.0.0:8088").parse()?;
    let static_dir = env_or("UI_STATIC_DIR", "/app/web");

    // SPA: serve files, fall back to index.html for client-side routes.
    let index = format!("{static_dir}/index.html");
    let spa = ServeDir::new(&static_dir).not_found_service(ServeFile::new(index));

    let api = Router::new()
        .route("/me", get(handlers::me))
        .route("/health", get(handlers::health))
        .route("/overview", get(handlers::overview))
        .route("/status", get(handlers::status))
        .route("/clients", get(handlers::clients))
        .route("/users", get(handlers::users))
        .route("/sessions", get(handlers::sessions))
        .route("/policy", get(handlers::policy_get).put(handlers::policy_put))
        .route("/dictionary", get(handlers::dictionary))
        .route("/policy/dry-run", post(handlers::policy_dry_run))
        .with_state(state.clone());

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api)
        .fallback_service(spa)
        .layer(TraceLayer::new_for_http());

    tracing::info!(%listen, metrics = %state.radius_metrics_url, "radius-ui-bff listening");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
