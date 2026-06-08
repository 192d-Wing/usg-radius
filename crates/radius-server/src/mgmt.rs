//! Management API.
//!
//! Exposes the running configuration (clients, users — secrets redacted), server
//! status, active sessions, and the live authorization policy (editable via PUT)
//! as JSON for the operator UI. Behind the `observability` feature (pulls in axum).
//!
//! Access control is **opt-in** (see [`MgmtSecurity`] and [`crate::access`]): with
//! `mgmt.tls` configured the listener serves mTLS and verifies client certificates;
//! with `mgmt.access_policy_file` configured an IAM-style ABAC policy authorizes
//! every request (default deny). With neither configured the API is open and a
//! prominent warning is logged at startup.

#[cfg(feature = "observability")]
use crate::access::{AccessContext, AccessPolicy};
#[cfg(feature = "observability")]
use crate::audit::{AuditEntry, AuditEventType, AuditLogger};
#[cfg(feature = "observability")]
use crate::config::Config;
#[cfg(feature = "observability")]
use crate::policy::{Decision, Dictionary, PolicyConfig, RequestContext, dictionary};
#[cfg(feature = "observability")]
use crate::state::SharedSessionManager;
#[cfg(feature = "observability")]
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(feature = "observability")]
use serde::Deserialize;
#[cfg(feature = "observability")]
use serde::Serialize;
#[cfg(feature = "observability")]
use std::collections::HashMap;
#[cfg(feature = "observability")]
use std::net::SocketAddr;
#[cfg(feature = "observability")]
use std::sync::{Arc, RwLock};
#[cfg(feature = "observability")]
use std::time::Instant;
#[cfg(feature = "observability")]
use tower_http::trace::TraceLayer;

/// A live-swappable handle to the IAM access policy, so it can be reloaded from
/// disk (e.g. on SIGHUP) without restarting the server. The request path takes a
/// brief read lock and clones the inner `Arc` out before evaluating.
#[cfg(feature = "observability")]
pub type SharedAccessPolicy = Arc<RwLock<Arc<AccessPolicy>>>;

/// Optional security configuration for the management API. When `access_policy`
/// is `Some`, every request is authorized against it (IAM-style ABAC, default
/// deny). When `None`, the API is open (today's behavior) — the caller logs a
/// warning. Defaults to fully open.
#[cfg(feature = "observability")]
#[derive(Clone, Default)]
pub struct MgmtSecurity {
    /// The loaded IAM-style access policy. `Some` ⇒ authorization is enforced.
    /// Held behind a lock so it can be hot-reloaded from disk.
    pub access_policy: Option<SharedAccessPolicy>,
    /// Trust forwarded `X-Auth-Request-*` identity headers when building the
    /// principal even if no client certificate authenticated the peer.
    pub trust_forwarded_identity: bool,
    /// Where authorization denials are recorded (if configured).
    pub audit: Option<Arc<AuditLogger>>,
}

/// Reload the IAM access policy from `path` into `cell`, validating it **before**
/// swapping. On any read/parse/validation error the currently-loaded policy is
/// kept and an error returned — a bad edit can never disable authorization or
/// fail open. Safe to call from a signal handler task (e.g. SIGHUP).
#[cfg(feature = "observability")]
pub fn reload_access_policy(cell: &SharedAccessPolicy, path: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let parsed: AccessPolicy =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
    parsed
        .validate()
        .map_err(|e| format!("validate {path}: {e}"))?;
    *cell
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(parsed);
    Ok(())
}

/// Identity parsed from a verified mTLS client certificate.
#[cfg(feature = "observability")]
#[derive(Clone, Debug, Default)]
pub struct CertIdentity {
    pub common_name: Option<String>,
    pub org_unit: Option<String>,
    pub sans: Vec<String>,
    /// Lowercase hex SHA-256 of the DER certificate.
    pub fingerprint_sha256: String,
}

/// Per-connection context injected into each request by the mTLS serving loop:
/// the verified client identity (if any) and the peer socket address.
#[cfg(feature = "observability")]
#[derive(Clone)]
struct ConnContext {
    cert: Option<Arc<CertIdentity>>,
    peer: SocketAddr,
}

/// Shared state for the management API.
#[cfg(feature = "observability")]
#[derive(Clone)]
pub struct MgmtState {
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
    /// The live authorization policy (editable via PUT).
    policy: Arc<RwLock<PolicyConfig>>,
    /// Where PUT persists the policy (if configured).
    policy_file: Option<Arc<str>>,
    /// IAM-style authorization + audit (None ⇒ open API).
    security: MgmtSecurity,
    started: Instant,
}

#[cfg(feature = "observability")]
impl MgmtState {
    pub fn new(
        config: Arc<Config>,
        session_manager: Arc<SharedSessionManager>,
        policy: Arc<RwLock<PolicyConfig>>,
        policy_file: Option<Arc<str>>,
        security: MgmtSecurity,
    ) -> Self {
        Self {
            config,
            session_manager,
            policy,
            policy_file,
            security,
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

/// The currently loaded authorization policy.
#[cfg(feature = "observability")]
async fn policy(State(st): State<MgmtState>) -> Json<PolicyConfig> {
    let p = st.policy.read().expect("policy lock poisoned").clone();
    Json(p)
}

/// Replace the authorization policy: validate referential integrity, persist to
/// POLICY_FILE (if configured), then swap the in-memory policy.
#[cfg(feature = "observability")]
async fn policy_put(
    State(st): State<MgmtState>,
    Json(new_policy): Json<PolicyConfig>,
) -> Result<Json<PolicyConfig>, (StatusCode, String)> {
    new_policy
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if let Some(path) = &st.policy_file {
        let json = serde_json::to_string_pretty(&new_policy)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Atomic write: write a temp file then rename over the target, so a crash
        // mid-write can't leave a truncated/corrupt POLICY_FILE. Async I/O to avoid
        // blocking the runtime worker.
        let tmp = format!("{path}.tmp");
        let persist = async {
            tokio::fs::write(&tmp, &json).await?;
            tokio::fs::rename(&tmp, path.as_ref()).await
        };
        persist.await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist policy to {path}: {e}"),
            )
        })?;
    }

    *st.policy.write().expect("policy lock poisoned") = new_policy.clone();
    tracing::info!("authorization policy updated");
    Ok(Json(new_policy))
}

/// The attribute + operator dictionary that drives the Condition Studio.
#[cfg(feature = "observability")]
async fn dictionary_handler() -> Json<Dictionary> {
    Json(dictionary())
}

/// Dry-run body: evaluate a candidate policy against a sample request.
#[cfg(feature = "observability")]
#[derive(Deserialize)]
struct DryRunRequest {
    policy: PolicyConfig,
    request: RequestContext,
}

/// Evaluate a candidate policy against a request without saving it ("what-if").
#[cfg(feature = "observability")]
async fn policy_dry_run(Json(body): Json<DryRunRequest>) -> Json<Decision> {
    Json(body.policy.evaluate(&body.request))
}

/// Map an HTTP method + path to the granular IAM `(action, resource)` it requires.
/// Unknown routes return `None`, which the middleware treats as deny.
#[cfg(feature = "observability")]
fn route_action(method: &Method, path: &str) -> Option<(&'static str, &'static str)> {
    use Method as M;
    match (method, path) {
        (&M::GET, "/api/v1/status") => Some(("radius:GetStatus", "arn:usgradius:mgmt:::status")),
        (&M::GET, "/api/v1/clients") => {
            Some(("radius:ListClients", "arn:usgradius:mgmt:::clients"))
        }
        (&M::GET, "/api/v1/users") => Some(("radius:ListUsers", "arn:usgradius:mgmt:::users")),
        (&M::GET, "/api/v1/sessions") => {
            Some(("radius:ListSessions", "arn:usgradius:mgmt:::sessions"))
        }
        (&M::GET, "/api/v1/dictionary") => {
            Some(("radius:GetDictionary", "arn:usgradius:mgmt:::dictionary"))
        }
        (&M::GET, "/api/v1/policy") => Some(("radius:GetPolicy", "arn:usgradius:mgmt:::policy")),
        (&M::PUT, "/api/v1/policy") => Some(("radius:PutPolicy", "arn:usgradius:mgmt:::policy")),
        (&M::POST, "/api/v1/policy/dry-run") => {
            Some(("radius:SimulatePolicy", "arn:usgradius:mgmt:::policy"))
        }
        _ => None,
    }
}

/// Read a single header value as an owned String.
#[cfg(feature = "observability")]
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Build the ABAC [`AccessContext`] for a request from the merged principal: the
/// verified mTLS client cert (if any) and the oauth2-proxy identity headers
/// (trusted only over a verified mTLS channel, or when explicitly opted in).
#[cfg(feature = "observability")]
fn build_access_context(
    action: &str,
    resource: &str,
    method: &Method,
    conn: Option<&ConnContext>,
    headers: &HeaderMap,
    trust_forwarded_identity: bool,
) -> AccessContext {
    let mut ctx = AccessContext::new();
    ctx.set("request:Action", Some(action))
        .set("request:Resource", Some(resource))
        .set("request:Method", Some(method.as_str()));

    let cert = conn.and_then(|c| c.cert.as_ref());
    if let Some(c) = cert {
        ctx.set("tls:ClientCN", c.common_name.clone())
            .set("tls:ClientOU", c.org_unit.clone())
            .set("tls:Fingerprint", Some(c.fingerprint_sha256.clone()))
            .set_multi("tls:ClientSAN", c.sans.iter().cloned());
    }
    if let Some(c) = conn {
        ctx.set("request:SourceIp", Some(c.peer.ip().to_string()));
    }

    // Forwarded OIDC identity is spoofable unless the channel itself is
    // authenticated, so only honor it over verified mTLS (cert present) — unless
    // the operator explicitly trusts headers without mTLS.
    if cert.is_some() || trust_forwarded_identity {
        ctx.set("identity:User", header_str(headers, "x-auth-request-user"))
            .set(
                "identity:Email",
                header_str(headers, "x-auth-request-email"),
            );
        if let Some(groups) = header_str(headers, "x-auth-request-groups") {
            ctx.set_multi(
                "identity:Group",
                groups
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
    }
    ctx
}

/// Authorization middleware (only mounted when an access policy is configured).
/// Maps the route to its IAM action/resource, builds the ABAC context from the
/// connection + headers, evaluates the policy (default deny), and returns 403 on
/// denial while auditing it.
#[cfg(feature = "observability")]
async fn authorize(State(st): State<MgmtState>, req: Request, next: Next) -> Response {
    // Clone the current policy Arc out of the swappable cell, then drop the lock —
    // so a concurrent SIGHUP reload never blocks (or is blocked by) evaluation.
    let policy = match &st.security.access_policy {
        Some(cell) => Arc::clone(
            &cell
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        ),
        // Defensive: middleware shouldn't be mounted without a policy.
        None => return next.run(req).await,
    };

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let Some((action, resource)) = route_action(&method, &path) else {
        return (StatusCode::FORBIDDEN, "unknown management route").into_response();
    };

    let conn = req.extensions().get::<ConnContext>().cloned();
    let ctx = build_access_context(
        action,
        resource,
        &method,
        conn.as_ref(),
        req.headers(),
        st.security.trust_forwarded_identity,
    );
    let decision = policy.evaluate(action, resource, &ctx);

    if decision.allowed {
        tracing::debug!(action, resource, reason = %decision.reason, "mgmt access allowed");
        return next.run(req).await;
    }

    // Deny: audit + 403.
    let principal = req
        .extensions()
        .get::<ConnContext>()
        .and_then(|c| c.cert.as_ref())
        .and_then(|c| c.common_name.clone())
        .or_else(|| header_str(req.headers(), "x-auth-request-user"))
        .unwrap_or_else(|| "unknown".to_string());
    tracing::warn!(action, resource, principal = %principal, reason = %decision.reason, "mgmt access DENIED");
    if let Some(audit) = &st.security.audit {
        let mut entry = AuditEntry::new(AuditEventType::UnauthorizedClient)
            .with_username(&principal)
            .with_details(format!("mgmt {action} on {resource}: {}", decision.reason));
        if let Some(c) = req.extensions().get::<ConnContext>() {
            entry = entry.with_client_ip(c.peer.ip());
        }
        audit.log(entry).await;
    }
    (StatusCode::FORBIDDEN, format!("{}\n", decision.reason)).into_response()
}

/// Build the management API router. When `security.access_policy` is set, an
/// IAM-style authorization middleware is mounted ahead of the handlers.
#[cfg(feature = "observability")]
pub fn create_mgmt_server(
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
    policy_cfg: Arc<RwLock<PolicyConfig>>,
    policy_file: Option<Arc<str>>,
    security: MgmtSecurity,
) -> Router {
    let enforce = security.access_policy.is_some();
    let state = MgmtState::new(config, session_manager, policy_cfg, policy_file, security);
    let mut app = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/users", get(users))
        .route("/api/v1/sessions", get(sessions))
        .route("/api/v1/policy", get(policy).put(policy_put))
        .route("/api/v1/dictionary", get(dictionary_handler))
        .route("/api/v1/policy/dry-run", post(policy_dry_run));
    if enforce {
        app = app.layer(middleware::from_fn_with_state(state.clone(), authorize));
    }
    app.layer(TraceLayer::new_for_http()).with_state(state)
}

/// Start the management API server on `addr`.
///
/// Serving mode is chosen from `config.mgmt.tls`:
/// * with TLS configured (and the `tls` feature built in) the listener serves
///   HTTPS and, when `client_ca_path` is set, requires + verifies client
///   certificates (mTLS) and exposes the verified identity to the authorization
///   middleware;
/// * otherwise it serves plain HTTP. When no access policy is configured the API
///   is **unauthenticated** and a prominent warning is logged.
#[cfg(feature = "observability")]
pub async fn start_mgmt_server(
    config: Arc<Config>,
    session_manager: Arc<SharedSessionManager>,
    policy_cfg: Arc<RwLock<PolicyConfig>>,
    policy_file: Option<Arc<str>>,
    security: MgmtSecurity,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    if security.access_policy.is_none() {
        tracing::warn!(
            "management API is UNAUTHENTICATED (no mgmt.access_policy_file): anyone who can \
             reach {addr} can read state and REWRITE the live authorization policy. Configure \
             mgmt.tls + mgmt.access_policy_file to enforce IAM-style access control."
        );
    }

    #[cfg(feature = "tls")]
    let tls = config.mgmt.as_ref().and_then(|m| m.tls.clone());
    #[cfg(not(feature = "tls"))]
    let tls: Option<crate::config::MgmtTlsConfig> = None;

    let app = create_mgmt_server(config, session_manager, policy_cfg, policy_file, security);

    match tls {
        #[cfg(feature = "tls")]
        Some(tls) => {
            tracing::info!(
                "Starting management API on https://{} (mTLS: {})",
                addr,
                tls.client_ca_path.is_some()
            );
            serve_mtls(addr, app, &tls).await
        }
        _ => {
            tracing::info!("Starting management API on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

/// Serve the router over TLS, accepting connections in a loop and exposing each
/// verified client certificate to the request via a [`ConnContext`] extension.
/// Uses a manual `tokio-rustls` + `hyper-util` accept loop because `axum::serve`
/// does not surface the peer certificate to handlers.
#[cfg(all(feature = "observability", feature = "tls"))]
async fn serve_mtls(
    addr: SocketAddr,
    app: Router,
    tls: &crate::config::MgmtTlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let server_config = build_mgmt_server_config(tls)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("mgmt accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    // A failed handshake (incl. a missing/invalid client cert under
                    // mTLS) is expected noise from scanners — log at debug.
                    tracing::debug!("mgmt TLS handshake from {peer} failed: {e}");
                    return;
                }
            };
            let cert = {
                let (_io, conn) = tls_stream.get_ref();
                conn.peer_certificates()
                    .and_then(|chain| chain.first())
                    .and_then(parse_cert_identity)
                    .map(Arc::new)
            };
            let conn_ctx = ConnContext { cert, peer };
            let io = TokioIo::new(tls_stream);
            let hyper_service = service_fn(move |request: hyper::Request<Incoming>| {
                let mut app = app.clone();
                let conn_ctx = conn_ctx.clone();
                async move {
                    let mut req = request.map(Body::new);
                    req.extensions_mut().insert(conn_ctx);
                    app.call(req).await
                }
            });
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                tracing::debug!("mgmt connection from {peer} ended: {e}");
            }
        });
    }
}

/// Build a rustls `ServerConfig` for the management listener. When
/// `client_ca_path` is set, client certificates are required and verified against
/// that CA bundle (mTLS); otherwise the listener is server-authenticated only.
#[cfg(all(feature = "observability", feature = "tls"))]
fn build_mgmt_server_config(
    tls: &crate::config::MgmtTlsConfig,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&tls.cert_path)?.collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&tls.key_path)?;

    let builder = rustls::ServerConfig::builder();
    let config = if let Some(ca_path) = &tls.client_ca_path {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(ca_path)? {
            roots.add(c?)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    Ok(config.with_single_cert(certs, key)?)
}

/// Parse the leaf client certificate into a [`CertIdentity`] (CN, OU, SANs, and a
/// SHA-256 fingerprint) for ABAC conditions. Returns `None` if the cert can't be
/// parsed (the connection still proceeds with no cert identity).
#[cfg(all(feature = "observability", feature = "tls"))]
fn parse_cert_identity(der: &rustls::pki_types::CertificateDer<'_>) -> Option<CertIdentity> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    let fingerprint_sha256 = {
        let mut h = Sha256::new();
        h.update(der.as_ref());
        hex_lower(&h.finalize())
    };
    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
    let subject = cert.subject();
    let first = |it: Option<&x509_parser::x509::AttributeTypeAndValue>| {
        it.and_then(|a| a.as_str().ok()).map(str::to_string)
    };
    let common_name = first(subject.iter_common_name().next());
    let org_unit = first(subject.iter_organizational_unit().next());

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(s) | GeneralName::RFC822Name(s) | GeneralName::URI(s) => {
                    sans.push(s.to_string())
                }
                GeneralName::IPAddress(b) => sans.push(fmt_ip_bytes(b)),
                _ => {}
            }
        }
    }
    Some(CertIdentity {
        common_name,
        org_unit,
        sans,
        fingerprint_sha256,
    })
}

#[cfg(all(feature = "observability", feature = "tls"))]
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(all(feature = "observability", feature = "tls"))]
fn fmt_ip_bytes(b: &[u8]) -> String {
    match b.len() {
        4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => String::new(),
    }
}

#[cfg(all(test, feature = "observability"))]
mod tests {
    use super::*;
    use crate::access::{ConditionEntry, ConditionOp, Effect as AEffect, Statement};

    fn headers(user: &str, groups: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-auth-request-user", user.parse().unwrap());
        h.insert("x-auth-request-groups", groups.parse().unwrap());
        h
    }

    fn conn_with_cert(cn: &str, ip: &str) -> ConnContext {
        ConnContext {
            cert: Some(Arc::new(CertIdentity {
                common_name: Some(cn.into()),
                org_unit: None,
                sans: vec![],
                fingerprint_sha256: "ab".into(),
            })),
            peer: SocketAddr::new(ip.parse().unwrap(), 5555),
        }
    }

    #[test]
    fn route_action_maps_known_and_rejects_unknown() {
        assert_eq!(
            route_action(&Method::PUT, "/api/v1/policy"),
            Some(("radius:PutPolicy", "arn:usgradius:mgmt:::policy"))
        );
        assert_eq!(
            route_action(&Method::GET, "/api/v1/status"),
            Some(("radius:GetStatus", "arn:usgradius:mgmt:::status"))
        );
        // Method matters: GET /policy is a different action than PUT.
        assert_eq!(
            route_action(&Method::GET, "/api/v1/policy"),
            Some(("radius:GetPolicy", "arn:usgradius:mgmt:::policy"))
        );
        assert_eq!(route_action(&Method::DELETE, "/api/v1/policy"), None);
        assert_eq!(route_action(&Method::GET, "/api/v1/secret"), None);
    }

    #[test]
    fn context_merges_cert_and_headers() {
        let conn = conn_with_cert("usg-radius-bff", "10.0.0.9");
        let ctx = build_access_context(
            "radius:GetPolicy",
            "arn:usgradius:mgmt:::policy",
            &Method::GET,
            Some(&conn),
            &headers("alice", "operators, staff"),
            false,
        );
        // A policy requiring BOTH the cert CN and a (cert-gated) OIDC group plus a
        // source-IP CIDR only passes if all three were merged into the context.
        let pol = AccessPolicy {
            version: None,
            statements: vec![Statement {
                sid: Some("ok".into()),
                effect: AEffect::Allow,
                action: vec!["radius:GetPolicy".into()],
                resource: vec!["*".into()],
                condition: vec![
                    ConditionEntry {
                        operator: ConditionOp::StringEquals,
                        key: "tls:ClientCN".into(),
                        values: vec!["usg-radius-bff".into()],
                    },
                    ConditionEntry {
                        operator: ConditionOp::StringEquals,
                        key: "identity:Group".into(),
                        values: vec!["operators".into()],
                    },
                    ConditionEntry {
                        operator: ConditionOp::IpAddress,
                        key: "request:SourceIp".into(),
                        values: vec!["10.0.0.0/8".into()],
                    },
                ],
            }],
        };
        assert!(
            pol.evaluate("radius:GetPolicy", "arn:usgradius:mgmt:::policy", &ctx)
                .allowed
        );
    }

    #[test]
    fn forwarded_headers_ignored_without_cert_unless_trusted() {
        // No cert, trust_forwarded_identity = false → identity headers are dropped,
        // so a group-gated allow does NOT match (prevents header spoofing).
        let ctx_untrusted = build_access_context(
            "radius:GetStatus",
            "arn:usgradius:mgmt:::status",
            &Method::GET,
            None,
            &headers("mallory", "operators"),
            false,
        );
        let pol = AccessPolicy {
            version: None,
            statements: vec![Statement {
                sid: Some("ops".into()),
                effect: AEffect::Allow,
                action: vec!["radius:*".into()],
                resource: vec!["*".into()],
                condition: vec![ConditionEntry {
                    operator: ConditionOp::StringEquals,
                    key: "identity:Group".into(),
                    values: vec!["operators".into()],
                }],
            }],
        };
        assert!(
            !pol.evaluate(
                "radius:GetStatus",
                "arn:usgradius:mgmt:::status",
                &ctx_untrusted
            )
            .allowed,
            "spoofable headers must be ignored without mTLS"
        );

        // Same request but trust_forwarded_identity = true → headers honored.
        let ctx_trusted = build_access_context(
            "radius:GetStatus",
            "arn:usgradius:mgmt:::status",
            &Method::GET,
            None,
            &headers("mallory", "operators"),
            true,
        );
        assert!(
            pol.evaluate(
                "radius:GetStatus",
                "arn:usgradius:mgmt:::status",
                &ctx_trusted
            )
            .allowed
        );
    }

    #[test]
    fn reload_swaps_on_valid_and_keeps_old_on_invalid() {
        use std::io::Write;

        // Start with a policy that denies everything (empty = default deny).
        let cell: SharedAccessPolicy = Arc::new(RwLock::new(Arc::new(AccessPolicy::default())));
        let ctx = AccessContext::new();
        assert!(
            !cell
                .read()
                .unwrap()
                .evaluate("radius:GetStatus", "x", &ctx)
                .allowed
        );

        // Reload a valid policy that allows GetStatus → the cell swaps.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{"statements":[{{"sid":"a","effect":"Allow","action":["radius:GetStatus"],"resource":["*"]}}]}}"#
        )
        .unwrap();
        let path = f.path().to_str().unwrap().to_string();
        reload_access_policy(&cell, &path).expect("valid reload");
        assert!(
            cell.read()
                .unwrap()
                .evaluate("radius:GetStatus", "x", &ctx)
                .allowed
        );

        // A subsequent invalid file (statement with no actions) is rejected and the
        // previously-enforced policy is kept — reload never fails open.
        let mut bad = tempfile::NamedTempFile::new().unwrap();
        write!(
            bad,
            r#"{{"statements":[{{"effect":"Allow","action":[],"resource":["*"]}}]}}"#
        )
        .unwrap();
        let bad_path = bad.path().to_str().unwrap().to_string();
        assert!(reload_access_policy(&cell, &bad_path).is_err());
        assert!(
            cell.read()
                .unwrap()
                .evaluate("radius:GetStatus", "x", &ctx)
                .allowed,
            "invalid reload must keep the previous policy"
        );
    }
}
