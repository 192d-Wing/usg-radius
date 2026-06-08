// SPDX-License-Identifier: Apache-2.0
//! BFF request handlers: identity, server health, and a parsed metrics overview.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

/// Identity forwarded by oauth2-proxy. Falls back to "operator" in local/dev.
pub async fn me(headers: HeaderMap) -> Json<Value> {
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let groups = h("x-auth-request-groups")
        .map(|g| g.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_else(Vec::new);
    Json(json!({
        "user": h("x-auth-request-user"),
        "email": h("x-auth-request-email"),
        "groups": groups,
    }))
}

/// Proxy the RADIUS server's readiness probe.
pub async fn health(State(st): State<AppState>) -> Json<Value> {
    let url = format!("{}/health/ready", st.radius_health_url);
    match st.http.get(&url).send().await {
        Ok(r) => Json(json!({ "ready": r.status().is_success(), "detail": r.status().to_string() })),
        Err(e) => Json(json!({ "ready": false, "detail": e.to_string() })),
    }
}

#[derive(Serialize)]
pub struct Metric {
    name: String,
    value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

/// Scrape the RADIUS `/metrics` endpoint (Prometheus text) and shape a small
/// overview for the dashboard.
pub async fn overview(State(st): State<AppState>) -> Result<Json<Value>, (axum::http::StatusCode, String)> {
    let url = format!("{}/metrics", st.radius_metrics_url);
    let body = st
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e.to_string()))?
        .text()
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e.to_string()))?;

    let metrics = parse_prometheus(&body);

    let find = |name: &str| metrics.iter().find(|m| m.name == name);
    let backend = find("radius_backend_up")
        .and_then(|m| m.labels.as_ref())
        .and_then(|l| l.get("backend"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let backend_up = find("radius_backend_up").map(|m| m.value >= 1.0).unwrap_or(false);
    let uptime = find("radius_uptime_seconds").map(|m| m.value).unwrap_or(f64::NAN);
    let cache = find("radius_cache_entries").map(|m| m.value).unwrap_or(0.0);

    Ok(Json(json!({
        "backend": backend,
        "backend_up": backend_up,
        "uptime_seconds": uptime,
        "cache_entries": cache,
        "metrics": metrics,
    })))
}

/// Proxy a request to the RADIUS management API. Reads the response body as text
/// and only parses JSON on success, so a non-2xx upstream error (which may be a
/// plain-text validation message, not JSON) is passed through with its real status
/// and body instead of being masked as a generic 502.
async fn proxy(
    st: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Json<Value>, (axum::http::StatusCode, String)> {
    let url = format!("{}{}", st.radius_api_url, path);
    let mut req = st.http.request(method, &url);
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e.to_string()))?;
    let code = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let text = resp
        .text()
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !code.is_success() {
        // Pass the upstream status + body (often a plain-text error) through.
        return Err((code, text));
    }
    let out = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e.to_string()))?
    };
    Ok(Json(out))
}

type ProxyResult = Result<Json<Value>, (axum::http::StatusCode, String)>;

pub async fn status(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/status", None).await
}
pub async fn clients(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/clients", None).await
}
pub async fn users(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/users", None).await
}
pub async fn sessions(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/sessions", None).await
}
pub async fn policy_get(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/policy", None).await
}
pub async fn dictionary(State(st): State<AppState>) -> ProxyResult {
    proxy(&st, reqwest::Method::GET, "/api/v1/dictionary", None).await
}
/// PUT a new policy to the management API (validate + persist); 4xx body passes through.
pub async fn policy_put(State(st): State<AppState>, Json(body): Json<Value>) -> ProxyResult {
    proxy(&st, reqwest::Method::PUT, "/api/v1/policy", Some(&body)).await
}
/// POST a candidate policy + request to the dry-run endpoint and return the decision.
pub async fn policy_dry_run(State(st): State<AppState>, Json(body): Json<Value>) -> ProxyResult {
    proxy(&st, reqwest::Method::POST, "/api/v1/policy/dry-run", Some(&body)).await
}

/// Minimal Prometheus text-format parser: one entry per non-comment sample line
/// of the form `name{labels} value` (labels optional).
fn parse_prometheus(body: &str) -> Vec<Metric> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split off the trailing value (last whitespace-separated token).
        let Some((series, value_str)) = line.rsplit_once(char::is_whitespace) else {
            continue;
        };
        let Ok(value) = value_str.trim().parse::<f64>() else {
            continue;
        };
        let (name, labels) = match series.split_once('{') {
            Some((name, rest)) => {
                let rest = rest.trim_end_matches('}');
                let mut map = std::collections::BTreeMap::new();
                for pair in rest.split(',') {
                    if let Some((k, v)) = pair.split_once('=') {
                        map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
                    }
                }
                (name.to_string(), (!map.is_empty()).then_some(map))
            }
            None => (series.to_string(), None),
        };
        out.push(Metric { name, value, labels });
    }
    out
}
