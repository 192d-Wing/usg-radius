//! Audit logging for RADIUS authentication events
//!
//! Provides structured JSON logging for security compliance and forensic analysis.
//! All authentication attempts, access decisions, and security events are logged.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{error, info};

enum AuditSink {
    File(Arc<Mutex<std::fs::File>>),
    Stdout,
}

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication attempt
    AuthAttempt,
    /// Authentication success
    AuthSuccess,
    /// Authentication failure
    AuthFailure,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Unauthorized client
    UnauthorizedClient,
    /// Duplicate request detected
    DuplicateRequest,
    /// Server started
    ServerStart,
    /// Server stopped
    ServerStop,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// ISO 8601 formatted timestamp
    pub timestamp_iso: String,
    /// Event type
    pub event_type: AuditEventType,
    /// Username (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Client IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Client name (from configuration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Request identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u8>,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Server version
    pub server_version: String,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(event_type: AuditEventType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let timestamp = now.as_secs();
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        AuditEntry {
            timestamp,
            timestamp_iso,
            event_type,
            username: None,
            client_ip: None,
            client_name: None,
            request_id: None,
            details: None,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Set username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set client IP
    pub fn with_client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip.to_string());
        self
    }

    /// Set client name
    pub fn with_client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    /// Set request ID
    pub fn with_request_id(mut self, id: u8) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Set details
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Audit logger
///
/// Sinks: a filesystem path, or the literal value `"stdout"` / `"-"` to emit
/// JSON-Lines on stdout (12-factor / Kubernetes friendly).
pub struct AuditLogger {
    file_path: Option<String>,
    sink: Option<AuditSink>,
}

impl AuditLogger {
    pub fn new(file_path: Option<String>) -> std::io::Result<Self> {
        let sink = match file_path.as_deref() {
            None => None,
            Some("stdout") | Some("-") => Some(AuditSink::Stdout),
            Some(path) => {
                let f = OpenOptions::new().create(true).append(true).open(path)?;
                Some(AuditSink::File(Arc::new(Mutex::new(f))))
            }
        };
        Ok(AuditLogger { file_path, sink })
    }

    pub async fn log(&self, entry: AuditEntry) {
        let Some(ref sink) = self.sink else { return };
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize audit entry: {}", e);
                return;
            }
        };
        match sink {
            AuditSink::File(file) => {
                let mut f = file.lock().await;
                if let Err(e) = writeln!(f, "{}", json) {
                    error!("Failed to write audit log: {}", e);
                }
            }
            AuditSink::Stdout => {
                info!(target: "audit", "{}", json);
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.sink.is_some()
    }

    pub fn file_path(&self) -> Option<&str> {
        self.file_path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(AuditEventType::AuthSuccess)
            .with_username("testuser")
            .with_client_ip("192.168.1.1".parse().unwrap())
            .with_request_id(42);

        assert_eq!(entry.username, Some("testuser".to_string()));
        assert_eq!(entry.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(entry.request_id, Some(42));
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry::new(AuditEventType::AuthFailure)
            .with_username("baduser")
            .with_client_ip("10.0.0.1".parse().unwrap())
            .with_details("Invalid password");

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("auth_failure"));
        assert!(json.contains("baduser"));
        assert!(json.contains("10.0.0.1"));
    }

    #[tokio::test]
    async fn test_audit_logger() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap().to_string();

        let logger = AuditLogger::new(Some(path.clone())).unwrap();
        assert!(logger.is_enabled());

        let entry = AuditEntry::new(AuditEventType::AuthSuccess)
            .with_username("testuser")
            .with_client_ip("192.168.1.1".parse().unwrap());

        logger.log(entry).await;

        // Read the file and verify
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("auth_success"));
        assert!(contents.contains("testuser"));
    }

    #[test]
    fn test_audit_logger_disabled() {
        let logger = AuditLogger::new(None).unwrap();
        assert!(!logger.is_enabled());
    }
}
