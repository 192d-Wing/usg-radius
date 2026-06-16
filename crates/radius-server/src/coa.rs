//! Server-originated CoA / Disconnect (RFC 5176) over the established RadSec
//! connection.
//!
//! RadSec is one long-lived TLS connection per NAS, opened by the NAS. To send a
//! Disconnect-Request / CoA-Request the server writes it *back* over that same
//! connection (server→NAS) and correlates the NAS's ACK/NAK by RADIUS Identifier.
//!
//! [`NasRegistry`] maps an authenticated NAS identity (its client-cert CN) to a
//! channel into its live connection task. A trigger (the management API) calls
//! [`NasRegistry::send`]; the connection task ([`crate::radsec`]) allocates the
//! Identifier, computes the Request Authenticator, writes the frame, and routes
//! the matching reply back.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use radius_proto::{Attribute, AttributeType, Code, Packet, PacketError};
use tokio::sync::{mpsc, oneshot};

/// A pending server-originated request handed to a connection task.
#[derive(Debug)]
pub struct CoaJob {
    /// The request with its code and identifying/change attributes set; the
    /// connection task fills in the Identifier and Request Authenticator.
    pub request: Packet,
    /// Where the connection task delivers the NAS's ACK/NAK packet.
    pub reply: oneshot::Sender<Packet>,
}

/// Errors originating a CoA / Disconnect.
#[derive(Debug, thiserror::Error)]
pub enum CoaError {
    #[error("NAS '{0}' is not connected over RadSec")]
    NasNotConnected(String),
    #[error("no free RADIUS Identifier on the connection (256 requests in flight)")]
    NoFreeIdentifier,
    #[error("timed out waiting for the NAS to answer")]
    Timeout,
    #[error("the RadSec connection closed before the NAS answered")]
    ConnectionClosed,
    #[error("failed to encode request: {0}")]
    Encode(#[from] PacketError),
}

/// Identifying attributes that let the NAS match the target session (RFC 5176
/// §2.3). At least one should be set; the NAS NAKs with Session-Context-Not-Found
/// (503) if nothing matches.
#[derive(Debug, Default, Clone)]
pub struct SessionKey {
    pub acct_session_id: Option<String>,
    pub calling_station_id: Option<String>,
    pub nas_port_id: Option<String>,
}

impl SessionKey {
    fn apply(&self, packet: &mut Packet) {
        if let Some(v) = &self.acct_session_id
            && let Ok(a) = Attribute::string(AttributeType::AcctSessionId as u8, v.clone())
        {
            packet.add_attribute(a);
        }
        if let Some(v) = &self.calling_station_id
            && let Ok(a) = Attribute::string(AttributeType::CallingStationId as u8, v.clone())
        {
            packet.add_attribute(a);
        }
        if let Some(v) = &self.nas_port_id
            && let Ok(a) = Attribute::string(AttributeType::NasPortId as u8, v.clone())
        {
            packet.add_attribute(a);
        }
    }
}

/// Build a Disconnect-Request (RFC 5176): terminate the matched session.
#[must_use]
pub fn disconnect_request(session: &SessionKey) -> Packet {
    let mut p = Packet::new(Code::DisconnectRequest, 0, [0u8; 16]);
    session.apply(&mut p);
    p
}

/// Build a CoA-Request (RFC 5176): apply `changes` (e.g. a new Filter-Id or VLAN)
/// to the matched session in place.
#[must_use]
pub fn coa_request(session: &SessionKey, changes: Vec<Attribute>) -> Packet {
    let mut p = Packet::new(Code::CoaRequest, 0, [0u8; 16]);
    session.apply(&mut p);
    for c in changes {
        p.add_attribute(c);
    }
    p
}

/// Registry of live RadSec connections, keyed by the NAS client-cert identity
/// (CN). Shared between the RadSec listener (which registers connections) and the
/// trigger that originates CoA/Disconnect.
#[derive(Debug, Default)]
pub struct NasRegistry {
    // value = (registration token, sender into the connection task). The token
    // lets a connection deregister only its *own* entry, so a reconnect that
    // replaced it isn't clobbered when the stale connection drops.
    conns: DashMap<String, (u64, mpsc::Sender<CoaJob>)>,
    next_token: AtomicU64,
}

impl NasRegistry {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a connection's job channel under `nas_id`. Returns a guard that
    /// deregisters exactly this registration on drop. A newer registration for
    /// the same id replaces this one (last connection wins).
    pub fn register(self: &Arc<Self>, nas_id: String, tx: mpsc::Sender<CoaJob>) -> ConnGuard {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        self.conns.insert(nas_id.clone(), (token, tx));
        ConnGuard {
            registry: Arc::clone(self),
            nas_id,
            token,
        }
    }

    /// The NAS identities (cert CNs) with a live RadSec connection.
    #[must_use]
    pub fn connected(&self) -> Vec<String> {
        self.conns.iter().map(|e| e.key().clone()).collect()
    }

    /// Send a CoA/Disconnect `request` to `nas_id` and await its ACK/NAK.
    ///
    /// # Errors
    /// [`CoaError::NasNotConnected`] if no live connection, [`CoaError::Timeout`]
    /// if the NAS doesn't answer in `timeout`, or [`CoaError::ConnectionClosed`].
    pub async fn send(
        &self,
        nas_id: &str,
        request: Packet,
        timeout: Duration,
    ) -> Result<Packet, CoaError> {
        let tx = self
            .conns
            .get(nas_id)
            .map(|e| e.value().1.clone())
            .ok_or_else(|| CoaError::NasNotConnected(nas_id.to_string()))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(CoaJob {
            request,
            reply: reply_tx,
        })
        .await
        .map_err(|_| CoaError::ConnectionClosed)?;

        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(packet)) => Ok(packet),
            Ok(Err(_)) => Err(CoaError::ConnectionClosed),
            Err(_) => Err(CoaError::Timeout),
        }
    }
}

/// Deregisters a connection's registry entry on drop (connection close).
#[derive(Debug)]
pub struct ConnGuard {
    registry: Arc<NasRegistry>,
    nas_id: String,
    token: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        // Only remove if this exact registration is still current — a reconnect
        // may have replaced it with a newer token.
        self.registry
            .conns
            .remove_if(&self.nas_id, |_, (t, _)| *t == self.token);
    }
}
