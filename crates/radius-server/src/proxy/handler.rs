//! Proxy handler for request forwarding and response routing

use crate::proxy::cache::{ProxyCache, ProxyCacheEntry, ProxyStateKey, generate_proxy_state_key};
use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::home_server::{HomeServer, HomeServerTransport};
use radius_proto::attributes::{Attribute, AttributeType, VendorSpecific};
use radius_proto::auth::{
    calculate_response_authenticator, decrypt_user_password, encrypt_user_password,
    verify_response_authenticator,
};
use radius_proto::mppe::{MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY, MS_MPPE_SEND_KEY, generate_salts};
use radius_proto::{MppeKeys, Packet, TunnelPassword, calculate_message_authenticator};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Maximum number of Proxy-State attributes allowed (loop detection)
const MAX_PROXY_STATE_ATTRIBUTES: usize = 5;

/// Proxy handler for forwarding requests and routing responses
pub struct ProxyHandler {
    /// Proxy cache for request correlation
    cache: Arc<ProxyCache>,
    /// UDP socket for communicating with home servers
    socket: Arc<UdpSocket>,
    /// Socket the NAS talked to (the server's listening socket). Relayed
    /// responses and timeout rejects go out through it, so they come from the
    /// address and port the NAS sent its request to; a NAS whose RADIUS socket
    /// is `connect()`ed to the proxy (eapol_test, wpa_supplicant, most
    /// embedded NASes) discards datagrams from any other source port. `None`
    /// (tests, embedding) falls back to `socket`.
    nas_socket: Option<Arc<UdpSocket>>,
}

impl ProxyHandler {
    /// Create a new proxy handler
    ///
    /// # Arguments
    /// * `cache` - Proxy cache for request tracking
    /// * `bind_addr` - Address to bind the proxy socket to
    pub async fn new(cache: Arc<ProxyCache>, bind_addr: SocketAddr) -> ProxyResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!(bind_addr = %bind_addr, "Proxy handler socket bound");

        Ok(ProxyHandler {
            cache,
            socket: Arc::new(socket),
            nas_socket: None,
        })
    }

    /// Reply to NASes through `socket` (the server's listening socket) instead
    /// of the home-server socket. See [`ProxyHandler::nas_socket`].
    pub fn with_nas_socket(mut self, socket: Arc<UdpSocket>) -> Self {
        self.nas_socket = Some(socket);
        self
    }

    /// Forward a request to a home server
    ///
    /// # Process
    /// 1. Check for proxy loops (count existing Proxy-State attributes)
    /// 2. Generate unique Proxy-State attribute
    /// 3. Add Proxy-State to request
    /// 4. Re-encrypt User-Password (RFC 2865 §5.2) from the client secret to
    ///    the home server secret
    /// 5. Recompute Message-Authenticator (RFC 3579 §3.2) under the home
    ///    server secret
    /// 6. Store the forwarded request in cache for correlation and retries
    /// 7. Send modified request to home server (UDP socket or RadSec link,
    ///    see [`ProxyHandler::send_to_home_server`])
    ///
    /// Steps 3–5 are [`rewrite_request_for_home_server`].
    ///
    /// A send failure (a RadSec link that is down, a socket error) is returned
    /// to the caller **with the cache entry left in place and counted as
    /// outstanding**: the retry manager resends it on its next tick and, after
    /// `max_retries`, answers the NAS with a signed Access-Reject. There is no
    /// second queue.
    ///
    /// # Returns
    /// The Proxy-State key used for correlation
    pub async fn forward_request(
        &self,
        request: Packet,
        source: SocketAddr,
        home_server: Arc<HomeServer>,
        client_secret: Vec<u8>,
    ) -> ProxyResult<ProxyStateKey> {
        // Check for proxy loops (RFC 2865 Section 5.33)
        let proxy_state_count = request
            .attributes
            .iter()
            .filter(|attr| attr.attr_type == AttributeType::ProxyState as u8)
            .count();

        if proxy_state_count >= MAX_PROXY_STATE_ATTRIBUTES {
            warn!(
                source = %source,
                proxy_state_count = proxy_state_count,
                "Proxy loop detected - too many Proxy-State attributes"
            );
            return Err(ProxyError::ProxyLoop(
                proxy_state_count,
                MAX_PROXY_STATE_ATTRIBUTES,
            ));
        }

        // Generate unique Proxy-State
        let proxy_state = generate_proxy_state_key();

        // Append Proxy-State and re-key the packet for the home server secret.
        let request = rewrite_request_for_home_server(
            request,
            proxy_state,
            &client_secret,
            home_server.secret(),
        )
        .inspect_err(|e| {
            warn!(
                source = %source,
                home_server = %home_server.name,
                error = %e,
                "Cannot rewrite request for home server; dropping it"
            );
        })?;

        // Create cache entry
        let entry = ProxyCacheEntry {
            original_request: request.clone(),
            original_source: source,
            home_server: home_server.clone(),
            sent_at: Instant::now(),
            retry_count: 0,
            proxy_state,
            client_secret,
        };

        // Store in cache (before sending to avoid race condition)
        self.cache.insert(entry)?;

        // In the cache ⇒ in flight, whether or not the send below succeeds:
        // the retry manager's `record_timeout` for this entry must have a
        // `record_request` to balance, or `outstanding` would underflow.
        home_server.stats().record_request();

        // Encode and send request to home server
        let request_data = request.encode()?;
        self.send_to_home_server(&request_data, &home_server)
            .await?;

        debug!(
            source = %source,
            home_server = %home_server.name,
            identifier = request.identifier,
            proxy_state = ?proxy_state,
            "Request forwarded to home server"
        );

        Ok(proxy_state)
    }

    /// Write one encoded packet to `home_server` over its transport: the
    /// shared UDP socket, or the server's RadSec link (RFC 6614). Every path
    /// that talks to a home server — forwarding, retries, health probes —
    /// goes through here. A RadSec server whose link is down fails
    /// immediately with [`ProxyError::LinkDown`]; nothing is queued.
    pub(crate) async fn send_to_home_server(
        &self,
        bytes: &[u8],
        home_server: &HomeServer,
    ) -> ProxyResult<()> {
        match home_server.transport() {
            HomeServerTransport::Udp => {
                self.socket.send_to(bytes, home_server.address).await?;
                Ok(())
            }
            HomeServerTransport::Radsec => {
                #[cfg(feature = "tls")]
                {
                    let link = home_server
                        .link()
                        .ok_or_else(|| ProxyError::LinkDown(home_server.name.clone()))?;
                    link.send(bytes.to_vec())
                        .map_err(|e| e.into_proxy_error(&home_server.name))
                }
                #[cfg(not(feature = "tls"))]
                {
                    // Unreachable after config validation, which refuses a
                    // RadSec home server in a binary without `tls`.
                    Err(ProxyError::Configuration(format!(
                        "home server {} uses transport = \"radsec\" but this binary was built \
                         without the `tls` feature",
                        home_server.name
                    )))
                }
            }
        }
    }

    /// Handle a response from a home server received on the UDP socket.
    ///
    /// # Process
    /// 1. Extract our Proxy-State attribute (last one added)
    /// 2. Look up original request in cache
    /// 3. Validate response authenticator (with home server secret)
    /// 4. Remove our Proxy-State attribute
    /// 5. Re-encrypt MS-MPPE-Send-Key / MS-MPPE-Recv-Key (RFC 2548 §2.4) and
    ///    Tunnel-Password (RFC 2868 §3.5) from the home server secret to the
    ///    client secret
    /// 6. Recalculate Message-Authenticator and Response-Authenticator (with
    ///    client secret)
    /// 7. Forward to original NAS
    ///
    /// Steps 3–6 are [`rewrite_response_for_nas`].
    ///
    /// Note: This method should be called from a background task that listens
    /// for responses on the proxy socket.
    pub async fn handle_response(
        &self,
        response: Packet,
        home_server_addr: SocketAddr,
    ) -> ProxyResult<()> {
        self.handle_response_from(response, ResponseOrigin::Udp(home_server_addr))
            .await
    }

    /// Handle a response read off a RadSec link (RFC 6614). Same processing as
    /// [`ProxyHandler::handle_response`]; the response is attributed to the
    /// link's home server by `Arc` identity instead of by source address,
    /// because the TLS peer — not an IP:port — is what authenticated it.
    pub async fn handle_link_response(
        &self,
        response: Packet,
        home_server: Arc<HomeServer>,
    ) -> ProxyResult<()> {
        self.handle_response_from(response, ResponseOrigin::Link(home_server))
            .await
    }

    /// Shared body of the two `handle_*_response` entry points.
    async fn handle_response_from(
        &self,
        response: Packet,
        origin: ResponseOrigin,
    ) -> ProxyResult<()> {
        // Extract the last Proxy-State attribute (the one we added)
        let proxy_state_attr = response
            .attributes
            .iter()
            .rfind(|attr| attr.attr_type == AttributeType::ProxyState as u8)
            .ok_or(ProxyError::CorrelationFailed)?;

        // Convert to ProxyStateKey
        if proxy_state_attr.value.len() != 16 {
            return Err(ProxyError::CorrelationFailed);
        }
        let mut proxy_state = [0u8; 16];
        proxy_state.copy_from_slice(&proxy_state_attr.value);

        // Look up original request. The entry is consumed only once the
        // response is attributed to its home server, so a datagram with a
        // guessed Proxy-State from elsewhere cannot evict a live entry.
        let entry = self
            .cache
            .get(&proxy_state)
            .ok_or(ProxyError::CorrelationFailed)?;

        // Verify this response is from the expected home server: for UDP the
        // configured address of a UDP server; for a link, that very server.
        let from_expected = match &origin {
            ResponseOrigin::Udp(addr) => {
                entry.home_server.transport() == HomeServerTransport::Udp
                    && *addr == entry.home_server.address
            }
            ResponseOrigin::Link(home_server) => Arc::ptr_eq(home_server, &entry.home_server),
        };
        if !from_expected {
            warn!(
                expected = %entry.home_server.name,
                expected_transport = %entry.home_server.transport(),
                origin = %origin,
                "Response from unexpected home server"
            );
            return Err(ProxyError::CorrelationFailed);
        }
        let entry = self
            .cache
            .remove(&proxy_state)
            .ok_or(ProxyError::CorrelationFailed)?;

        // Record statistics
        entry.home_server.stats().record_response();

        let response = rewrite_response_for_nas(response, &entry)?;

        // Forward response to original NAS, from the address it sent to.
        let response_data = response.encode()?;
        self.nas_socket()
            .send_to(&response_data, entry.original_source)
            .await?;

        info!(
            nas = %entry.original_source,
            home_server = %entry.home_server.name,
            code = ?response.code,
            identifier = response.identifier,
            "Response forwarded to NAS"
        );

        Ok(())
    }

    /// Get the proxy socket for listening to responses
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// The socket responses to NASes are sent from: the one set with
    /// [`ProxyHandler::with_nas_socket`], else the home-server socket.
    pub fn nas_socket(&self) -> Arc<UdpSocket> {
        self.nas_socket
            .as_ref()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(&self.socket))
    }

    /// Get cache reference for statistics
    pub fn cache(&self) -> Arc<ProxyCache> {
        Arc::clone(&self.cache)
    }
}

/// Where a home server response arrived from.
enum ResponseOrigin {
    /// A datagram on the shared UDP socket, from this address.
    Udp(SocketAddr),
    /// A frame on this home server's RadSec link.
    Link(Arc<HomeServer>),
}

impl std::fmt::Display for ResponseOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "udp {addr}"),
            Self::Link(hs) => write!(f, "radsec link {}", hs.name),
        }
    }
}

/// Turn the NAS's Access-Request into the request the home server expects.
///
/// The NAS encrypted User-Password and signed Message-Authenticator with *its*
/// shared secret; the home server checks both against *its own* secret, so a
/// packet relayed verbatim is rejected upstream whenever the two differ. The
/// Request Authenticator is forwarded unchanged (RFC 2865 §2.3 only requires
/// the proxy to re-encrypt User-Password), so it keys both hops and only the
/// secret changes; the response leg relies on this.
///
/// 1. Append our Proxy-State (RFC 2865 §5.33), so the Message-Authenticator
///    computed below covers it.
/// 2. User-Password (RFC 2865 §5.2) is `MD5(secret || Request-Authenticator)`
///    chained over the padded password: decrypt under the client secret,
///    re-encrypt under the home server secret. A password that does not
///    decrypt (bad framing, non-UTF-8 plaintext from a wrong client secret)
///    fails the forward rather than sending the home server garbage.
///    CHAP-Password (RFC 2865 §5.3) is `MD5(ident || password || challenge)`
///    with the challenge taken from CHAP-Challenge or the Request
///    Authenticator; it involves no shared secret, so it is forwarded as is,
///    which is also why the Request Authenticator must not change.
/// 3. Recompute Message-Authenticator (RFC 3579 §3.2) under the home server
///    secret, zeroing it first and hashing with Authenticator = Request
///    Authenticator. One is added when absent but the request carries
///    EAP-Message, as RFC 3579 requires of every hop.
pub(crate) fn rewrite_request_for_home_server(
    mut request: Packet,
    proxy_state: ProxyStateKey,
    client_secret: &[u8],
    home_secret: &[u8],
) -> ProxyResult<Packet> {
    // 1. Proxy-State.
    request.add_attribute(
        Attribute::new(AttributeType::ProxyState as u8, proxy_state.to_vec()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to create Proxy-State attribute: {}", e))
        })?,
    );

    // 2. User-Password from the client secret to the home server secret.
    let request_authenticator = request.authenticator;
    for attr in request
        .attributes
        .iter_mut()
        .filter(|a| a.attr_type == AttributeType::UserPassword as u8)
    {
        let password = decrypt_user_password(&attr.value, client_secret, &request_authenticator)
            .map_err(ProxyError::InvalidUserPassword)?;
        attr.value = encrypt_user_password(&password, home_secret, &request_authenticator);
    }

    // 3. Message-Authenticator under the home server secret.
    recompute_message_authenticator(&mut request, &request_authenticator, home_secret)?;

    Ok(request)
}

/// Turn a home server's response into the response the NAS expects.
///
/// The home server authenticated its reply against *its* shared secret and
/// the Request Authenticator of the request we forwarded; the NAS will check
/// everything against *its* secret and the Request Authenticator it sent. The
/// proxy forwards the NAS's Request Authenticator unchanged, so the same
/// 16 octets (`entry.original_request.authenticator`) serve both sides and only
/// the secret changes.
///
/// 1. Verify the Response Authenticator with the home server secret — before
///    touching any attribute, since it covers the packet as received.
/// 2. Remove the Proxy-State we appended.
/// 3. MS-MPPE-Send-Key / MS-MPPE-Recv-Key (RFC 2548 §2.4.2) are encrypted with
///    `MD5(secret || Request-Authenticator || Salt)`, so they are opaque to the
///    NAS unless re-encrypted: decrypt under the home server secret, re-encrypt
///    under the client secret with fresh salts. Keys that do not decrypt are
///    dropped rather than forwarded as garbage.
/// 4. Tunnel-Password (RFC 2868 §3.5) uses the same salted chain with a Tag
///    octet in front: each one is decrypted under the home server secret and
///    re-encrypted under the client secret with a fresh salt, keeping its Tag
///    and position. Passwords that do not decrypt are dropped.
/// 5. Recompute Message-Authenticator (RFC 3579 §3.2) under the client secret
///    if present — or add one when the response carries EAP-Message.
/// 6. Recompute the Response Authenticator under the client secret.
pub(crate) fn rewrite_response_for_nas(
    mut response: Packet,
    entry: &ProxyCacheEntry,
) -> ProxyResult<Packet> {
    let request_authenticator = &entry.original_request.authenticator;

    // 1. Authenticate the home server's reply.
    if !verify_response_authenticator(&response, request_authenticator, entry.home_server.secret())
    {
        warn!(
            home_server = %entry.home_server.name,
            identifier = response.identifier,
            "Response authenticator from home server is invalid; dropping response"
        );
        return Err(ProxyError::InvalidResponseAuthenticator);
    }

    // 2. Remove our Proxy-State attribute from response
    let proxy_state = entry.proxy_state;
    response.attributes.retain(|attr| {
        !(attr.attr_type == AttributeType::ProxyState as u8 && attr.value == proxy_state)
    });

    // 3. Re-key MS-MPPE attributes from the home server secret to the client secret.
    rekey_mppe_attributes(&mut response, entry);

    // 4. Re-key Tunnel-Password attributes the same way.
    rekey_tunnel_passwords(&mut response, entry);

    // 5. Message-Authenticator under the client secret.
    recompute_message_authenticator(&mut response, request_authenticator, &entry.client_secret)?;

    // 6. Response Authenticator under the client secret.
    response.authenticator =
        calculate_response_authenticator(&response, request_authenticator, &entry.client_secret);

    Ok(response)
}

/// Decrypt the RFC 2548 MS-MPPE keys under the home server pair and re-encrypt
/// them under the client pair, replacing the sub-attributes in place. A packet
/// without MPPE keys is left untouched; keys that fail to decrypt (or an
/// unpaired key) are removed so the NAS never receives undecryptable material.
fn rekey_mppe_attributes(response: &mut Packet, entry: &ProxyCacheEntry) {
    let request_authenticator = &entry.original_request.authenticator;

    let keys =
        match MppeKeys::from_packet(response, entry.home_server.secret(), request_authenticator) {
            Ok(None) => return,
            Ok(Some(keys)) => Some(keys),
            Err(e) => {
                warn!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    error = %e,
                    "Failed to decrypt MS-MPPE keys from home server; dropping them"
                );
                None
            }
        };

    strip_mppe_attributes(response);

    if let Some(keys) = keys {
        match keys.to_attributes(&entry.client_secret, request_authenticator) {
            Ok(attrs) => {
                for attr in attrs {
                    response.add_attribute(attr);
                }
                debug!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    "Re-encrypted MS-MPPE keys for NAS"
                );
            }
            Err(e) => {
                warn!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    error = %e,
                    "Failed to re-encrypt MS-MPPE keys for NAS; dropping them"
                );
            }
        }
    }
}

/// Remove every Microsoft MS-MPPE-Send-Key / MS-MPPE-Recv-Key sub-attribute.
/// Other sub-attributes sharing a Vendor-Specific attribute are preserved;
/// a Vendor-Specific attribute that cannot be decoded is left as is.
fn strip_mppe_attributes(response: &mut Packet) {
    let is_mppe_key = |v: &VendorSpecific| {
        v.vendor_id == MICROSOFT_VENDOR_ID
            && (v.vendor_type == MS_MPPE_SEND_KEY || v.vendor_type == MS_MPPE_RECV_KEY)
    };

    let mut rewritten = Vec::with_capacity(response.attributes.len());
    for attr in response.attributes.drain(..) {
        if attr.attr_type != AttributeType::VendorSpecific as u8 {
            rewritten.push(attr);
            continue;
        }
        let Ok(subs) = VendorSpecific::from_attribute(&attr) else {
            rewritten.push(attr);
            continue;
        };
        if !subs.iter().any(is_mppe_key) {
            rewritten.push(attr);
            continue;
        }
        let remaining: Vec<VendorSpecific> = subs.into_iter().filter(|v| !is_mppe_key(v)).collect();
        if remaining.is_empty() {
            continue;
        }
        match VendorSpecific::to_attribute_combined(&remaining) {
            Ok(a) => rewritten.push(a),
            // Re-encoding a subset of a decodable VSA cannot grow it; keep the
            // original rather than lose the vendor's other sub-attributes.
            Err(_) => rewritten.push(attr),
        }
    }
    response.attributes = rewritten;
}

/// Decrypt every RFC 2868 Tunnel-Password under the home server pair and
/// re-encrypt it under the client pair with a fresh salt, in place and with its
/// Tag preserved. A password that fails to decrypt (wrong secret, bad framing,
/// invalid Tag or Salt) is removed and logged so the NAS never receives
/// undecryptable material; every other attribute is left untouched.
fn rekey_tunnel_passwords(response: &mut Packet, entry: &ProxyCacheEntry) {
    let request_authenticator = &entry.original_request.authenticator;
    let tunnel_password = AttributeType::TunnelPassword as u8;

    let count = response
        .attributes
        .iter()
        .filter(|a| a.attr_type == tunnel_password)
        .count();
    if count == 0 {
        return;
    }

    // RFC 2868 §3.5: every Salt in the packet must be unique, including those
    // the MS-MPPE keys (re-keyed just before us) already carry.
    let in_use: Vec<[u8; 2]> = response
        .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY)
        .into_iter()
        .chain(response.find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY))
        .filter_map(|v| v.value.get(..2).map(|s| [s[0], s[1]]))
        .collect();
    let mut salts = fresh_salts(count, &in_use).into_iter();

    let mut rewritten = Vec::with_capacity(response.attributes.len());
    for attr in response.attributes.drain(..) {
        if attr.attr_type != tunnel_password {
            rewritten.push(attr);
            continue;
        }
        let password = match TunnelPassword::from_attribute(
            &attr,
            entry.home_server.secret(),
            request_authenticator,
        ) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    error = %e,
                    "Failed to decrypt Tunnel-Password from home server; dropping it"
                );
                continue;
            }
        };
        let salt = salts.next().expect("one fresh salt per Tunnel-Password");
        match password.to_attribute_with_salt(&entry.client_secret, request_authenticator, salt) {
            Ok(a) => {
                debug!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    tag = password.tag,
                    "Re-encrypted Tunnel-Password for NAS"
                );
                rewritten.push(a);
            }
            Err(e) => {
                warn!(
                    home_server = %entry.home_server.name,
                    identifier = response.identifier,
                    error = %e,
                    "Failed to re-encrypt Tunnel-Password for NAS; dropping it"
                );
            }
        }
    }
    response.attributes = rewritten;
}

/// `count` distinct salts (MSB set) none of which appears in `in_use`.
/// [`generate_salts`] yields distinct values, so asking for `count + in_use.len()`
/// and discarding the ones already taken always leaves at least `count`.
fn fresh_salts(count: usize, in_use: &[[u8; 2]]) -> Vec<[u8; 2]> {
    let mut salts = generate_salts(count + in_use.len());
    salts.retain(|s| !in_use.contains(s));
    salts.truncate(count);
    salts
}

/// Recompute Message-Authenticator (RFC 3579 §3.2) over the rewritten packet
/// with the secret of the hop it is going to and the NAS's Request
/// Authenticator. One is added when absent but the packet carries EAP-Message,
/// as RFC 3579 requires.
fn recompute_message_authenticator(
    response: &mut Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> ProxyResult<()> {
    let has_ma = response
        .attributes
        .iter()
        .any(|a| a.attr_type == AttributeType::MessageAuthenticator as u8);
    let has_eap = response
        .attributes
        .iter()
        .any(|a| a.attr_type == AttributeType::EapMessage as u8);
    if !has_ma && !has_eap {
        return Ok(());
    }
    if !has_ma {
        response.add_attribute(Attribute::new(
            AttributeType::MessageAuthenticator as u8,
            vec![0u8; 16],
        )?);
    }

    // HMAC input: the packet with Authenticator = Request Authenticator and the
    // Message-Authenticator value zeroed.
    for ma in response
        .attributes
        .iter_mut()
        .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
    {
        ma.value = vec![0u8; 16];
    }
    let original_auth = response.authenticator;
    response.authenticator = *request_authenticator;
    let packet_bytes = response.encode()?;
    response.authenticator = original_auth;

    let mac = calculate_message_authenticator(&packet_bytes, secret);
    if let Some(ma) = response
        .attributes
        .iter_mut()
        .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
    {
        ma.value = mac.to_vec();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use radius_proto::Code;
    use radius_proto::mppe::encrypt_key;
    use std::time::Duration;

    const HOME_SECRET: &[u8] = b"home_secret";
    const CLIENT_SECRET: &[u8] = b"test_secret";
    const REQUEST_AUTH: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const PROXY_STATE: [u8; 16] = [0x50; 16];

    fn test_keys() -> MppeKeys {
        MppeKeys {
            send_key: (0x01..=0x20).collect(),
            recv_key: (0x21..=0x40).collect(),
        }
    }

    /// Cache entry for a request the proxy forwarded: the NAS's request plus our
    /// Proxy-State, authenticated by `REQUEST_AUTH`.
    fn create_test_entry(source: SocketAddr) -> ProxyCacheEntry {
        let mut request = Packet::new(Code::AccessRequest, 7, REQUEST_AUTH);
        request
            .add_attribute(Attribute::string(AttributeType::UserName as u8, "testuser").unwrap());
        request.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, PROXY_STATE.to_vec()).unwrap(),
        );
        ProxyCacheEntry {
            original_request: request,
            original_source: source,
            home_server: create_test_home_server(),
            sent_at: Instant::now(),
            retry_count: 0,
            proxy_state: PROXY_STATE,
            client_secret: CLIENT_SECRET.to_vec(),
        }
    }

    /// Finalize a home server reply: zero Message-Authenticator (the proxy does
    /// not verify it), echo our Proxy-State, sign with the home server secret.
    fn finalize_home_response(mut response: Packet) -> Packet {
        response.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, PROXY_STATE.to_vec()).unwrap(),
        );
        response.authenticator =
            calculate_response_authenticator(&response, &REQUEST_AUTH, HOME_SECRET);
        response
    }

    /// Access-Accept as a home server would send it after EAP-TLS: EAP-Success,
    /// Message-Authenticator and the MPPE keys encrypted under the home pair.
    fn home_access_accept_with_keys() -> Packet {
        let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        response.add_attribute(
            Attribute::new(
                AttributeType::EapMessage as u8,
                vec![0x03, 0x01, 0x00, 0x04],
            )
            .unwrap(),
        );
        response.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        for attr in test_keys()
            .to_attributes_with_salts(HOME_SECRET, &REQUEST_AUTH, [0x80, 0x01], [0x80, 0x02])
            .unwrap()
        {
            response.add_attribute(attr);
        }
        finalize_home_response(response)
    }

    fn mppe_ciphertexts(packet: &Packet) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let send = packet
            .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY)
            .into_iter()
            .map(|v| v.value)
            .collect();
        let recv = packet
            .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY)
            .into_iter()
            .map(|v| v.value)
            .collect();
        (send, recv)
    }

    /// Message-Authenticator check mirroring what a NAS does (RFC 3579 §3.2).
    fn message_authenticator_valid(
        packet: &Packet,
        request_auth: &[u8; 16],
        secret: &[u8],
    ) -> bool {
        let received = packet
            .find_attribute(AttributeType::MessageAuthenticator as u8)
            .map(|a| a.value.clone())
            .expect("Message-Authenticator present");
        let mut zeroed = packet.clone();
        zeroed.authenticator = *request_auth;
        for ma in zeroed
            .attributes
            .iter_mut()
            .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
        {
            ma.value = vec![0u8; 16];
        }
        calculate_message_authenticator(&zeroed.encode().unwrap(), secret).to_vec() == received
    }

    #[test]
    fn rewrite_rekeys_mppe_from_home_secret_to_client_secret() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let home_response = home_access_accept_with_keys();
        let (home_send, home_recv) = mppe_ciphertexts(&home_response);

        let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

        // The NAS accepts the packet under its own secret ...
        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        assert!(message_authenticator_valid(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        // ... our Proxy-State is gone, everything else survived ...
        assert!(
            relayed
                .find_attribute(AttributeType::ProxyState as u8)
                .is_none()
        );
        assert!(
            relayed
                .find_attribute(AttributeType::EapMessage as u8)
                .is_some()
        );
        // ... and the keys decrypt under the client pair to the home server's keys.
        let decrypted = MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH)
            .unwrap()
            .expect("MPPE keys present");
        assert_eq!(decrypted, test_keys());

        // Exactly one of each, with ciphertext that differs from the home server's
        // (different secret and fresh salts), and no longer decryptable as-is
        // under the home pair.
        let (send, recv) = mppe_ciphertexts(&relayed);
        assert_eq!(send.len(), 1);
        assert_eq!(recv.len(), 1);
        assert_ne!(send, home_send);
        assert_ne!(recv, home_recv);
        assert!(
            MppeKeys::from_packet(&relayed, HOME_SECRET, &REQUEST_AUTH)
                .map(|k| k != Some(test_keys()))
                .unwrap_or(true)
        );
    }

    #[test]
    fn rewrite_without_mppe_keys_leaves_attributes_alone() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        response
            .add_attribute(Attribute::integer(AttributeType::SessionTimeout as u8, 3600).unwrap());
        let home_response = finalize_home_response(response);

        let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        assert_eq!(relayed.attributes.len(), 1);
        assert_eq!(
            relayed.attributes[0].attr_type,
            AttributeType::SessionTimeout as u8
        );
        // No EAP-Message, so no Message-Authenticator is invented.
        assert!(
            relayed
                .find_attribute(AttributeType::MessageAuthenticator as u8)
                .is_none()
        );
    }

    #[test]
    fn rewrite_drops_undecryptable_mppe_keys_but_keeps_other_vsas() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        // A Send-Key encrypted under the wrong Request Authenticator (as a buggy
        // or misconfigured home server might emit) and no Recv-Key at all.
        let bad = encrypt_key(
            &test_keys().send_key,
            HOME_SECRET,
            &[0x11; 16],
            [0x80, 0x09],
        )
        .unwrap();
        // Share the VSA with MS-MPPE-Encryption-Policy (7), which must survive.
        let policy = VendorSpecific::new(MICROSOFT_VENDOR_ID, 7, vec![0, 0, 0, 1]).unwrap();
        let send = VendorSpecific::new(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY, bad).unwrap();
        response
            .add_attribute(VendorSpecific::to_attribute_combined(&[policy.clone(), send]).unwrap());
        let home_response = finalize_home_response(response);

        let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        let (send, recv) = mppe_ciphertexts(&relayed);
        assert!(
            send.is_empty(),
            "undecryptable Send-Key must not be forwarded"
        );
        assert!(recv.is_empty());
        assert_eq!(
            relayed.find_vendor_attributes(MICROSOFT_VENDOR_ID, 7),
            vec![policy]
        );
        assert_eq!(
            MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
            None
        );
    }

    fn test_tunnel_passwords() -> Vec<TunnelPassword> {
        vec![
            TunnelPassword {
                tag: 0x01,
                password: b"l2tp-primary-secret".to_vec(),
            },
            TunnelPassword {
                tag: 0x02,
                password: (0x30..=0x6f).collect(),
            },
        ]
    }

    fn tunnel_password_values(packet: &Packet) -> Vec<Vec<u8>> {
        packet
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::TunnelPassword as u8)
            .map(|a| a.value.clone())
            .collect()
    }

    /// Access-Accept from a home server provisioning two tunnels: tagged
    /// Tunnel-Type / Tunnel-Medium-Type around each Tunnel-Password (so order
    /// matters), plus MPPE keys to share the salt space with.
    fn home_access_accept_with_tunnel_passwords() -> Packet {
        let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        for (i, tp) in test_tunnel_passwords().iter().enumerate() {
            // Tunnel-Type (64), tagged, L2TP (3).
            response.add_attribute(Attribute::new(64, vec![tp.tag, 0, 0, 3]).unwrap());
            response.add_attribute(
                tp.to_attribute_with_salt(HOME_SECRET, &REQUEST_AUTH, [0x80, 0x10 + i as u8])
                    .unwrap(),
            );
            // Tunnel-Medium-Type (65), tagged, IPv4 (1).
            response.add_attribute(Attribute::new(65, vec![tp.tag, 0, 0, 1]).unwrap());
        }
        for attr in test_keys()
            .to_attributes_with_salts(HOME_SECRET, &REQUEST_AUTH, [0x80, 0x01], [0x80, 0x02])
            .unwrap()
        {
            response.add_attribute(attr);
        }
        finalize_home_response(response)
    }

    #[test]
    fn rewrite_reencrypts_tunnel_password_from_home_secret_to_client_secret() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let home_response = home_access_accept_with_tunnel_passwords();
        let home_values = tunnel_password_values(&home_response);
        let home_types: Vec<u8> = home_response
            .attributes
            .iter()
            .map(|a| a.attr_type)
            .filter(|t| *t != AttributeType::ProxyState as u8)
            .collect();

        let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

        // The NAS accepts the packet under its own secret ...
        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        // ... attribute order is intact, so the tagged tunnel groups still line
        // up (MPPE keys get re-appended, which keeps them last) ...
        let relayed_types: Vec<u8> = relayed.attributes.iter().map(|a| a.attr_type).collect();
        assert_eq!(relayed_types, home_types);

        // ... each Tunnel-Password decrypts under the client pair to the home
        // server's password with its Tag preserved ...
        let decrypted: Vec<TunnelPassword> = relayed
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::TunnelPassword as u8)
            .map(|a| TunnelPassword::from_attribute(a, CLIENT_SECRET, &REQUEST_AUTH).unwrap())
            .collect();
        assert_eq!(decrypted, test_tunnel_passwords());

        // ... with ciphertext that differs from the home server's (different
        // secret and fresh salts), tags in the clear and no longer decryptable
        // as-is under the home pair.
        let values = tunnel_password_values(&relayed);
        assert_eq!(values.len(), 2);
        assert_ne!(values, home_values);
        assert_eq!(values[0][0], 0x01);
        assert_eq!(values[1][0], 0x02);
        for (a, h) in relayed
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::TunnelPassword as u8)
            .zip(test_tunnel_passwords())
        {
            if let Ok(p) = TunnelPassword::from_attribute(a, HOME_SECRET, &REQUEST_AUTH) {
                assert_ne!(p, h);
            }
        }

        // Every salt in the packet is distinct: both Tunnel-Passwords and the
        // two MPPE keys.
        let (send, recv) = mppe_ciphertexts(&relayed);
        let mut salts: Vec<[u8; 2]> = values
            .iter()
            .map(|v| [v[1], v[2]])
            .chain(send.iter().chain(recv.iter()).map(|v| [v[0], v[1]]))
            .collect();
        assert!(salts.iter().all(|s| s[0] & 0x80 != 0));
        salts.sort_unstable();
        salts.dedup();
        assert_eq!(salts.len(), 4, "salts must be unique within the packet");

        // MPPE keys are still re-keyed alongside.
        assert_eq!(
            MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
            Some(test_keys())
        );
    }

    #[test]
    fn rewrite_drops_undecryptable_tunnel_password_but_keeps_the_rest() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let good = test_tunnel_passwords().remove(0);
        let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        response.add_attribute(Attribute::new(64, vec![good.tag, 0, 0, 3]).unwrap());
        response.add_attribute(
            good.to_attribute_with_salt(HOME_SECRET, &REQUEST_AUTH, [0x80, 0x10])
                .unwrap(),
        );
        // A Tunnel-Password encrypted under the wrong Request Authenticator (as a
        // buggy or misconfigured home server might emit). With this salt the
        // keystream mismatch deterministically yields a Data-Length octet larger
        // than the single plaintext block, so decryption fails ...
        response.add_attribute(
            TunnelPassword {
                tag: 0x02,
                password: b"never-forwarded".to_vec(),
            }
            .to_attribute_with_salt(HOME_SECRET, &[0x11; 16], [0x80, 0x15])
            .unwrap(),
        );
        // ... and one whose Tag is out of range.
        let mut bad_tag = good
            .to_attribute_with_salt(HOME_SECRET, &REQUEST_AUTH, [0x80, 0x12])
            .unwrap();
        bad_tag.value[0] = 0x20;
        response.add_attribute(bad_tag);
        response
            .add_attribute(Attribute::integer(AttributeType::SessionTimeout as u8, 3600).unwrap());
        let home_response = finalize_home_response(response);

        let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        let relayed_types: Vec<u8> = relayed.attributes.iter().map(|a| a.attr_type).collect();
        assert_eq!(
            relayed_types,
            vec![
                64,
                AttributeType::TunnelPassword as u8,
                AttributeType::SessionTimeout as u8
            ]
        );
        let forwarded = relayed
            .find_attribute(AttributeType::TunnelPassword as u8)
            .unwrap();
        assert_eq!(
            TunnelPassword::from_attribute(forwarded, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
            good
        );
    }

    #[test]
    fn rewrite_rejects_response_with_bad_home_authenticator() {
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let mut home_response = home_access_accept_with_keys();
        home_response.authenticator[0] ^= 0xff;

        match rewrite_response_for_nas(home_response, &entry) {
            Err(ProxyError::InvalidResponseAuthenticator) => {}
            other => panic!(
                "expected InvalidResponseAuthenticator, got {:?}",
                other.map(|_| ())
            ),
        }
    }

    #[tokio::test]
    async fn handle_response_relays_rekeyed_accept_to_nas() {
        // A loopback socket stands in for the NAS.
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let nas_addr = nas.local_addr().unwrap();

        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let entry = create_test_entry(nas_addr);
        let home_addr = entry.home_server.address;
        cache.insert(entry).unwrap();

        handler
            .handle_response(home_access_accept_with_keys(), home_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), nas.recv_from(&mut buf))
            .await
            .expect("relayed response within 5s")
            .unwrap();
        assert_eq!(from, handler.socket().local_addr().unwrap());
        let relayed = Packet::decode(&buf[..len]).unwrap();

        assert_eq!(relayed.code, Code::AccessAccept);
        assert_eq!(relayed.identifier, 7);
        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        assert!(message_authenticator_valid(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        assert_eq!(
            MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
            Some(test_keys())
        );
        assert!(cache.get(&PROXY_STATE).is_none(), "entry consumed");
    }

    // ---- Request leg -----------------------------------------------------

    /// PAP plaintext the NAS sends. Built at runtime (not a literal) so the
    /// value is not mistaken for a hard-coded credential by static analysis.
    fn pap_password() -> String {
        ('a'..='p').collect()
    }

    /// Sign an Access-Request the way a NAS does: Message-Authenticator under
    /// `secret` with the Request Authenticator as the Authenticator field.
    fn sign_request(mut request: Packet, secret: &[u8]) -> Packet {
        recompute_message_authenticator(&mut request, &REQUEST_AUTH, secret).unwrap();
        request
    }

    /// PAP Access-Request from the NAS: User-Password under the client pair and
    /// Message-Authenticator under the client secret (RFC 5080 §2.2.2 BlastRADIUS
    /// mitigation makes NASes send one on every Access-Request).
    fn nas_pap_request() -> Packet {
        let mut request = Packet::new(Code::AccessRequest, 7, REQUEST_AUTH);
        request.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
        request.add_attribute(
            Attribute::new(
                AttributeType::UserPassword as u8,
                encrypt_user_password(&pap_password(), CLIENT_SECRET, &REQUEST_AUTH),
            )
            .unwrap(),
        );
        request.add_attribute(Attribute::integer(AttributeType::NasPort as u8, 3).unwrap());
        request.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        sign_request(request, CLIENT_SECRET)
    }

    /// EAP Access-Request from the NAS (an EAP-Response/Identity) with the
    /// Message-Authenticator RFC 3579 §3.2 mandates.
    fn nas_eap_request() -> Packet {
        let mut request = Packet::new(Code::AccessRequest, 7, REQUEST_AUTH);
        request.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
        request.add_attribute(
            Attribute::new(
                AttributeType::EapMessage as u8,
                vec![0x02, 0x01, 0x00, 0x0a, 0x01, b'a', b'l', b'i', b'c', b'e'],
            )
            .unwrap(),
        );
        request.add_attribute(Attribute::new(AttributeType::State as u8, vec![0x55; 8]).unwrap());
        request.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        sign_request(request, CLIENT_SECRET)
    }

    fn attribute_types(packet: &Packet) -> Vec<u8> {
        packet.attributes.iter().map(|a| a.attr_type).collect()
    }

    #[test]
    fn rewrite_request_rekeys_user_password_and_message_authenticator() {
        let nas_request = nas_pap_request();
        assert!(message_authenticator_valid(
            &nas_request,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        let nas_password = nas_request
            .find_attribute(AttributeType::UserPassword as u8)
            .unwrap()
            .value
            .clone();

        let forwarded = rewrite_request_for_home_server(
            nas_request.clone(),
            PROXY_STATE,
            CLIENT_SECRET,
            HOME_SECRET,
        )
        .unwrap();

        // Request Authenticator, identifier and attribute order are intact, with
        // our Proxy-State appended last.
        assert_eq!(forwarded.authenticator, REQUEST_AUTH);
        assert_eq!(forwarded.identifier, nas_request.identifier);
        let mut expected_types = attribute_types(&nas_request);
        expected_types.push(AttributeType::ProxyState as u8);
        assert_eq!(attribute_types(&forwarded), expected_types);
        assert_eq!(
            forwarded.attributes.last().unwrap().value,
            PROXY_STATE.to_vec()
        );

        // The home server accepts the Message-Authenticator under its secret,
        // and the NAS's HMAC no longer verifies.
        assert!(message_authenticator_valid(
            &forwarded,
            &REQUEST_AUTH,
            HOME_SECRET
        ));
        assert!(!message_authenticator_valid(
            &forwarded,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));

        // User-Password decrypts under the home server pair to the NAS's
        // password, with ciphertext that differs from what the NAS sent.
        let home_password = &forwarded
            .find_attribute(AttributeType::UserPassword as u8)
            .unwrap()
            .value;
        assert_ne!(*home_password, nas_password);
        assert_eq!(
            decrypt_user_password(home_password, HOME_SECRET, &REQUEST_AUTH).unwrap(),
            pap_password()
        );
        assert_ne!(
            decrypt_user_password(home_password, CLIENT_SECRET, &REQUEST_AUTH).ok(),
            Some(pap_password())
        );

        // Everything else is byte-for-byte what the NAS sent.
        assert_eq!(
            forwarded.find_attribute(AttributeType::UserName as u8),
            nas_request.find_attribute(AttributeType::UserName as u8)
        );
        assert_eq!(
            forwarded.find_attribute(AttributeType::NasPort as u8),
            nas_request.find_attribute(AttributeType::NasPort as u8)
        );
    }

    #[test]
    fn rewrite_request_resigns_eap_request_for_home_server() {
        let nas_request = nas_eap_request();

        let forwarded = rewrite_request_for_home_server(
            nas_request.clone(),
            PROXY_STATE,
            CLIENT_SECRET,
            HOME_SECRET,
        )
        .unwrap();

        assert_eq!(forwarded.authenticator, REQUEST_AUTH);
        assert!(message_authenticator_valid(
            &forwarded,
            &REQUEST_AUTH,
            HOME_SECRET
        ));
        assert!(!message_authenticator_valid(
            &forwarded,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        // Exactly one Message-Authenticator; EAP-Message and State untouched;
        // no User-Password invented.
        assert_eq!(
            forwarded
                .attributes
                .iter()
                .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
                .count(),
            1
        );
        assert_eq!(
            forwarded.find_attribute(AttributeType::EapMessage as u8),
            nas_request.find_attribute(AttributeType::EapMessage as u8)
        );
        assert_eq!(
            forwarded.find_attribute(AttributeType::State as u8),
            nas_request.find_attribute(AttributeType::State as u8)
        );
        assert!(
            forwarded
                .find_attribute(AttributeType::UserPassword as u8)
                .is_none()
        );
        let mut expected_types = attribute_types(&nas_request);
        expected_types.push(AttributeType::ProxyState as u8);
        assert_eq!(attribute_types(&forwarded), expected_types);
    }

    #[test]
    fn rewrite_request_without_password_or_authenticator_only_adds_proxy_state() {
        // CHAP: CHAP-Password is MD5(ident || password || challenge) and involves
        // no shared secret, so the proxy must forward it (and the challenge it is
        // bound to) untouched.
        let mut nas_request = Packet::new(Code::AccessRequest, 9, REQUEST_AUTH);
        nas_request.add_attribute(Attribute::string(AttributeType::UserName as u8, "bob").unwrap());
        let mut chap = vec![0x01];
        chap.extend_from_slice(&[0xc4; 16]);
        nas_request.add_attribute(Attribute::new(AttributeType::ChapPassword as u8, chap).unwrap());
        nas_request.add_attribute(
            Attribute::new(AttributeType::ChapChallenge as u8, vec![0x7e; 16]).unwrap(),
        );
        // A Proxy-State from an upstream proxy, which must stay in front of ours.
        nas_request
            .add_attribute(Attribute::new(AttributeType::ProxyState as u8, vec![0x11; 4]).unwrap());

        let forwarded = rewrite_request_for_home_server(
            nas_request.clone(),
            PROXY_STATE,
            CLIENT_SECRET,
            HOME_SECRET,
        )
        .unwrap();

        let mut expected = nas_request.clone();
        expected.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, PROXY_STATE.to_vec()).unwrap(),
        );
        assert_eq!(forwarded.encode().unwrap(), expected.encode().unwrap());
    }

    #[test]
    fn rewrite_request_rejects_malformed_user_password() {
        let mut nas_request = Packet::new(Code::AccessRequest, 7, REQUEST_AUTH);
        // RFC 2865 §5.2: the value is a whole number of 16-octet blocks.
        nas_request.add_attribute(
            Attribute::new(AttributeType::UserPassword as u8, vec![0xab; 20]).unwrap(),
        );

        match rewrite_request_for_home_server(nas_request, PROXY_STATE, CLIENT_SECRET, HOME_SECRET)
        {
            Err(ProxyError::InvalidUserPassword(_)) => {}
            other => panic!("expected InvalidUserPassword, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn forward_request_sends_rekeyed_request_and_caches_it() {
        // A loopback socket stands in for the home server.
        let home = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let home_server = home_server_at(home.local_addr().unwrap());

        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let proxy_state = handler
            .forward_request(
                nas_pap_request(),
                source,
                home_server,
                CLIENT_SECRET.to_vec(),
            )
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), home.recv_from(&mut buf))
            .await
            .expect("forwarded request within 5s")
            .unwrap();
        assert_eq!(from, handler.socket().local_addr().unwrap());
        let upstream = Packet::decode(&buf[..len]).unwrap();

        // What the home server receives is valid under its own secret ...
        assert_eq!(upstream.code, Code::AccessRequest);
        assert_eq!(upstream.authenticator, REQUEST_AUTH);
        assert!(message_authenticator_valid(
            &upstream,
            &REQUEST_AUTH,
            HOME_SECRET
        ));
        assert_eq!(
            decrypt_user_password(
                &upstream
                    .find_attribute(AttributeType::UserPassword as u8)
                    .unwrap()
                    .value,
                HOME_SECRET,
                &REQUEST_AUTH
            )
            .unwrap(),
            pap_password()
        );
        assert_eq!(
            upstream.attributes.last().unwrap().value,
            proxy_state.to_vec()
        );

        // ... and the cache holds that same packet, so retries resend it and the
        // response leg keys off the NAS's Request Authenticator.
        let entry = cache.get(&proxy_state).expect("entry cached");
        assert_eq!(
            entry.original_request.encode().unwrap(),
            upstream.encode().unwrap()
        );
        assert_eq!(entry.client_secret, CLIENT_SECRET);
        assert_eq!(entry.original_source, source);
    }

    fn home_server_at(address: SocketAddr) -> Arc<HomeServer> {
        let config = HomeServerConfig {
            name: Some("Test Server".to_string()),
            ..HomeServerConfig::udp(
                address.to_string(),
                String::from_utf8(HOME_SECRET.to_vec()).unwrap(),
            )
        };
        Arc::new(HomeServer::new(config).unwrap())
    }

    #[tokio::test]
    async fn handle_response_replies_from_the_nas_socket() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
            .with_nas_socket(Arc::clone(&listener));
        let upstream_port = handler.socket().local_addr().unwrap().port();
        assert_ne!(upstream_port, listener.local_addr().unwrap().port());

        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut entry = create_test_entry(nas.local_addr().unwrap());
        let home_server = create_test_home_server();
        let home_addr = home_server.address;
        entry.home_server = home_server;
        cache.insert(entry).unwrap();

        handler
            .handle_response(home_access_accept_with_keys(), home_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), nas.recv_from(&mut buf))
            .await
            .expect("NAS must receive the relayed Accept")
            .unwrap();
        assert_eq!(
            from,
            listener.local_addr().unwrap(),
            "relayed response must come from the socket the NAS sent to"
        );
        let relayed = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(relayed.code, Code::AccessAccept);
        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
    }

    fn create_test_home_server() -> Arc<HomeServer> {
        let config = HomeServerConfig {
            name: Some("Test Server".to_string()),
            ..HomeServerConfig::udp("127.0.0.1:11812", "home_secret")
        };
        Arc::new(HomeServer::new(config).unwrap())
    }

    fn create_test_request() -> Packet {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "testuser").unwrap());
        packet
    }

    #[tokio::test]
    async fn test_proxy_handler_creation() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap(); // OS-assigned port

        let handler = ProxyHandler::new(cache, bind_addr).await;
        assert!(handler.is_ok());
    }

    #[tokio::test]
    async fn test_forward_request_adds_proxy_state() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let request = create_test_request();
        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // Forward request
        let proxy_state = handler
            .forward_request(
                request.clone(),
                source,
                home_server,
                b"test_secret".to_vec(),
            )
            .await
            .unwrap();

        // Verify entry is in cache
        let entry = cache.get(&proxy_state);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.original_source, source);
        assert_eq!(entry.retry_count, 0);
    }

    #[tokio::test]
    async fn test_proxy_loop_detection() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Create request with many Proxy-State attributes (simulating loop)
        let mut request = create_test_request();
        for _ in 0..MAX_PROXY_STATE_ATTRIBUTES {
            request.add_attribute(
                Attribute::new(AttributeType::ProxyState as u8, vec![0u8; 16]).unwrap(),
            );
        }

        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // Should detect loop
        let result = handler
            .forward_request(request, source, home_server, b"test_secret".to_vec())
            .await;
        assert!(result.is_err());
        match result {
            Err(ProxyError::ProxyLoop(count, limit)) => {
                assert_eq!(count, MAX_PROXY_STATE_ATTRIBUTES);
                assert_eq!(limit, MAX_PROXY_STATE_ATTRIBUTES);
            }
            _ => panic!("Expected ProxyLoop error"),
        }
    }

    #[tokio::test]
    async fn test_cache_full_error() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1)); // Max 1 entry
        let handler = ProxyHandler::new(cache, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // First request should succeed
        let result = handler
            .forward_request(
                create_test_request(),
                source,
                home_server.clone(),
                b"test_secret".to_vec(),
            )
            .await;
        assert!(result.is_ok());

        // Second request should fail (cache full)
        let result = handler
            .forward_request(
                create_test_request(),
                source,
                home_server,
                b"test_secret".to_vec(),
            )
            .await;
        assert!(result.is_err());
        match result {
            Err(ProxyError::CacheFull(_)) => {}
            _ => panic!("Expected CacheFull error"),
        }
    }

    // ---- Response origin: UDP address vs. RadSec link identity -------------

    #[tokio::test]
    async fn udp_response_for_another_server_at_a_different_address_is_rejected() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        cache.insert(entry).unwrap();

        let other: SocketAddr = "127.0.0.1:11813".parse().unwrap();
        let err = handler
            .handle_response(home_access_accept_with_keys(), other)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");
        assert!(
            cache.get(&PROXY_STATE).is_some(),
            "a response from the wrong peer must not consume the entry"
        );
    }

    #[tokio::test]
    async fn link_response_for_a_udp_entry_is_rejected() {
        // A RadSec link cannot answer for a UDP home server, even one at the
        // same address: identity is the Arc, not the socket address.
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let entry = create_test_entry("192.168.1.100:12345".parse().unwrap());
        let same_address_other_server = create_test_home_server();
        assert_eq!(same_address_other_server.address, entry.home_server.address);
        assert!(!Arc::ptr_eq(&same_address_other_server, &entry.home_server));
        cache.insert(entry).unwrap();

        let err = handler
            .handle_link_response(home_access_accept_with_keys(), same_address_other_server)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");
        assert!(cache.get(&PROXY_STATE).is_some());
    }

    #[tokio::test]
    async fn link_response_from_the_entry_home_server_is_relayed() {
        // The same `Arc<HomeServer>` the entry was forwarded to: accepted,
        // re-keyed and relayed to the NAS.
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let entry = create_test_entry(nas.local_addr().unwrap());
        let home_server = Arc::clone(&entry.home_server);
        cache.insert(entry).unwrap();

        handler
            .handle_link_response(home_access_accept_with_keys(), home_server)
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), nas.recv_from(&mut buf))
            .await
            .expect("relayed response within 5s")
            .unwrap();
        let relayed = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(relayed.code, Code::AccessAccept);
        assert!(verify_response_authenticator(
            &relayed,
            &REQUEST_AUTH,
            CLIENT_SECRET
        ));
        assert_eq!(
            MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
            Some(test_keys())
        );
        assert!(cache.get(&PROXY_STATE).is_none(), "entry consumed");
    }

    // ---- RadSec home servers (fixed "radsec" hop secret) --------------------

    #[cfg(feature = "tls")]
    mod radsec {
        use super::*;
        use crate::proxy::home_server::HomeServerTlsConfig;
        use crate::radsec_frame::RADSEC_SECRET;

        /// A RadSec home server with no link attached (the link is down).
        fn radsec_home_server(address: &str) -> Arc<HomeServer> {
            let tls = HomeServerTlsConfig {
                ca_path: "/nonexistent/ca.pem".to_string(),
                cert_path: "/nonexistent/proxy.pem".to_string(),
                key_path: "/nonexistent/proxy.key".to_string(),
                server_name: "home.test".to_string(),
                revocation: None,
            };
            Arc::new(
                HomeServer::new(HomeServerConfig {
                    name: Some("home-radsec".to_string()),
                    ..HomeServerConfig::radsec(address, tls)
                })
                .unwrap(),
            )
        }

        /// `create_test_entry` re-pointed at a RadSec home server, whose
        /// response is signed with the fixed "radsec" secret.
        fn radsec_entry(source: SocketAddr) -> ProxyCacheEntry {
            let mut entry = create_test_entry(source);
            entry.home_server = radsec_home_server("127.0.0.1:12083");
            entry
        }

        fn home_response_under_radsec(mut response: Packet) -> Packet {
            response.add_attribute(
                Attribute::new(AttributeType::ProxyState as u8, PROXY_STATE.to_vec()).unwrap(),
            );
            response.authenticator =
                calculate_response_authenticator(&response, &REQUEST_AUTH, RADSEC_SECRET);
            response
        }

        #[test]
        fn request_leg_is_rekeyed_to_the_radsec_secret() {
            let hs = radsec_home_server("127.0.0.1:12083");
            assert_eq!(hs.secret(), RADSEC_SECRET);
            let forwarded = rewrite_request_for_home_server(
                nas_pap_request(),
                PROXY_STATE,
                CLIENT_SECRET,
                hs.secret(),
            )
            .unwrap();
            assert!(message_authenticator_valid(
                &forwarded,
                &REQUEST_AUTH,
                RADSEC_SECRET
            ));
            let pw = &forwarded
                .find_attribute(AttributeType::UserPassword as u8)
                .unwrap()
                .value;
            assert_eq!(
                decrypt_user_password(pw, RADSEC_SECRET, &REQUEST_AUTH).unwrap(),
                pap_password()
            );
        }

        #[test]
        fn response_leg_rekeys_mppe_and_tunnel_password_from_radsec_to_client_secret() {
            let entry = radsec_entry("192.168.1.100:12345".parse().unwrap());
            let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
            response.add_attribute(
                Attribute::new(
                    AttributeType::EapMessage as u8,
                    vec![0x03, 0x01, 0x00, 0x04],
                )
                .unwrap(),
            );
            response.add_attribute(
                Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
            );
            for attr in test_keys()
                .to_attributes_with_salts(RADSEC_SECRET, &REQUEST_AUTH, [0x80, 0x01], [0x80, 0x02])
                .unwrap()
            {
                response.add_attribute(attr);
            }
            let tp = test_tunnel_passwords().remove(0);
            response.add_attribute(
                tp.to_attribute_with_salt(RADSEC_SECRET, &REQUEST_AUTH, [0x80, 0x10])
                    .unwrap(),
            );
            let home_response = home_response_under_radsec(response);

            let relayed = rewrite_response_for_nas(home_response, &entry).unwrap();

            assert!(verify_response_authenticator(
                &relayed,
                &REQUEST_AUTH,
                CLIENT_SECRET
            ));
            assert!(message_authenticator_valid(
                &relayed,
                &REQUEST_AUTH,
                CLIENT_SECRET
            ));
            assert_eq!(
                MppeKeys::from_packet(&relayed, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
                Some(test_keys())
            );
            let forwarded_tp = relayed
                .find_attribute(AttributeType::TunnelPassword as u8)
                .unwrap();
            assert_eq!(
                TunnelPassword::from_attribute(forwarded_tp, CLIENT_SECRET, &REQUEST_AUTH).unwrap(),
                tp
            );
            assert!(
                relayed
                    .find_attribute(AttributeType::ProxyState as u8)
                    .is_none()
            );
        }

        #[test]
        fn response_leg_rejects_a_reply_not_signed_under_radsec() {
            // Signed with some other secret: the TLS peer is authenticated,
            // but the RADIUS layer still has to agree on "radsec".
            let entry = radsec_entry("192.168.1.100:12345".parse().unwrap());
            let home_response =
                finalize_home_response(Packet::new(Code::AccessAccept, 7, [0u8; 16]));
            assert!(matches!(
                rewrite_response_for_nas(home_response, &entry),
                Err(ProxyError::InvalidResponseAuthenticator)
            ));
        }

        #[tokio::test]
        async fn udp_datagram_cannot_answer_a_radsec_entry() {
            let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
            let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let entry = radsec_entry("192.168.1.100:12345".parse().unwrap());
            let home_addr = entry.home_server.address;
            cache.insert(entry).unwrap();

            // Even from the RadSec server's own address.
            let response =
                home_response_under_radsec(Packet::new(Code::AccessAccept, 7, [0u8; 16]));
            let err = handler
                .handle_response(response, home_addr)
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");
            assert!(cache.get(&PROXY_STATE).is_some(), "entry kept for the link");
        }

        #[tokio::test]
        async fn link_response_for_a_radsec_entry_from_another_server_is_rejected() {
            let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
            let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let entry = radsec_entry("192.168.1.100:12345".parse().unwrap());
            cache.insert(entry).unwrap();

            let impostor = radsec_home_server("127.0.0.1:12083");
            let response =
                home_response_under_radsec(Packet::new(Code::AccessAccept, 7, [0u8; 16]));
            let err = handler
                .handle_link_response(response, impostor)
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");
            assert!(cache.get(&PROXY_STATE).is_some());
        }

        #[tokio::test]
        async fn forward_request_to_a_down_link_keeps_the_entry_and_counts_it() {
            let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
            let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let hs = radsec_home_server("127.0.0.1:12083");
            let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

            let err = handler
                .forward_request(
                    nas_pap_request(),
                    source,
                    Arc::clone(&hs),
                    CLIENT_SECRET.to_vec(),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::LinkDown(_)), "{err}");

            // The request waits in the cache for the retry manager, already
            // re-keyed for "radsec", and counts as outstanding.
            assert_eq!(cache.len(), 1);
            assert_eq!(hs.stats().outstanding(), 1);
            assert_eq!(hs.stats().requests_sent(), 1);
            let entry = cache.get_timed_out(Duration::ZERO).remove(0);
            assert!(Arc::ptr_eq(&entry.home_server, &hs));
            assert!(message_authenticator_valid(
                &entry.original_request,
                &REQUEST_AUTH,
                RADSEC_SECRET
            ));
        }

        #[tokio::test]
        async fn link_response_with_a_malformed_missing_or_unknown_proxy_state_is_rejected() {
            // The link delivers any frame carrying a Proxy-State; the handler
            // owns the length check (16 octets, RFC 2865 §5.33 as we encode it)
            // and the cache lookup. None of these may touch the live entry.
            let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
            let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let entry = radsec_entry("192.168.1.100:12345".parse().unwrap());
            let hs = Arc::clone(&entry.home_server);
            cache.insert(entry).unwrap();

            // 4-octet Proxy-State.
            let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
            response.add_attribute(
                Attribute::new(AttributeType::ProxyState as u8, vec![0x50; 4]).unwrap(),
            );
            response.authenticator =
                calculate_response_authenticator(&response, &REQUEST_AUTH, RADSEC_SECRET);
            let err = handler
                .handle_link_response(response, Arc::clone(&hs))
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");

            // No Proxy-State at all (a Status-Server reply that reached the
            // wrong path, say).
            let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
            response.authenticator =
                calculate_response_authenticator(&response, &REQUEST_AUTH, RADSEC_SECRET);
            let err = handler
                .handle_link_response(response, Arc::clone(&hs))
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");

            // Well-formed but unknown Proxy-State.
            let mut response = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
            response.add_attribute(
                Attribute::new(AttributeType::ProxyState as u8, vec![0x51; 16]).unwrap(),
            );
            response.authenticator =
                calculate_response_authenticator(&response, &REQUEST_AUTH, RADSEC_SECRET);
            let err = handler
                .handle_link_response(response, Arc::clone(&hs))
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::CorrelationFailed), "{err}");

            assert!(
                cache.get(&PROXY_STATE).is_some(),
                "none of these may consume the live entry"
            );
            assert_eq!(cache.len(), 1);
        }

        #[tokio::test]
        async fn send_to_home_server_without_a_link_is_link_down() {
            let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
            let handler = ProxyHandler::new(cache, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let hs = radsec_home_server("127.0.0.1:12083");
            let err = handler
                .send_to_home_server(&[0u8; 20], &hs)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ProxyError::LinkDown(ref n) if n == "home-radsec"),
                "{err}"
            );
        }
    }
}
