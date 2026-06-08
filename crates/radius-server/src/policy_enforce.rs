//! Bridges the authorization policy engine to live RADIUS packets (Phase 2b):
//! builds a [`RequestContext`] from an Access-Request, and maps an authorization
//! profile's returned attributes back to RADIUS [`Attribute`]s for the reply.

use crate::policy::{ReplyAttribute, RequestContext};
use radius_proto::{Attribute, AttributeType, Packet};
use std::collections::HashMap;

/// Read a big-endian u32 from a 4-byte integer attribute.
fn read_u32(req: &Packet, ty: u8) -> Option<u32> {
    req.find_attribute(ty).and_then(|a| {
        (a.value.len() == 4)
            .then(|| u32::from_be_bytes([a.value[0], a.value[1], a.value[2], a.value[3]]))
    })
}

/// Map common NAS-Port-Type integer codes (RFC 2865) to the names operators
/// author against; falls back to the numeric value.
fn nas_port_type_name(n: u32) -> String {
    match n {
        0 => "Async".into(),
        1 => "Sync".into(),
        2 => "ISDN-Sync".into(),
        5 => "Virtual".into(),
        15 => "Ethernet".into(),
        17 => "Cable".into(),
        18 => "Wireless-Other".into(),
        19 => "Wireless-802.11".into(),
        other => other.to_string(),
    }
}

/// Map Service-Type integer codes (RFC 2865) to names so conditions can be
/// authored against the names the dictionary advertises.
fn service_type_name(n: u32) -> String {
    match n {
        1 => "Login".into(),
        2 => "Framed".into(),
        3 => "Callback-Login".into(),
        4 => "Callback-Framed".into(),
        5 => "Outbound".into(),
        6 => "Administrative".into(),
        7 => "NAS-Prompt".into(),
        8 => "Authenticate-Only".into(),
        9 => "Callback-NAS-Prompt".into(),
        10 => "Call-Check".into(),
        11 => "Callback-Administrative".into(),
        other => other.to_string(),
    }
}

/// Map Framed-Protocol integer codes (RFC 2865) to names.
fn framed_protocol_name(n: u32) -> String {
    match n {
        1 => "PPP".into(),
        2 => "SLIP".into(),
        3 => "ARAP".into(),
        4 => "Gandalf-SLML".into(),
        5 => "Xylogics-IPX-SLIP".into(),
        6 => "X.75-Synchronous".into(),
        other => other.to_string(),
    }
}

/// Map EAP method type numbers (IANA) to names.
fn eap_type_name(t: u8) -> String {
    match t {
        1 => "Identity".into(),
        2 => "Notification".into(),
        4 => "MD5-Challenge".into(),
        6 => "GTC".into(),
        13 => "EAP-TLS".into(),
        21 => "EAP-TTLS".into(),
        25 => "PEAP".into(),
        43 => "EAP-FAST".into(),
        55 => "EAP-TEAP".into(),
        other => format!("EAP-Type-{other}"),
    }
}

/// Extract the EAP method type from the first EAP-Message (an EAP
/// Request/Response packet: code, id, length(2), type, ...).
fn eap_type(request: &Packet) -> Option<String> {
    let a = request.find_attribute(AttributeType::EapMessage as u8)?;
    // Only Request(1)/Response(2) packets carry a method type byte at offset 4.
    if a.value.len() >= 5 && (a.value[0] == 1 || a.value[0] == 2) {
        Some(eap_type_name(a.value[4]))
    } else {
        None
    }
}

/// Build the policy [`RequestContext`] from an Access-Request packet. Attribute
/// names match the engine's dictionary so policy conditions can reference them.
pub fn request_context(request: &Packet, username: &str) -> RequestContext {
    let mut attrs: HashMap<String, String> = HashMap::new();
    attrs.insert("User-Name".into(), username.to_string());

    // String-valued attributes. Use lossy UTF-8 (not as_string, which fails on
    // non-UTF-8 and would DROP the attribute — a missing attribute silently flips
    // `not_equals` conditions, a security-relevant change).
    for (name, ty) in [
        ("NAS-Identifier", AttributeType::NasIdentifier),
        ("Called-Station-Id", AttributeType::CalledStationId),
        ("Calling-Station-Id", AttributeType::CallingStationId),
        ("Filter-Id", AttributeType::FilterId),
    ] {
        if let Some(a) = request.find_attribute(ty as u8) {
            attrs.insert(name.into(), String::from_utf8_lossy(&a.value).into_owned());
        }
    }

    // NAS-IP-Address (4-byte IPv4).
    if let Some(a) = request.find_attribute(AttributeType::NasIpAddress as u8)
        && a.value.len() == 4
    {
        attrs.insert(
            "NAS-IP-Address".into(),
            format!(
                "{}.{}.{}.{}",
                a.value[0], a.value[1], a.value[2], a.value[3]
            ),
        );
    }

    // Integer-coded attributes, mapped to the names the dictionary advertises.
    if let Some(n) = read_u32(request, AttributeType::NasPortType as u8) {
        attrs.insert("NAS-Port-Type".into(), nas_port_type_name(n));
    }
    if let Some(n) = read_u32(request, AttributeType::ServiceType as u8) {
        attrs.insert("Service-Type".into(), service_type_name(n));
    }
    if let Some(n) = read_u32(request, AttributeType::FramedProtocol as u8) {
        attrs.insert("Framed-Protocol".into(), framed_protocol_name(n));
    }
    if let Some(t) = eap_type(request) {
        attrs.insert("EAP-Type".into(), t);
    }

    RequestContext::new(attrs)
}

/// Tag octet for tunnel attributes. We only ever return a single tunnel group, so
/// a fixed tag of 1 groups Tunnel-Type / Tunnel-Medium-Type / Tunnel-Private-Group-ID
/// together (RFC 2868 §3.1); a tag of 0 would mean "untagged".
const TUNNEL_TAG: u8 = 1;

/// Map an authorization profile's returned attribute (name + value) to a RADIUS
/// [`Attribute`]. Returns `None` for names this server doesn't know how to encode
/// (the caller logs and skips them). Keep in sync with
/// [`crate::policy::KNOWN_REPLY_ATTRIBUTES`].
pub fn reply_attribute(ra: &ReplyAttribute) -> Option<Attribute> {
    match ra.name.as_str() {
        "Filter-Id" => Attribute::string(AttributeType::FilterId as u8, ra.value.clone()).ok(),
        "Reply-Message" => {
            Attribute::string(AttributeType::ReplyMessage as u8, ra.value.clone()).ok()
        }
        "Class" => Attribute::string(AttributeType::Class as u8, ra.value.clone()).ok(),
        "Session-Timeout" => ra
            .value
            .parse::<u32>()
            .ok()
            .and_then(|n| Attribute::integer(AttributeType::SessionTimeout as u8, n).ok()),
        "Idle-Timeout" => ra
            .value
            .parse::<u32>()
            .ok()
            .and_then(|n| Attribute::integer(AttributeType::IdleTimeout as u8, n).ok()),
        // RFC 2868 §3.1: tagged integer — high octet is the tag, low 3 octets the
        // value. Encoding these as a plain 4-byte integer (the old behavior) put the
        // value's top byte where the tag belongs, corrupting the VLAN assignment.
        "Tunnel-Type" => ra
            .value
            .parse::<u32>()
            .ok()
            .and_then(|n| tagged_integer(64, n)),
        "Tunnel-Medium-Type" => ra
            .value
            .parse::<u32>()
            .ok()
            .and_then(|n| tagged_integer(65, n)),
        // RFC 2868 §3.5: tagged string — a leading tag octet then the value bytes.
        "Tunnel-Private-Group-ID" => {
            let mut v = Vec::with_capacity(1 + ra.value.len());
            v.push(TUNNEL_TAG);
            v.extend_from_slice(ra.value.as_bytes());
            Attribute::new(81, v).ok()
        }
        _ => None,
    }
}

/// Encode an RFC 2868 tagged integer: `[tag, value_hi, value_mid, value_lo]`.
fn tagged_integer(ty: u8, n: u32) -> Option<Attribute> {
    Attribute::new(
        ty,
        vec![TUNNEL_TAG, (n >> 16) as u8, (n >> 8) as u8, n as u8],
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_proto::Code;

    fn req(attrs: Vec<Attribute>) -> Packet {
        let mut p = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        for a in attrs {
            p.add_attribute(a);
        }
        p
    }

    #[test]
    fn context_extracts_named_attributes() {
        let p = req(vec![
            Attribute::ipv4(AttributeType::NasIpAddress as u8, [10, 0, 1, 5]).unwrap(),
            Attribute::integer(AttributeType::NasPortType as u8, 19).unwrap(),
            Attribute::string(AttributeType::CallingStationId as u8, "aa-bb-cc").unwrap(),
        ]);
        let ctx = request_context(&p, "alice");
        assert_eq!(ctx.attributes.get("User-Name").unwrap(), "alice");
        assert_eq!(ctx.attributes.get("NAS-IP-Address").unwrap(), "10.0.1.5");
        assert_eq!(
            ctx.attributes.get("NAS-Port-Type").unwrap(),
            "Wireless-802.11"
        );
        assert_eq!(
            ctx.attributes.get("Calling-Station-Id").unwrap(),
            "aa-bb-cc"
        );
    }

    #[test]
    fn context_maps_integer_codes_and_eap_type() {
        // EAP-Response/EAP-TLS: code=2, id=1, len=6, type=13.
        let eap = Attribute::new(AttributeType::EapMessage as u8, vec![2, 1, 0, 6, 13, 0]).unwrap();
        let p = req(vec![
            Attribute::integer(AttributeType::ServiceType as u8, 2).unwrap(),
            Attribute::integer(AttributeType::FramedProtocol as u8, 1).unwrap(),
            eap,
        ]);
        let ctx = request_context(&p, "bob");
        assert_eq!(ctx.attributes.get("Service-Type").unwrap(), "Framed");
        assert_eq!(ctx.attributes.get("Framed-Protocol").unwrap(), "PPP");
        assert_eq!(ctx.attributes.get("EAP-Type").unwrap(), "EAP-TLS");
    }

    #[test]
    fn context_keeps_non_utf8_string_attribute() {
        // A non-UTF-8 Calling-Station-Id must still be present (lossy), not dropped —
        // otherwise a `not_equals` condition would silently flip to matching.
        let p = req(vec![
            Attribute::new(AttributeType::CallingStationId as u8, vec![0xff, 0xfe]).unwrap(),
        ]);
        let ctx = request_context(&p, "alice");
        assert!(ctx.attributes.contains_key("Calling-Station-Id"));
    }

    #[test]
    fn reply_attribute_maps_known_names() {
        // RFC 2868 tagged string: leading tag octet (1) then the value bytes.
        let vlan = reply_attribute(&ReplyAttribute {
            name: "Tunnel-Private-Group-ID".into(),
            value: "42".into(),
        })
        .unwrap();
        assert_eq!(vlan.attr_type, 81);
        assert_eq!(vlan.value, vec![TUNNEL_TAG, b'4', b'2']);

        // RFC 2868 tagged integer: [tag, hi, mid, lo]; VLAN tunnel type = 13.
        let tt = reply_attribute(&ReplyAttribute {
            name: "Tunnel-Type".into(),
            value: "13".into(),
        })
        .unwrap();
        assert_eq!(tt.attr_type, 64);
        assert_eq!(tt.value, vec![TUNNEL_TAG, 0, 0, 13]);

        let to = reply_attribute(&ReplyAttribute {
            name: "Session-Timeout".into(),
            value: "3600".into(),
        })
        .unwrap();
        assert_eq!(to.attr_type, AttributeType::SessionTimeout as u8);
        assert_eq!(to.value, 3600u32.to_be_bytes());

        assert!(
            reply_attribute(&ReplyAttribute {
                name: "Bogus".into(),
                value: "x".into()
            })
            .is_none()
        );
    }
}
