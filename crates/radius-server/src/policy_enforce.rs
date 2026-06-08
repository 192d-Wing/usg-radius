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

/// Build the policy [`RequestContext`] from an Access-Request packet. Attribute
/// names match the engine's dictionary so policy conditions can reference them.
pub fn request_context(request: &Packet, username: &str) -> RequestContext {
    let mut attrs: HashMap<String, String> = HashMap::new();
    attrs.insert("User-Name".into(), username.to_string());

    // String-valued attributes.
    for (name, ty) in [
        ("NAS-Identifier", AttributeType::NasIdentifier),
        ("Called-Station-Id", AttributeType::CalledStationId),
        ("Calling-Station-Id", AttributeType::CallingStationId),
        ("Filter-Id", AttributeType::FilterId),
    ] {
        if let Some(v) = request
            .find_attribute(ty as u8)
            .and_then(|a| a.as_string().ok())
        {
            attrs.insert(name.into(), v);
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

    // Integer-coded attributes (mapped to names where well-known).
    if let Some(n) = read_u32(request, AttributeType::NasPortType as u8) {
        attrs.insert("NAS-Port-Type".into(), nas_port_type_name(n));
    }
    if let Some(n) = read_u32(request, AttributeType::ServiceType as u8) {
        attrs.insert("Service-Type".into(), n.to_string());
    }

    RequestContext::new(attrs)
}

enum Kind {
    Str,
    Int,
}

/// Map an authorization profile's returned attribute (name + value) to a RADIUS
/// [`Attribute`]. Returns `None` for names this server doesn't know how to encode
/// (the caller logs and skips them).
pub fn reply_attribute(ra: &ReplyAttribute) -> Option<Attribute> {
    // (RADIUS attribute number, encoding). Covers the common authorization
    // results; tunnel attrs use their RFC 2868 numbers (not in AttributeType).
    let (ty, kind): (u8, Kind) = match ra.name.as_str() {
        "Filter-Id" => (AttributeType::FilterId as u8, Kind::Str),
        "Reply-Message" => (AttributeType::ReplyMessage as u8, Kind::Str),
        "Class" => (AttributeType::Class as u8, Kind::Str),
        "Session-Timeout" => (AttributeType::SessionTimeout as u8, Kind::Int),
        "Idle-Timeout" => (AttributeType::IdleTimeout as u8, Kind::Int),
        "Tunnel-Type" => (64, Kind::Int),
        "Tunnel-Medium-Type" => (65, Kind::Int),
        "Tunnel-Private-Group-ID" => (81, Kind::Str),
        _ => return None,
    };
    match kind {
        Kind::Str => Attribute::string(ty, ra.value.clone()).ok(),
        Kind::Int => ra
            .value
            .parse::<u32>()
            .ok()
            .and_then(|n| Attribute::integer(ty, n).ok()),
    }
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
    fn reply_attribute_maps_known_names() {
        let vlan = reply_attribute(&ReplyAttribute {
            name: "Tunnel-Private-Group-ID".into(),
            value: "42".into(),
        })
        .unwrap();
        assert_eq!(vlan.attr_type, 81);
        assert_eq!(vlan.as_string().unwrap(), "42");

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
