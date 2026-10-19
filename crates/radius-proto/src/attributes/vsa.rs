//! Vendor-Specific Attribute (Type 26) sub-attribute codec — RFC 2865 §5.26.
//!
//! A Vendor-Specific attribute wraps one or more vendor sub-attributes in a
//! single RADIUS attribute:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type (26) |    Length     |            Vendor-Id
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      Vendor-Id (cont)           |  Vendor type  | Vendor length |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Attribute-Specific...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The Vendor-Id is the vendor's IANA Private Enterprise Number (high octet
//! zero) in network byte order. The "SHOULD" encoding of RFC 2865 §5.26 —
//! which every vendor this server cares about (Microsoft RFC 2548, Cisco,
//! WISPr, ...) follows — is a sequence of `vendor-type (1) || vendor-length
//! (1) || value` TLVs, where vendor-length counts itself and the type octet.
//!
//! [`VendorSpecific`] models one such sub-attribute; [`VendorSpecific::to_attribute`]
//! wraps it in a RADIUS attribute of its own (the common case, and the only
//! legal form for the RFC 2548 MS-MPPE keys), and [`VendorSpecific::from_attribute`]
//! unpacks every sub-attribute a received VSA carries.

use super::attribute::Attribute;
use super::types::AttributeType;
use crate::packet::{Packet, PacketError};

/// One vendor sub-attribute of a Vendor-Specific (26) RADIUS attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorSpecific {
    /// IANA Private Enterprise Number of the vendor (e.g. 311 = Microsoft).
    pub vendor_id: u32,
    /// Vendor-assigned attribute type.
    pub vendor_type: u8,
    /// Attribute-specific value.
    pub value: Vec<u8>,
}

impl VendorSpecific {
    /// Size of the Vendor-Id field.
    pub const VENDOR_ID_LENGTH: usize = 4;
    /// Size of the vendor-type + vendor-length header of a sub-attribute.
    pub const SUB_HEADER_LENGTH: usize = 2;
    /// Maximum value length of a sub-attribute that is carried alone in a
    /// RADIUS attribute: 253 (max attribute value) − 4 (Vendor-Id) − 2 (header).
    pub const MAX_VALUE_LENGTH: usize =
        Attribute::MAX_VALUE_LENGTH - Self::VENDOR_ID_LENGTH - Self::SUB_HEADER_LENGTH;

    /// Create a sub-attribute, rejecting values that cannot fit in a single
    /// RADIUS attribute.
    pub fn new(vendor_id: u32, vendor_type: u8, value: Vec<u8>) -> Result<Self, PacketError> {
        if value.len() > Self::MAX_VALUE_LENGTH {
            return Err(PacketError::AttributeError(format!(
                "Vendor-Specific value too long: {} bytes (max {})",
                value.len(),
                Self::MAX_VALUE_LENGTH
            )));
        }
        Ok(VendorSpecific {
            vendor_id,
            vendor_type,
            value,
        })
    }

    /// Encode this sub-attribute's TLV (`vendor-type || vendor-length || value`),
    /// without the Vendor-Id prefix.
    pub fn encode_sub_attribute(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SUB_HEADER_LENGTH + self.value.len());
        out.push(self.vendor_type);
        out.push((Self::SUB_HEADER_LENGTH + self.value.len()) as u8);
        out.extend_from_slice(&self.value);
        out
    }

    /// Encode the full Vendor-Specific attribute *value*
    /// (`Vendor-Id || vendor-type || vendor-length || value`).
    pub fn encode_value(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(Self::VENDOR_ID_LENGTH + Self::SUB_HEADER_LENGTH + self.value.len());
        out.extend_from_slice(&self.vendor_id.to_be_bytes());
        out.extend_from_slice(&self.encode_sub_attribute());
        out
    }

    /// Wrap this sub-attribute in a RADIUS Vendor-Specific (26) attribute.
    pub fn to_attribute(&self) -> Result<Attribute, PacketError> {
        Attribute::new(AttributeType::VendorSpecific as u8, self.encode_value())
    }

    /// Encode several sub-attributes of the *same* vendor into one
    /// Vendor-Specific attribute (RFC 2865 §5.26 permits this when they fit).
    ///
    /// Errors if the sub-attributes have differing Vendor-Ids, the list is
    /// empty, or the combined encoding exceeds the attribute size limit.
    pub fn to_attribute_combined(subs: &[VendorSpecific]) -> Result<Attribute, PacketError> {
        let Some(first) = subs.first() else {
            return Err(PacketError::AttributeError(
                "Vendor-Specific attribute needs at least one sub-attribute".into(),
            ));
        };
        let mut value = Vec::new();
        value.extend_from_slice(&first.vendor_id.to_be_bytes());
        for sub in subs {
            if sub.vendor_id != first.vendor_id {
                return Err(PacketError::AttributeError(format!(
                    "Cannot combine sub-attributes of vendors {} and {}",
                    first.vendor_id, sub.vendor_id
                )));
            }
            value.extend_from_slice(&sub.encode_sub_attribute());
        }
        Attribute::new(AttributeType::VendorSpecific as u8, value)
    }

    /// Decode a Vendor-Specific attribute *value* into its sub-attributes.
    ///
    /// Rejects truncated or inconsistent vendor-length fields (RFC 2865 §5.26:
    /// a malformed VSA should be treated as an unknown attribute rather than
    /// partially trusted).
    pub fn decode_value(value: &[u8]) -> Result<Vec<VendorSpecific>, PacketError> {
        if value.len() < Self::VENDOR_ID_LENGTH + Self::SUB_HEADER_LENGTH {
            return Err(PacketError::AttributeError(format!(
                "Vendor-Specific value too short: {} bytes",
                value.len()
            )));
        }
        let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let mut rest = &value[Self::VENDOR_ID_LENGTH..];
        let mut subs = Vec::new();
        while !rest.is_empty() {
            if rest.len() < Self::SUB_HEADER_LENGTH {
                return Err(PacketError::AttributeError(
                    "Truncated Vendor-Specific sub-attribute header".into(),
                ));
            }
            let vendor_type = rest[0];
            let vendor_length = rest[1] as usize;
            if vendor_length < Self::SUB_HEADER_LENGTH || vendor_length > rest.len() {
                return Err(PacketError::AttributeError(format!(
                    "Invalid Vendor-Specific sub-attribute length: {} (remaining {})",
                    vendor_length,
                    rest.len()
                )));
            }
            subs.push(VendorSpecific {
                vendor_id,
                vendor_type,
                value: rest[Self::SUB_HEADER_LENGTH..vendor_length].to_vec(),
            });
            rest = &rest[vendor_length..];
        }
        Ok(subs)
    }

    /// Decode the sub-attributes carried by a RADIUS attribute, which must be
    /// of type Vendor-Specific (26).
    pub fn from_attribute(attr: &Attribute) -> Result<Vec<VendorSpecific>, PacketError> {
        if attr.attr_type != AttributeType::VendorSpecific as u8 {
            return Err(PacketError::AttributeError(format!(
                "Expected Vendor-Specific (26) attribute, got type {}",
                attr.attr_type
            )));
        }
        Self::decode_value(&attr.value)
    }
}

impl Packet {
    /// All sub-attributes of the given vendor and vendor-type in this packet,
    /// in wire order. Malformed Vendor-Specific attributes are skipped, as are
    /// other vendors' attributes.
    pub fn find_vendor_attributes(&self, vendor_id: u32, vendor_type: u8) -> Vec<VendorSpecific> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::VendorSpecific as u8)
            .filter_map(|a| VendorSpecific::decode_value(&a.value).ok())
            .flatten()
            .filter(|v| v.vendor_id == vendor_id && v.vendor_type == vendor_type)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Code;

    #[test]
    fn encode_matches_rfc_2865_layout() {
        // Microsoft (311) vendor-type 7 = MS-MPPE-Encryption-Policy, value 1.
        let vsa = VendorSpecific::new(311, 7, vec![0, 0, 0, 1]).unwrap();
        let attr = vsa.to_attribute().unwrap();
        assert_eq!(attr.attr_type, 26);
        assert_eq!(
            attr.encode().unwrap(),
            vec![26, 12, 0x00, 0x00, 0x01, 0x37, 7, 6, 0, 0, 0, 1]
        );
    }

    #[test]
    fn round_trip_single() {
        let vsa = VendorSpecific::new(9, 1, b"shell:priv-lvl=15".to_vec()).unwrap();
        let attr = vsa.to_attribute().unwrap();
        let decoded = VendorSpecific::from_attribute(&attr).unwrap();
        assert_eq!(decoded, vec![vsa]);
    }

    #[test]
    fn round_trip_combined() {
        let a = VendorSpecific::new(311, 16, vec![0xAA; 10]).unwrap();
        let b = VendorSpecific::new(311, 17, vec![0xBB; 3]).unwrap();
        let attr = VendorSpecific::to_attribute_combined(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(VendorSpecific::from_attribute(&attr).unwrap(), vec![a, b]);
    }

    #[test]
    fn combined_rejects_mixed_vendors_and_empty() {
        let a = VendorSpecific::new(311, 16, vec![1]).unwrap();
        let b = VendorSpecific::new(9, 1, vec![1]).unwrap();
        assert!(VendorSpecific::to_attribute_combined(&[a, b]).is_err());
        assert!(VendorSpecific::to_attribute_combined(&[]).is_err());
    }

    #[test]
    fn max_value_length_enforced() {
        assert!(VendorSpecific::new(311, 1, vec![0; VendorSpecific::MAX_VALUE_LENGTH]).is_ok());
        assert!(
            VendorSpecific::new(311, 1, vec![0; VendorSpecific::MAX_VALUE_LENGTH + 1]).is_err()
        );
        // The maximal sub-attribute still fits in a 255-octet RADIUS attribute.
        let max = VendorSpecific::new(311, 1, vec![0; VendorSpecific::MAX_VALUE_LENGTH]).unwrap();
        assert_eq!(max.to_attribute().unwrap().encode().unwrap().len(), 255);
    }

    #[test]
    fn decode_rejects_malformed() {
        // Too short for Vendor-Id + header.
        assert!(VendorSpecific::decode_value(&[0, 0, 1, 0x37, 7]).is_err());
        // vendor-length below the 2-octet minimum.
        assert!(VendorSpecific::decode_value(&[0, 0, 1, 0x37, 7, 1]).is_err());
        // vendor-length overruns the value.
        assert!(VendorSpecific::decode_value(&[0, 0, 1, 0x37, 7, 9, 1, 2]).is_err());
        // Trailing partial header after a good sub-attribute.
        assert!(VendorSpecific::decode_value(&[0, 0, 1, 0x37, 7, 3, 1, 9]).is_err());
        // Wrong outer attribute type.
        let attr = Attribute::new(25, vec![0, 0, 1, 0x37, 7, 2]).unwrap();
        assert!(VendorSpecific::from_attribute(&attr).is_err());
    }

    #[test]
    fn decode_accepts_empty_sub_attribute_value() {
        let subs = VendorSpecific::decode_value(&[0, 0, 1, 0x37, 7, 2]).unwrap();
        assert_eq!(subs, vec![VendorSpecific::new(311, 7, vec![]).unwrap()]);
    }

    #[test]
    fn packet_find_vendor_attributes_filters_and_skips_malformed() {
        let mut p = Packet::new(Code::AccessAccept, 1, [0u8; 16]);
        p.add_attribute(
            VendorSpecific::new(311, 16, vec![1])
                .unwrap()
                .to_attribute()
                .unwrap(),
        );
        p.add_attribute(
            VendorSpecific::new(311, 17, vec![2])
                .unwrap()
                .to_attribute()
                .unwrap(),
        );
        p.add_attribute(
            VendorSpecific::new(9, 16, vec![3])
                .unwrap()
                .to_attribute()
                .unwrap(),
        );
        p.add_attribute(
            VendorSpecific::new(311, 16, vec![4])
                .unwrap()
                .to_attribute()
                .unwrap(),
        );
        // Malformed VSA: vendor-length overruns.
        p.add_attribute(Attribute::new(26, vec![0, 0, 1, 0x37, 16, 9]).unwrap());

        let found = p.find_vendor_attributes(311, 16);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].value, vec![1]);
        assert_eq!(found[1].value, vec![4]);
        assert_eq!(p.find_vendor_attributes(311, 17).len(), 1);
        assert!(p.find_vendor_attributes(311, 18).is_empty());
    }
}
