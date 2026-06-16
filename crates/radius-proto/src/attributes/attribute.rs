use crate::packet::PacketError;
use std::io::{Cursor, Read, Write};

/// RADIUS Attribute structure as defined in RFC 2865 Section 5
///
/// ```text
///  0                   1                   2
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |  Value ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute type (1 byte)
    pub attr_type: u8,
    /// Attribute value (0-253 bytes)
    pub value: Vec<u8>,
}

impl Attribute {
    /// Minimum attribute length (type + length fields = 2 bytes)
    pub const MIN_LENGTH: usize = 2;
    /// Maximum attribute length (255 bytes including type and length)
    pub const MAX_LENGTH: usize = 255;
    /// Maximum value length (253 bytes)
    pub const MAX_VALUE_LENGTH: usize = 253;

    pub fn new(attr_type: u8, value: Vec<u8>) -> Result<Self, PacketError> {
        if value.len() > Self::MAX_VALUE_LENGTH {
            return Err(PacketError::AttributeError(format!(
                "Attribute value too long: {} bytes (max {})",
                value.len(),
                Self::MAX_VALUE_LENGTH
            )));
        }
        Ok(Attribute { attr_type, value })
    }

    /// Create a string attribute
    pub fn string(attr_type: u8, value: impl Into<String>) -> Result<Self, PacketError> {
        Self::new(attr_type, value.into().into_bytes())
    }

    /// Create an integer attribute (32-bit big-endian)
    pub fn integer(attr_type: u8, value: u32) -> Result<Self, PacketError> {
        Self::new(attr_type, value.to_be_bytes().to_vec())
    }

    /// Create an IP address attribute
    pub fn ipv4(attr_type: u8, value: [u8; 4]) -> Result<Self, PacketError> {
        Self::new(attr_type, value.to_vec())
    }

    /// Encode attribute to bytes
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let length = self.encoded_length();
        if length > Self::MAX_LENGTH {
            return Err(PacketError::AttributeError(format!(
                "Encoded attribute too long: {} bytes",
                length
            )));
        }

        let mut buffer = Vec::with_capacity(length);
        buffer.write_all(&[self.attr_type])?;
        buffer.write_all(&[length as u8])?;
        buffer.write_all(&self.value)?;

        Ok(buffer)
    }

    /// Decode attribute from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < Self::MIN_LENGTH {
            return Err(PacketError::AttributeError(format!(
                "Attribute data too short: {} bytes",
                data.len()
            )));
        }

        let mut cursor = Cursor::new(data);

        // Read type
        let mut type_buf = [0u8; 1];
        cursor.read_exact(&mut type_buf)?;
        let attr_type = type_buf[0];

        // Read length
        let mut len_buf = [0u8; 1];
        cursor.read_exact(&mut len_buf)?;
        let length = len_buf[0] as usize;

        if !(Self::MIN_LENGTH..=Self::MAX_LENGTH).contains(&length) {
            return Err(PacketError::AttributeError(format!(
                "Invalid attribute length: {}",
                length
            )));
        }

        if data.len() < length {
            return Err(PacketError::AttributeError(format!(
                "Insufficient data for attribute: expected {}, got {}",
                length,
                data.len()
            )));
        }

        // Read value
        let value_length = length - Self::MIN_LENGTH;
        let mut value = vec![0u8; value_length];
        cursor.read_exact(&mut value)?;

        Ok(Attribute { attr_type, value })
    }

    /// Get the encoded length of this attribute
    pub fn encoded_length(&self) -> usize {
        Self::MIN_LENGTH + self.value.len()
    }

    /// Try to interpret value as a string
    pub fn as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.value.clone())
    }

    /// Try to interpret value as an integer (32-bit big-endian)
    pub fn as_integer(&self) -> Result<u32, PacketError> {
        if self.value.len() != 4 {
            return Err(PacketError::AttributeError(format!(
                "Expected 4 bytes for integer, got {}",
                self.value.len()
            )));
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.value);
        Ok(u32::from_be_bytes(bytes))
    }

    /// Try to interpret value as an IPv4 address
    pub fn as_ipv4(&self) -> Result<[u8; 4], PacketError> {
        if self.value.len() != 4 {
            return Err(PacketError::AttributeError(format!(
                "Expected 4 bytes for IPv4, got {}",
                self.value.len()
            )));
        }
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&self.value);
        Ok(addr)
    }

    /// Interpret the value as a 16-octet IPv6 address (RFC 3162).
    pub fn as_ipv6(&self) -> Result<[u8; 16], PacketError> {
        if self.value.len() != 16 {
            return Err(PacketError::AttributeError(format!(
                "Expected 16 bytes for IPv6, got {}",
                self.value.len()
            )));
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.value);
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_attribute() {
        let attr = Attribute::string(1, "testuser").unwrap();
        assert_eq!(attr.attr_type, 1);
        assert_eq!(attr.as_string().unwrap(), "testuser");
    }

    #[test]
    fn test_integer_attribute() {
        let attr = Attribute::integer(6, 1234).unwrap();
        assert_eq!(attr.attr_type, 6);
        assert_eq!(attr.as_integer().unwrap(), 1234);
    }

    #[test]
    fn test_attribute_encode_decode() {
        let attr = Attribute::string(1, "test").unwrap();
        let encoded = attr.encode().unwrap();
        let decoded = Attribute::decode(&encoded).unwrap();
        assert_eq!(attr, decoded);
    }

    #[test]
    fn test_max_value_length() {
        let value = vec![0u8; 254];
        assert!(Attribute::new(1, value).is_err());
    }
}
