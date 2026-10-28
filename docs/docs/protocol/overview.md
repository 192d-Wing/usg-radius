# RADIUS Protocol Overview

The Remote Authentication Dial-In User Service (RADIUS) protocol is a network protocol that provides centralized Authentication, Authorization, and Accounting (AAA) management for users who connect and use a network service.

## RFC Compliance

USG RADIUS implements the following RFCs:

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 2865](https://tools.ietf.org/html/rfc2865) | Remote Authentication Dial In User Service (RADIUS) | ✅ Implemented |
| [RFC 2866](https://tools.ietf.org/html/rfc2866) | RADIUS Accounting | ✅ Implemented (dedicated 1813/udp socket) |
| [RFC 2869](https://tools.ietf.org/html/rfc2869) | RADIUS Extensions | ✅ Message-Authenticator |
| [RFC 5997](https://tools.ietf.org/html/rfc5997) | Use of Status-Server Messages | ✅ Implemented |

## Protocol Basics

### Transport

- **Protocol**: UDP
- **Authentication Port**: 1812 (legacy port 1645)
- **Accounting Port**: 1813 (legacy port 1646)
- **Packet Size**: Maximum 4096 bytes

### Communication Model

```
┌──────────┐                    ┌──────────┐
│  Client  │                    │  Server  │
│   (NAS)  │                    │ (RADIUS) │
└────┬─────┘                    └─────┬────┘
     │                                │
     │  Access-Request               │
     │─────────────────────────────>│
     │  (ID=1, User, Password)       │
     │                                │
     │              Access-Accept    │
     │<─────────────────────────────│
     │              (ID=1)           │
     │                                │
```

### Shared Secret

RADIUS uses a shared secret between the client and server for:

- Encrypting User-Password attributes
- Calculating Request and Response Authenticators
- Ensuring message integrity

!!! warning "Security"
    The shared secret should be at least 16 characters and kept confidential.

## Packet Structure

A RADIUS packet consists of a fixed header followed by zero or more attributes.

### Packet Header

Per RFC 2865 Section 3:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Authenticator                         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-
```

**Fields:**

- **Code** (1 byte): Packet type
- **Identifier** (1 byte): Matches requests with responses
- **Length** (2 bytes): Total packet length (20-4096 bytes)
- **Authenticator** (16 bytes): Request or Response Authenticator

### Packet Types (Code)

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| 1 | Access-Request | Client → Server | Authentication request |
| 2 | Access-Accept | Server → Client | Authentication success |
| 3 | Access-Reject | Server → Client | Authentication failure |
| 4 | Accounting-Request | Client → Server | Accounting data |
| 5 | Accounting-Response | Server → Client | Accounting acknowledgment |
| 11 | Access-Challenge | Server → Client | Challenge for additional auth |
| 12 | Status-Server | Client → Server | Server health check |
| 13 | Status-Client | Server → Client | Client health check |

## Attributes

Attributes carry specific authentication, authorization, and configuration information.

### Attribute Format

```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |  Value ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Fields:**

- **Type** (1 byte): Attribute type
- **Length** (1 byte): Attribute length (2-255 bytes)
- **Value** (0-253 bytes): Attribute value

### Common Attributes

| Type | Name | Data Type | Description |
|------|------|-----------|-------------|
| 1 | User-Name | String | Username for authentication |
| 2 | User-Password | String (encrypted) | User's password |
| 3 | CHAP-Password | String | CHAP encrypted password |
| 4 | NAS-IP-Address | IPv4 Address | IP address of NAS |
| 5 | NAS-Port | Integer | Physical port of NAS |
| 6 | Service-Type | Integer | Type of service requested |
| 18 | Reply-Message | String | Message to display to user |
| 24 | State | String | State information |
| 27 | Session-Timeout | Integer | Maximum session time |
| 80 | Message-Authenticator | String | HMAC-MD5 message authentication |

[Full Attribute List →](attributes.md)

## Authentication Flow

### Basic Authentication (PAP)

1. **Client sends Access-Request** with:
   - User-Name attribute
   - User-Password attribute (encrypted)
   - NAS-IP-Address and other identifying attributes
   - Random Request Authenticator

2. **Server processes request**:
   - Decrypts User-Password using shared secret
   - Validates credentials
   - Calculates Response Authenticator

3. **Server sends response**:
   - Access-Accept: Authentication successful
   - Access-Reject: Authentication failed
   - Access-Challenge: Additional authentication required

### Password Encryption

The User-Password attribute is encrypted using MD5:

Per RFC 2865 Section 5.2:

```
b(1) = MD5(Secret + Request Authenticator)
c(1) = p(1) XOR b(1)

b(i) = MD5(Secret + c(i-1))
c(i) = p(i) XOR b(i)
```

Where:

- `p(i)` = 16-byte blocks of password (padded with nulls)
- `c(i)` = encrypted blocks
- `b(i)` = MD5 hash blocks

!!! note
    User-Password encryption only protects the password in transit. The shared secret must be kept secure.

## Authenticators

### Request Authenticator

For Access-Request packets, the Request Authenticator is a random 16-byte value used to:

- Prevent replay attacks
- Encrypt the User-Password attribute
- Verify the Response Authenticator

### Response Authenticator

For response packets (Access-Accept, Access-Reject, Access-Challenge), the Response Authenticator is calculated as:

```
MD5(Code + ID + Length + Request Authenticator + Attributes + Secret)
```

This ensures:

- Message integrity
- Authentication of the server
- Protection against modification

## Message Flow Example

### Successful Authentication

```
Client                                Server
  |                                     |
  | Access-Request                      |
  |  Code: 1                            |
  |  ID: 42                             |
  |  Authenticator: [random]            |
  |  User-Name: "alice"                 |
  |  User-Password: [encrypted]         |
  |  NAS-IP-Address: 192.168.1.1        |
  |------------------------------------>|
  |                                     |
  |                                     | [Validate credentials]
  |                                     | [Calculate Response Auth]
  |                                     |
  |              Access-Accept          |
  |  Code: 2                            |
  |  ID: 42                             |
  |  Authenticator: [calculated]        |
  |  Session-Timeout: 3600              |
  |  Reply-Message: "Welcome!"          |
  |<------------------------------------|
  |                                     |
```

### Failed Authentication

```
Client                                Server
  |                                     |
  | Access-Request                      |
  |  User-Name: "bob"                   |
  |  User-Password: [encrypted]         |
  |------------------------------------>|
  |                                     |
  |                                     | [Credentials invalid]
  |                                     |
  |              Access-Reject          |
  |  Reply-Message: "Auth failed"       |
  |<------------------------------------|
  |                                     |
```

## Security Considerations

### MD5 Weaknesses

RADIUS uses MD5, which has known cryptographic weaknesses:

- ✅ Sufficient for RADIUS use case (not used for digital signatures)
- ⚠️ User-Password encryption is not end-to-end secure
- ⚠️ Vulnerable to offline dictionary attacks if secret is weak

**Recommendations:**

1. Use strong shared secrets (16+ characters, random)
2. Consider deploying RadSec (RADIUS over TLS) for sensitive environments
3. Use IPsec or VPN for RADIUS traffic over untrusted networks
4. Implement EAP methods for stronger authentication

### Best Practices

1. **Unique Secrets**: Use different shared secrets for each client
2. **Secret Rotation**: Regularly rotate shared secrets
3. **Network Isolation**: Keep RADIUS traffic on isolated networks
4. **Monitoring**: Log and monitor all authentication attempts
5. **Rate Limiting**: Implement rate limiting to prevent brute force attacks

## Implementation Details

### Packet Encoding

```rust
use usg_radius::{Packet, Code, Attribute};

// Create Access-Accept packet
let mut packet = Packet::new(
    Code::AccessAccept,
    identifier,
    authenticator
);

// Add attributes
packet.add_attribute(
    Attribute::string(1, "alice").unwrap()
);

// Encode to bytes
let bytes = packet.encode()?;
```

### Packet Decoding

```rust
// Decode from bytes
let packet = Packet::decode(&bytes)?;

// Access fields
println!("Code: {:?}", packet.code);
println!("ID: {}", packet.identifier);

// Find attributes
if let Some(attr) = packet.find_attribute(1) {
    let username = attr.as_string()?;
    println!("Username: {}", username);
}
```

## Next Steps

- [Attribute Reference](attributes.md)
- [Authentication Methods](authentication.md)
- [Status-Server Implementation](status-server.md)
