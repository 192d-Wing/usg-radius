//! Integration tests for USG RADIUS Server
//!
//! These tests verify end-to-end functionality including:
//! - Authentication flows (PAP and CHAP)
//! - Multi-round authentication (Access-Challenge)

#![allow(clippy::field_reassign_with_default)]
//! - Client validation
//! - Rate limiting
//! - Configuration validation
//! - Audit logging

use radius_proto::accounting::AcctStatusType;
use radius_proto::auth::{
    calculate_accounting_request_authenticator, encrypt_user_password,
    generate_request_authenticator,
};
use radius_proto::chap::{ChapChallenge, ChapResponse, compute_chap_response};
use radius_proto::{Attribute, AttributeType, Code, Packet, calculate_message_authenticator};
use radius_server::{
    AccountingHandler, AuthHandler, AuthResult, Config, RadiusServer, ServerConfig,
    SimpleAccountingHandler, SimpleAuthHandler,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Test helper to create a RADIUS Access-Request packet with PAP
fn create_access_request(username: &str, password: &str, secret: &[u8], identifier: u8) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, identifier, req_auth);

    // Add User-Name attribute
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted User-Password
    let encrypted_pwd = encrypt_user_password(password, secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password attribute"),
    );

    // Add NAS-IP-Address (RFC 2865 requires either NAS-IP-Address or NAS-Identifier)
    packet.add_attribute(
        Attribute::new(
            AttributeType::NasIpAddress as u8,
            vec![127, 0, 0, 1], // 127.0.0.1
        )
        .expect("Failed to create NAS-IP-Address attribute"),
    );

    packet
}

/// Test helper to create a RADIUS Access-Request packet with CHAP
fn create_chap_access_request(
    username: &str,
    password: &str,
    identifier: u8,
    chap_ident: u8,
) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, identifier, req_auth);

    // Add User-Name attribute
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name attribute"),
    );

    // Compute CHAP response using Request Authenticator as challenge
    let challenge = ChapChallenge::from_authenticator(&req_auth);
    let response_hash = compute_chap_response(chap_ident, password, challenge.as_bytes());
    let chap_response = ChapResponse {
        ident: chap_ident,
        response: response_hash,
    };

    // Add CHAP-Password attribute (17 bytes: 1 byte ident + 16 bytes hash)
    packet.add_attribute(
        Attribute::new(AttributeType::ChapPassword as u8, chap_response.to_bytes())
            .expect("Failed to create CHAP-Password attribute"),
    );

    // Add NAS-IP-Address (RFC 2865 requires either NAS-IP-Address or NAS-Identifier)
    packet.add_attribute(
        Attribute::new(
            AttributeType::NasIpAddress as u8,
            vec![127, 0, 0, 1], // 127.0.0.1
        )
        .expect("Failed to create NAS-IP-Address attribute"),
    );

    packet
}

/// Test helper to send a RADIUS packet and receive response
async fn send_radius_request(
    packet: &Packet,
    server_addr: SocketAddr,
) -> Result<Packet, Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket as AsyncUdpSocket;
    use tokio::time::timeout;

    let socket = AsyncUdpSocket::bind("127.0.0.1:0").await?;

    let bytes = packet.encode()?;
    socket.send_to(&bytes, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;

    let response = Packet::decode(&buf[..len])?;
    Ok(response)
}

#[tokio::test]
async fn test_successful_authentication() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0; // Let OS assign port
    config.secret = "testing123".to_string();

    // Create authentication handler
    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    // Create server
    let server_config = ServerConfig::from_config(config.clone(), Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");

    // Get the actual port assigned
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        server.run().await.expect("Server failed");
    });

    // Wait for server to start
    sleep(Duration::from_millis(500)).await;

    // Create and send Access-Request
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Accept response
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_failed_authentication_wrong_password() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "correctpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request with wrong password
    let packet = create_access_request("testuser", "wrongpass", b"testing123", 2);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 2);
}

#[tokio::test]
async fn test_failed_authentication_unknown_user() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("realuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request for unknown user
    let packet = create_access_request("unknownuser", "password", b"testing123", 3);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 3);
}

#[tokio::test]
async fn test_multiple_sequential_authentications() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("user1", "pass1");
    handler.add_user("user2", "pass2");
    handler.add_user("user3", "pass3");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test multiple users sequentially
    for (i, (username, password)) in [("user1", "pass1"), ("user2", "pass2"), ("user3", "pass3")]
        .iter()
        .enumerate()
    {
        let packet = create_access_request(username, password, b"testing123", (i + 1) as u8);

        let response = send_radius_request(&packet, server_addr)
            .await
            .expect("Failed to send request");

        assert_eq!(
            response.code,
            Code::AccessAccept,
            "Failed for user {}",
            username
        );
        assert_eq!(response.identifier, (i + 1) as u8);
    }
}

#[test]
fn test_env_var_expansion() {
    use std::env;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Set test environment variable
    // SAFETY: This test runs in isolation and sets/removes test-specific environment variables.
    // The variables are cleaned up at the end of the test.
    unsafe {
        env::set_var("TEST_RADIUS_SECRET", "env_secret_value");
    }

    // Create temporary config file with env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{TEST_RADIUS_SECRET}}",
        "clients": [],
        "users": []
    }}"#
    )
    .expect("Failed to write to temp file");

    // Load config
    let config = Config::from_file(temp_file.path()).expect("Failed to load config with env var");

    // Verify env var was expanded
    assert_eq!(config.secret, "env_secret_value");

    // Clean up
    // SAFETY: Cleaning up test-specific environment variable
    unsafe {
        env::remove_var("TEST_RADIUS_SECRET");
    }
}

#[test]
fn test_env_var_not_found() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create config with non-existent env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{NONEXISTENT_VAR_12345}}",
        "clients": [],
        "users": []
    }}"#
    )
    .expect("Failed to write to temp file");

    // Should fail to load
    let result = Config::from_file(temp_file.path());
    assert!(result.is_err(), "Should fail with missing env var");
}

#[tokio::test]
async fn test_rate_limiting() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Set very low rate limits for testing
    config.rate_limit_per_client_rps = Some(2);
    config.rate_limit_per_client_burst = Some(3);

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send requests rapidly to trigger rate limit
    // First 3 should succeed (burst), then rate limit kicks in
    let mut success_count = 0;
    let mut rate_limited = false;

    for i in 0..10 {
        let packet = create_access_request("testuser", "testpass", b"testing123", i);

        // Try to send request with short timeout
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            send_radius_request(&packet, server_addr),
        )
        .await;

        match result {
            Ok(Ok(_response)) => {
                success_count += 1;
            }
            Ok(Err(_)) | Err(_) => {
                rate_limited = true;
            }
        }
    }

    // Should have some successful requests and some rate limited
    assert!(success_count > 0, "Should have some successful requests");
    assert!(rate_limited, "Should have triggered rate limiting");
    assert!(
        success_count < 10,
        "Not all requests should succeed due to rate limiting"
    );
}

#[tokio::test]
async fn test_client_ip_validation() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create config with specific client IP restrictions
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "127.0.0.1",
        "listen_port": 1812,
        "secret": "testing123",
        "clients": [
            {{
                "name": "Test Client",
                "address": "127.0.0.1",
                "secret": "testing123"
            }}
        ],
        "users": [
            {{
                "username": "testuser",
                "password": "testpass"
            }}
        ]
    }}"#
    )
    .expect("Failed to write to temp file");

    let mut config = Config::from_file(temp_file.path()).expect("Failed to load config");

    // Override to use OS-assigned port for testing
    config.listen_port = 0;

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request from authorized IP (127.0.0.1)
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Should succeed because 127.0.0.1 is authorized
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_nas_identifier_validation() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create config with NAS-Identifier requirement
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "127.0.0.1",
        "listen_port": 1812,
        "secret": "testing123",
        "clients": [
            {{
                "name": "Test Switch",
                "address": "127.0.0.1",
                "secret": "testing123",
                "nas_identifier": "switch01.example.com"
            }}
        ],
        "users": [
            {{
                "username": "testuser",
                "password": "testpass"
            }}
        ]
    }}"#
    )
    .expect("Failed to write to temp file");

    let mut config = Config::from_file(temp_file.path()).expect("Failed to load config");
    config.listen_port = 0; // OS-assigned port

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test 1: Request with correct NAS-Identifier
    let req_auth1 = generate_request_authenticator();
    let mut packet1 = Packet::new(Code::AccessRequest, 1, req_auth1);
    packet1.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );
    let encrypted_pwd1 = encrypt_user_password("testpass", b"testing123", &req_auth1);
    packet1.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd1)
            .expect("Failed to create User-Password attribute"),
    );
    packet1.add_attribute(
        Attribute::string(AttributeType::NasIdentifier as u8, "switch01.example.com")
            .expect("Failed to create NAS-Identifier attribute"),
    );

    let response1 = send_radius_request(&packet1, server_addr)
        .await
        .expect("Failed to send request with correct NAS-Identifier");

    // Should succeed with correct NAS-Identifier
    assert_eq!(response1.code, Code::AccessAccept);

    // Test 2: Request with wrong NAS-Identifier
    let req_auth2 = generate_request_authenticator();
    let mut packet2 = Packet::new(Code::AccessRequest, 2, req_auth2);
    packet2.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );
    let encrypted_pwd2 = encrypt_user_password("testpass", b"testing123", &req_auth2);
    packet2.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd2)
            .expect("Failed to create User-Password attribute"),
    );
    packet2.add_attribute(
        Attribute::string(
            AttributeType::NasIdentifier as u8,
            "wrongswitch.example.com",
        )
        .expect("Failed to create NAS-Identifier attribute"),
    );

    let result2 = send_radius_request(&packet2, server_addr).await;

    // Should timeout because server rejects packets with wrong NAS-Identifier
    assert!(
        result2.is_err(),
        "Expected timeout for wrong NAS-Identifier"
    );

    // Test 3: Request without NAS-Identifier (when required)
    let req_auth3 = generate_request_authenticator();
    let mut packet3 = Packet::new(Code::AccessRequest, 3, req_auth3);
    packet3.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );
    let encrypted_pwd3 = encrypt_user_password("testpass", b"testing123", &req_auth3);
    packet3.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd3)
            .expect("Failed to create User-Password attribute"),
    );
    // Add NAS-IP-Address instead of NAS-Identifier
    packet3.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address attribute"),
    );

    let result3 = send_radius_request(&packet3, server_addr).await;

    // Should timeout because NAS-Identifier is required but not provided
    assert!(
        result3.is_err(),
        "Expected timeout for missing NAS-Identifier"
    );
}

#[tokio::test]
async fn test_ipv6_support() {
    use tokio::net::UdpSocket as AsyncUdpSocket;

    // Check if IPv6 is available on this system
    let ipv6_test = AsyncUdpSocket::bind("[::1]:0").await;
    if ipv6_test.is_err() {
        // IPv6 not available, skip test
        println!("IPv6 not available on this system, skipping test");
        return;
    }
    drop(ipv6_test);

    let mut config = Config::default();
    config.listen_address = "::1".to_string(); // IPv6 loopback
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await;

    // If server creation fails (IPv6 not supported), skip test
    if server.is_err() {
        println!("IPv6 server creation failed, skipping test");
        return;
    }

    let server = server.unwrap();
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request over IPv6
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

    // Try to send request over IPv6
    let result = send_radius_request(&packet, server_addr).await;

    // If we get a routing error, IPv6 isn't fully configured, skip test
    if let Err(ref e) = result
        && (e.to_string().contains("No route to host") || e.to_string().contains("HostUnreachable"))
    {
        println!("IPv6 routing not configured, skipping test");
        return;
    }

    let response = result.expect("Failed to send request over IPv6");
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_duplicate_request_detection() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();
    config.request_cache_ttl = Some(10); // 10 second TTL

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send same request twice
    let packet = create_access_request(
        "testuser",
        "testpass",
        b"testing123",
        42, // Use specific ID
    );

    // First request should succeed
    let response1 = send_radius_request(&packet, server_addr)
        .await
        .expect("First request failed");
    assert_eq!(response1.code, Code::AccessAccept);

    // Immediate duplicate should be silently dropped (no response)
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        send_radius_request(&packet, server_addr),
    )
    .await;

    // Should timeout because duplicate requests are silently dropped
    assert!(
        result.is_err(),
        "Duplicate request should timeout (be silently dropped)"
    );
}

#[tokio::test]
async fn test_chap_successful_authentication() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create authentication handler
    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "chappass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Create and send CHAP Access-Request
    let packet = create_chap_access_request("chapuser", "chappass", 1, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Accept response
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_chap_failed_authentication_wrong_password() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "correctpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send CHAP request with wrong password
    let packet = create_chap_access_request("chapuser", "wrongpass", 2, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 2);
}

#[tokio::test]
async fn test_chap_failed_authentication_unknown_user() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("realuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send CHAP request for unknown user
    let packet = create_chap_access_request("unknownuser", "password", 3, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 3);
}

#[tokio::test]
async fn test_chap_and_pap_interleaved() {
    // Test that server can handle both PAP and CHAP requests
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("user1", "pass1");
    handler.add_user("user2", "pass2");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test PAP request
    let pap_packet = create_access_request("user1", "pass1", b"testing123", 1);
    let response = send_radius_request(&pap_packet, server_addr)
        .await
        .expect("Failed to send PAP request");
    assert_eq!(response.code, Code::AccessAccept);

    // Test CHAP request
    let chap_packet = create_chap_access_request("user2", "pass2", 2, 42);
    let response = send_radius_request(&chap_packet, server_addr)
        .await
        .expect("Failed to send CHAP request");
    assert_eq!(response.code, Code::AccessAccept);

    // Test another PAP request
    let pap_packet2 = create_access_request("user1", "pass1", b"testing123", 3);
    let response = send_radius_request(&pap_packet2, server_addr)
        .await
        .expect("Failed to send second PAP request");
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_chap_different_identifiers() {
    // Test that CHAP works with different CHAP identifiers
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "chappass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test with different CHAP identifiers
    for chap_ident in [0x01, 0x42, 0x7F, 0xFF] {
        let packet = create_chap_access_request("chapuser", "chappass", chap_ident, chap_ident);
        let response = send_radius_request(&packet, server_addr)
            .await
            .expect("Failed to send CHAP request");
        assert_eq!(
            response.code,
            Code::AccessAccept,
            "Failed with CHAP identifier {}",
            chap_ident
        );
    }
}

/// Custom authentication handler for testing Access-Challenge
struct ChallengeAuthHandler {
    users: std::collections::HashMap<String, String>,
    pin: String,
}

impl ChallengeAuthHandler {
    fn new() -> Self {
        ChallengeAuthHandler {
            users: std::collections::HashMap::new(),
            pin: "1234".to_string(),
        }
    }

    fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }
}

impl AuthHandler for ChallengeAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Simple password check
        self.users
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }

    fn get_user_password(&self, username: &str) -> Option<String> {
        self.users.get(username).cloned()
    }

    fn authenticate_with_challenge(
        &self,
        username: &str,
        password: Option<&str>,
        state: Option<&[u8]>,
    ) -> AuthResult {
        // Check if user exists
        if !self.users.contains_key(username) {
            return AuthResult::Reject;
        }

        // If no state, this is the first request - send challenge
        if state.is_none() {
            return AuthResult::Challenge {
                message: Some("Please enter your PIN".to_string()),
                state: b"challenge_state_123".to_vec(),
                attributes: vec![],
            };
        }

        // If we have state, verify it and check the PIN
        if state == Some(b"challenge_state_123" as &[u8]) {
            // Password should be the PIN
            if let Some(pwd) = password
                && pwd == self.pin
            {
                return AuthResult::accept();
            }
        }

        AuthResult::Reject
    }
}

#[tokio::test]
async fn test_access_challenge() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create challenge authentication handler
    let mut handler = ChallengeAuthHandler::new();
    handler.add_user("challengeuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // First request - should get Access-Challenge
    let packet1 = create_access_request("challengeuser", "password", b"testing123", 1);
    let response1 = send_radius_request(&packet1, server_addr)
        .await
        .expect("Failed to send first request");

    assert_eq!(response1.code, Code::AccessChallenge);
    assert_eq!(response1.identifier, 1);

    // Extract State attribute from challenge
    let state_attr = response1
        .find_attribute(AttributeType::State as u8)
        .expect("State attribute should be present in Access-Challenge");

    // Verify Reply-Message is present
    let reply_msg = response1
        .find_attribute(AttributeType::ReplyMessage as u8)
        .and_then(|attr| attr.as_string().ok());
    assert_eq!(reply_msg, Some("Please enter your PIN".to_string()));

    // Second request - with State and correct PIN
    let req_auth2 = generate_request_authenticator();
    let mut packet2 = Packet::new(Code::AccessRequest, 2, req_auth2);

    // Add User-Name
    packet2.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "challengeuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted PIN as User-Password
    let encrypted_pin = encrypt_user_password("1234", b"testing123", &req_auth2);
    packet2.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pin)
            .expect("Failed to create User-Password attribute"),
    );

    // Add State attribute from previous response
    packet2.add_attribute(
        Attribute::new(AttributeType::State as u8, state_attr.value.clone())
            .expect("Failed to create State attribute"),
    );

    // Add NAS-IP-Address (RFC 2865 requires either NAS-IP-Address or NAS-Identifier)
    packet2.add_attribute(
        Attribute::new(
            AttributeType::NasIpAddress as u8,
            vec![127, 0, 0, 1], // 127.0.0.1
        )
        .expect("Failed to create NAS-IP-Address attribute"),
    );

    let response2 = send_radius_request(&packet2, server_addr)
        .await
        .expect("Failed to send second request");

    // Should now get Access-Accept
    assert_eq!(response2.code, Code::AccessAccept);
    assert_eq!(response2.identifier, 2);
}

#[tokio::test]
async fn test_access_challenge_wrong_pin() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create challenge authentication handler
    let mut handler = ChallengeAuthHandler::new();
    handler.add_user("challengeuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // First request - should get Access-Challenge
    let packet1 = create_access_request("challengeuser", "password", b"testing123", 1);
    let response1 = send_radius_request(&packet1, server_addr)
        .await
        .expect("Failed to send first request");

    assert_eq!(response1.code, Code::AccessChallenge);

    // Extract State attribute
    let state_attr = response1
        .find_attribute(AttributeType::State as u8)
        .expect("State attribute should be present");

    // Second request - with State but WRONG PIN
    let req_auth2 = generate_request_authenticator();
    let mut packet2 = Packet::new(Code::AccessRequest, 2, req_auth2);

    packet2.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "challengeuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add wrong PIN
    let encrypted_pin = encrypt_user_password("9999", b"testing123", &req_auth2);
    packet2.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pin)
            .expect("Failed to create User-Password attribute"),
    );

    packet2.add_attribute(
        Attribute::new(AttributeType::State as u8, state_attr.value.clone())
            .expect("Failed to create State attribute"),
    );

    // Add NAS-IP-Address (RFC 2865 requires either NAS-IP-Address or NAS-Identifier)
    packet2.add_attribute(
        Attribute::new(
            AttributeType::NasIpAddress as u8,
            vec![127, 0, 0, 1], // 127.0.0.1
        )
        .expect("Failed to create NAS-IP-Address attribute"),
    );

    let response2 = send_radius_request(&packet2, server_addr)
        .await
        .expect("Failed to send second request");

    // Should get Access-Reject for wrong PIN
    assert_eq!(response2.code, Code::AccessReject);
    assert_eq!(response2.identifier, 2);
}

// ============================================================================
// Accounting Tests
// ============================================================================

/// Test helper to create an Accounting-Request packet
fn create_accounting_request(
    status_type: AcctStatusType,
    session_id: &str,
    username: &str,
    identifier: u8,
    secret: &[u8],
) -> Packet {
    // Create packet with zero authenticator initially
    let mut packet = Packet::new(Code::AccountingRequest, identifier, [0u8; 16]);

    // Add Acct-Status-Type
    let status_bytes = status_type.as_u32().to_be_bytes().to_vec();
    packet.add_attribute(
        Attribute::new(AttributeType::AcctStatusType as u8, status_bytes)
            .expect("Failed to create Acct-Status-Type attribute"),
    );

    // Add Acct-Session-Id (for session-related accounting)
    if status_type.is_session_status() {
        packet.add_attribute(
            Attribute::string(AttributeType::AcctSessionId as u8, session_id)
                .expect("Failed to create Acct-Session-Id attribute"),
        );
    }

    // Add User-Name (for session-related accounting)
    if status_type.is_session_status() {
        packet.add_attribute(
            Attribute::string(AttributeType::UserName as u8, username)
                .expect("Failed to create User-Name attribute"),
        );
    }

    // Calculate and set the accounting request authenticator (RFC 2866)
    let authenticator = calculate_accounting_request_authenticator(&packet, secret);
    packet.authenticator = authenticator;

    packet
}

#[tokio::test]
async fn test_accounting_session_lifecycle() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0; // Let OS assign a random port

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");
    let accounting_handler_impl = Arc::new(SimpleAccountingHandler::new());
    let accounting_handler = accounting_handler_impl.clone() as Arc<dyn AccountingHandler>;

    // Create server config with accounting enabled
    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler.clone());

    // Start server
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";
    let session_id = "session-12345";

    // Test 1: Accounting Start
    let start_packet =
        create_accounting_request(AcctStatusType::Start, session_id, "testuser", 1, secret);
    let start_response = send_radius_request(&start_packet, server_addr)
        .await
        .expect("Failed to send Accounting-Start");

    assert_eq!(start_response.code, Code::AccountingResponse);
    assert_eq!(start_response.identifier, 1);
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Test 2: Interim Update
    let mut interim_packet = Packet::new(Code::AccountingRequest, 2, [0u8; 16]);

    // Add Acct-Status-Type
    interim_packet.add_attribute(
        Attribute::new(
            AttributeType::AcctStatusType as u8,
            AcctStatusType::InterimUpdate
                .as_u32()
                .to_be_bytes()
                .to_vec(),
        )
        .expect("Failed to create Acct-Status-Type attribute"),
    );

    // Add session info
    interim_packet.add_attribute(
        Attribute::string(AttributeType::AcctSessionId as u8, session_id)
            .expect("Failed to create Acct-Session-Id attribute"),
    );
    interim_packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add usage statistics
    interim_packet.add_attribute(
        Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 60])
            .expect("Failed to create Acct-Session-Time attribute"),
    );
    interim_packet.add_attribute(
        Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 1, 0])
            .expect("Failed to create Acct-Input-Octets attribute"),
    );

    // Calculate authenticator after all attributes are added
    let interim_auth = calculate_accounting_request_authenticator(&interim_packet, secret);
    interim_packet.authenticator = interim_auth;

    let interim_response = send_radius_request(&interim_packet, server_addr)
        .await
        .expect("Failed to send Interim-Update");

    assert_eq!(interim_response.code, Code::AccountingResponse);
    assert_eq!(interim_response.identifier, 2);
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Verify session was updated
    let sessions = accounting_handler_impl.get_active_sessions().await;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_time, 60);
    assert_eq!(sessions[0].input_octets, 256);

    // Test 3: Accounting Stop
    let mut stop_packet = Packet::new(Code::AccountingRequest, 3, [0u8; 16]);

    // Add Acct-Status-Type
    stop_packet.add_attribute(
        Attribute::new(
            AttributeType::AcctStatusType as u8,
            AcctStatusType::Stop.as_u32().to_be_bytes().to_vec(),
        )
        .expect("Failed to create Acct-Status-Type attribute"),
    );

    // Add session info
    stop_packet.add_attribute(
        Attribute::string(AttributeType::AcctSessionId as u8, session_id)
            .expect("Failed to create Acct-Session-Id attribute"),
    );
    stop_packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add final usage statistics
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 1, 44])
            .expect("Failed to create Acct-Session-Time attribute"),
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 2, 0])
            .expect("Failed to create Acct-Input-Octets attribute"),
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctOutputOctets as u8, vec![0, 0, 3, 0])
            .expect("Failed to create Acct-Output-Octets attribute"),
    );

    // Calculate authenticator after all attributes are added
    let stop_auth = calculate_accounting_request_authenticator(&stop_packet, secret);
    stop_packet.authenticator = stop_auth;

    let stop_response = send_radius_request(&stop_packet, server_addr)
        .await
        .expect("Failed to send Accounting-Stop");

    assert_eq!(stop_response.code, Code::AccountingResponse);
    assert_eq!(stop_response.identifier, 3);

    // Session should be removed after stop
    assert_eq!(accounting_handler_impl.session_count(), 0);
}

#[tokio::test]
async fn test_accounting_nas_events() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0; // Let OS assign a random port

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");
    let accounting_handler_impl = Arc::new(SimpleAccountingHandler::new());
    let accounting_handler = accounting_handler_impl.clone() as Arc<dyn AccountingHandler>;

    // Create server config with accounting enabled
    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler.clone());

    // Start server
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";

    // Test Accounting-On
    let on_packet = create_accounting_request(AcctStatusType::AccountingOn, "", "", 1, secret);
    let on_response = send_radius_request(&on_packet, server_addr)
        .await
        .expect("Failed to send Accounting-On");

    assert_eq!(on_response.code, Code::AccountingResponse);
    assert_eq!(on_response.identifier, 1);

    // Create a few sessions
    for i in 0..3 {
        let session_id = format!("session-{}", i);
        let start_packet = create_accounting_request(
            AcctStatusType::Start,
            &session_id,
            "testuser",
            i + 2,
            secret,
        );
        let _ = send_radius_request(&start_packet, server_addr).await;
    }

    assert_eq!(accounting_handler_impl.session_count(), 3);

    // Test Accounting-Off (should terminate all sessions from this NAS)
    let off_packet = create_accounting_request(AcctStatusType::AccountingOff, "", "", 10, secret);
    let off_response = send_radius_request(&off_packet, server_addr)
        .await
        .expect("Failed to send Accounting-Off");

    assert_eq!(off_response.code, Code::AccountingResponse);
    assert_eq!(off_response.identifier, 10);

    // All sessions from this NAS should be terminated
    // Note: In real implementation, this would only clear sessions from the specific NAS IP
    // For this test, since all sessions are from 127.0.0.1, they should all be removed
    assert_eq!(accounting_handler_impl.session_count(), 0);
}

#[tokio::test]
async fn test_accounting_without_handler() {
    // Create test configuration without accounting handler
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0; // Let OS assign a random port

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    // Create server config WITHOUT accounting enabled
    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    // Start server
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";

    // Try to send accounting request
    let start_packet =
        create_accounting_request(AcctStatusType::Start, "session-123", "testuser", 1, secret);

    // Request should fail silently or return no response
    // (server will log an error but won't respond to invalid requests)
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        send_radius_request(&start_packet, server_addr),
    )
    .await;

    // Should timeout since server doesn't respond to accounting without handler
    assert!(result.is_err() || result.unwrap().is_err());
}

/// Test Message-Authenticator validation (RFC 2869)
#[tokio::test]
async fn test_message_authenticator_valid() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Create Access-Request with Message-Authenticator
    let secret = b"testing123";
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, 1, req_auth);

    // Add User-Name
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted User-Password
    let encrypted_pwd = encrypt_user_password("testpass", secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password attribute"),
    );

    // Add NAS-IP-Address
    packet.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address attribute"),
    );

    // Add Message-Authenticator placeholder (will be calculated)
    packet.add_attribute(
        Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16])
            .expect("Failed to create Message-Authenticator attribute"),
    );

    // Calculate proper Message-Authenticator
    let mut packet_bytes = packet.encode().expect("Failed to encode packet");

    // Find Message-Authenticator offset
    let mut offset = 20; // Header size
    for attr in &packet.attributes {
        if attr.attr_type == AttributeType::MessageAuthenticator as u8 {
            // Skip Type (1) + Length (1) to get to value
            offset += 2;
            break;
        }
        offset += 2 + attr.value.len();
    }

    // Calculate and insert correct Message-Authenticator
    let mut packet_copy = packet_bytes.clone();
    packet_copy[offset..offset + 16].fill(0);
    let msg_auth = calculate_message_authenticator(&packet_copy, secret);
    packet_bytes[offset..offset + 16].copy_from_slice(&msg_auth);

    // Decode the corrected packet
    let packet = Packet::decode(&packet_bytes).expect("Failed to decode packet");

    // Send request
    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Should succeed with Access-Accept
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

/// Test Message-Authenticator validation with invalid authenticator
#[tokio::test]
async fn test_message_authenticator_invalid() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Create Access-Request with invalid Message-Authenticator
    let secret = b"testing123";
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, 2, req_auth);

    // Add User-Name
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted User-Password
    let encrypted_pwd = encrypt_user_password("testpass", secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password attribute"),
    );

    // Add NAS-IP-Address
    packet.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address attribute"),
    );

    // Add INVALID Message-Authenticator (all 0xFF instead of proper HMAC)
    packet.add_attribute(
        Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0xFF; 16])
            .expect("Failed to create Message-Authenticator attribute"),
    );

    // Send request with invalid Message-Authenticator
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        send_radius_request(&packet, server_addr),
    )
    .await;

    // Server should reject the request (either timeout or no response)
    // Typically servers don't respond to invalid Message-Authenticator for security
    assert!(result.is_err() || matches!(result, Ok(Err(_))));
}

/// Test that requests without Message-Authenticator still work (it's optional)
#[tokio::test]
async fn test_message_authenticator_optional() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Create normal Access-Request WITHOUT Message-Authenticator
    let packet = create_access_request("testuser", "testpass", b"testing123", 3);

    // Send request
    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Should succeed - Message-Authenticator is optional
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 3);
}

/// Test session timeout handling
#[tokio::test]
async fn test_accounting_session_timeout() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    // Create accounting handler with 2 second timeout
    let accounting_handler = Arc::new(SimpleAccountingHandler::with_config(2, 0));
    let accounting_handler_impl = Arc::clone(&accounting_handler);

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler);

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    let secret = b"testing123";

    // Start a session
    let session_id = "timeout-session-123";
    let start_packet =
        create_accounting_request(AcctStatusType::Start, session_id, "testuser", 1, secret);

    let start_response = send_radius_request(&start_packet, server_addr)
        .await
        .expect("Failed to send Accounting-Start");

    assert_eq!(start_response.code, Code::AccountingResponse);
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Wait for session to timeout (2 seconds + buffer)
    sleep(Duration::from_secs(3)).await;

    // Try to start another session - this should trigger cleanup
    let start_packet2 = create_accounting_request(
        AcctStatusType::Start,
        "new-session-456",
        "testuser",
        2,
        secret,
    );

    send_radius_request(&start_packet2, server_addr)
        .await
        .expect("Failed to send second Accounting-Start");

    // Should have only 1 session (the old one was cleaned up)
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Verify the old session was removed
    let old_session = accounting_handler_impl.get_session(session_id).await;
    assert!(old_session.is_none());

    // Verify the new session exists
    let new_session = accounting_handler_impl.get_session("new-session-456").await;
    assert!(new_session.is_some());
}

/// Test concurrent session limits
#[tokio::test]
async fn test_accounting_concurrent_session_limit() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    // Create accounting handler with limit of 2 sessions per user
    let accounting_handler = Arc::new(SimpleAccountingHandler::with_config(0, 2));
    let accounting_handler_impl = Arc::clone(&accounting_handler);

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler);

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    let secret = b"testing123";

    // Start first session - should succeed
    let start1 =
        create_accounting_request(AcctStatusType::Start, "session-1", "testuser", 1, secret);
    let response1 = send_radius_request(&start1, server_addr)
        .await
        .expect("Failed to send first start");
    assert_eq!(response1.code, Code::AccountingResponse);
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Start second session - should succeed
    let start2 =
        create_accounting_request(AcctStatusType::Start, "session-2", "testuser", 2, secret);
    let response2 = send_radius_request(&start2, server_addr)
        .await
        .expect("Failed to send second start");
    assert_eq!(response2.code, Code::AccountingResponse);
    assert_eq!(accounting_handler_impl.session_count(), 2);

    // Try to start third session - should fail (limit exceeded)
    let start3 =
        create_accounting_request(AcctStatusType::Start, "session-3", "testuser", 3, secret);

    // Server currently doesn't respond when session limit exceeded (returns error)
    // This causes a timeout - in future, should send Accounting-Response per RFC 2866
    let result3 = tokio::time::timeout(
        Duration::from_secs(1),
        send_radius_request(&start3, server_addr),
    )
    .await;

    // Should timeout or error (session limit exceeded)
    assert!(result3.is_err() || matches!(result3, Ok(Err(_))));

    // Session count should stay at 2 (limit not exceeded)
    assert_eq!(accounting_handler_impl.session_count(), 2);

    // Verify only the first two sessions exist
    assert!(
        accounting_handler_impl
            .get_session("session-1")
            .await
            .is_some()
    );
    assert!(
        accounting_handler_impl
            .get_session("session-2")
            .await
            .is_some()
    );
    assert!(
        accounting_handler_impl
            .get_session("session-3")
            .await
            .is_none()
    );

    // Stop one session
    let stop1 = create_accounting_request(AcctStatusType::Stop, "session-1", "testuser", 4, secret);
    send_radius_request(&stop1, server_addr)
        .await
        .expect("Failed to send stop");
    assert_eq!(accounting_handler_impl.session_count(), 1);

    // Now we should be able to start a new session
    let start4 =
        create_accounting_request(AcctStatusType::Start, "session-4", "testuser", 5, secret);
    let response4 = send_radius_request(&start4, server_addr)
        .await
        .expect("Failed to send fourth start");
    assert_eq!(response4.code, Code::AccountingResponse);
    assert_eq!(accounting_handler_impl.session_count(), 2);
}

/// Test session query by user
#[tokio::test]
async fn test_accounting_query_by_user() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("user1", "pass1");
    auth_handler.add_user("user2", "pass2");

    let accounting_handler = Arc::new(SimpleAccountingHandler::new());
    let accounting_handler_impl = Arc::clone(&accounting_handler);

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler);

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    let secret = b"testing123";

    // Start 2 sessions for user1
    send_radius_request(
        &create_accounting_request(AcctStatusType::Start, "user1-session-1", "user1", 1, secret),
        server_addr,
    )
    .await
    .unwrap();

    send_radius_request(
        &create_accounting_request(AcctStatusType::Start, "user1-session-2", "user1", 2, secret),
        server_addr,
    )
    .await
    .unwrap();

    // Start 1 session for user2
    send_radius_request(
        &create_accounting_request(AcctStatusType::Start, "user2-session-1", "user2", 3, secret),
        server_addr,
    )
    .await
    .unwrap();

    // Query sessions by user
    let user1_sessions = accounting_handler_impl.get_sessions_by_user("user1").await;
    assert_eq!(user1_sessions.len(), 2);
    assert!(user1_sessions.iter().all(|s| s.username == "user1"));

    let user2_sessions = accounting_handler_impl.get_sessions_by_user("user2").await;
    assert_eq!(user2_sessions.len(), 1);
    assert_eq!(user2_sessions[0].username, "user2");

    let user3_sessions = accounting_handler_impl.get_sessions_by_user("user3").await;
    assert_eq!(user3_sessions.len(), 0);
}

#[tokio::test]
async fn test_file_accounting_handler() {
    use radius_server::accounting::file::FileAccountingHandler;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let accounting_file = temp_dir.path().join("accounting.jsonl");

    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("fileuser", "testpass");

    // Create file-based accounting handler
    let accounting_handler = Arc::new(
        FileAccountingHandler::new(accounting_file.clone())
            .await
            .expect("Failed to create FileAccountingHandler"),
    );

    // Create server config with accounting enabled
    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config")
        .with_accounting_handler(accounting_handler);

    // Start server
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";

    // Send accounting start with framed IP
    let mut start_packet = create_accounting_request(
        AcctStatusType::Start,
        "file-session-123",
        "fileuser",
        1,
        secret,
    );
    start_packet.add_attribute(
        Attribute::new(AttributeType::FramedIpAddress as u8, vec![192, 168, 10, 50]).unwrap(),
    );
    // Recalculate authenticator after adding framed IP
    start_packet.authenticator = calculate_accounting_request_authenticator(&start_packet, secret);

    send_radius_request(&start_packet, server_addr)
        .await
        .expect("Failed to send accounting start");

    // Wait a bit and send interim update with usage data
    sleep(Duration::from_millis(50)).await;

    let mut interim_packet = create_accounting_request(
        AcctStatusType::InterimUpdate,
        "file-session-123",
        "fileuser",
        2,
        secret,
    );
    interim_packet.add_attribute(
        Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 30]).unwrap(),
    );
    interim_packet.add_attribute(
        Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 5, 0]).unwrap(),
    );
    interim_packet.add_attribute(
        Attribute::new(AttributeType::AcctOutputOctets as u8, vec![0, 0, 10, 0]).unwrap(),
    );
    // Recalculate authenticator after adding attributes
    interim_packet.authenticator =
        calculate_accounting_request_authenticator(&interim_packet, secret);

    send_radius_request(&interim_packet, server_addr)
        .await
        .expect("Failed to send interim update");

    // Wait a bit and send stop packet with final usage data
    sleep(Duration::from_millis(50)).await;

    let mut stop_packet = create_accounting_request(
        AcctStatusType::Stop,
        "file-session-123",
        "fileuser",
        3,
        secret,
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 60]).unwrap(),
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 15, 0]).unwrap(),
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctOutputOctets as u8, vec![0, 0, 30, 0]).unwrap(),
    );
    stop_packet.add_attribute(
        Attribute::new(AttributeType::AcctTerminateCause as u8, vec![0, 0, 0, 1]).unwrap(),
    );
    // Recalculate authenticator after adding attributes
    stop_packet.authenticator = calculate_accounting_request_authenticator(&stop_packet, secret);

    send_radius_request(&stop_packet, server_addr)
        .await
        .expect("Failed to send accounting stop");

    // Wait for writes to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Read and verify the accounting file
    let content = tokio::fs::read_to_string(&accounting_file)
        .await
        .expect("Failed to read accounting file");

    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "Expected 3 accounting records");

    // Parse and verify each line is valid JSON
    for line in &lines {
        let json: serde_json::Value =
            serde_json::from_str(line).expect("Failed to parse JSON line");
        assert!(json.get("timestamp").is_some());
        assert!(json.get("event").is_some());
        assert!(json.get("nas_ip").is_some());
    }

    // Verify start event
    let start_json: serde_json::Value =
        serde_json::from_str(lines[0]).expect("Failed to parse start event");
    assert_eq!(start_json["event"], "start");
    assert_eq!(start_json["session_id"], "file-session-123");
    assert_eq!(start_json["username"], "fileuser");
    assert_eq!(start_json["framed_ip"], "192.168.10.50");

    // Verify interim update event
    let interim_json: serde_json::Value =
        serde_json::from_str(lines[1]).expect("Failed to parse interim event");
    assert_eq!(interim_json["event"], "interimupdate");
    assert_eq!(interim_json["session_id"], "file-session-123");
    assert_eq!(interim_json["session_time"], 30);
    assert_eq!(interim_json["input_octets"], 1280);
    assert_eq!(interim_json["output_octets"], 2560);

    // Verify stop event
    let stop_json: serde_json::Value =
        serde_json::from_str(lines[2]).expect("Failed to parse stop event");
    assert_eq!(stop_json["event"], "stop");
    assert_eq!(stop_json["session_id"], "file-session-123");
    assert_eq!(stop_json["session_time"], 60);
    assert_eq!(stop_json["input_octets"], 3840);
    assert_eq!(stop_json["output_octets"], 7680);
    assert_eq!(stop_json["terminate_cause"], 1);
}

// ---------------------------------------------------------------------------
// Proxy-State echo (RFC 2865 §5.33)
//
// "If a Proxy-State attribute was added to the Access-Request, it MUST be
// copied unmodified to the response packet." The sender's relative ordering
// of multiple Proxy-State attributes must be preserved (RFC 2865 §5.33 and
// §3 invariant on response composition).
// ---------------------------------------------------------------------------

/// Collect every Proxy-State attribute value from `packet` in the order they
/// appear on the wire. We deliberately avoid `Packet::find_attribute`
/// (returns only the first) — order is the property under test.
fn extract_proxy_states(packet: &Packet) -> Vec<Vec<u8>> {
    packet
        .attributes
        .iter()
        .filter(|a| a.attr_type == AttributeType::ProxyState as u8)
        .map(|a| a.value.clone())
        .collect()
}

/// Append three Proxy-State attributes [A, B, C] to `packet`. Returns the
/// expected ordered list of values for assertion.
fn add_three_proxy_states(packet: &mut Packet) -> Vec<Vec<u8>> {
    let values: Vec<Vec<u8>> = vec![
        b"proxy-A".to_vec(),
        b"proxy-B".to_vec(),
        b"proxy-C".to_vec(),
    ];
    for v in &values {
        packet.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, v.clone())
                .expect("Proxy-State attribute"),
        );
    }
    values
}

#[tokio::test]
async fn test_proxy_state_echoed_on_access_accept() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("psuser", "pspass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("server config");
    let server = RadiusServer::new(server_config).await.expect("server");
    let server_addr = server.local_addr().expect("server addr");

    tokio::spawn(async move {
        server.run().await.ok();
    });
    sleep(Duration::from_millis(500)).await;

    let mut packet = create_access_request("psuser", "pspass", b"testing123", 1);
    let expected = add_three_proxy_states(&mut packet);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("send");

    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(extract_proxy_states(&response), expected);
}

#[tokio::test]
async fn test_proxy_state_echoed_on_access_reject() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("psuser", "rightpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("server config");
    let server = RadiusServer::new(server_config).await.expect("server");
    let server_addr = server.local_addr().expect("server addr");

    tokio::spawn(async move {
        server.run().await.ok();
    });
    sleep(Duration::from_millis(500)).await;

    // Wrong password forces Access-Reject.
    let mut packet = create_access_request("psuser", "wrongpass", b"testing123", 2);
    let expected = add_three_proxy_states(&mut packet);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("send");

    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(extract_proxy_states(&response), expected);
}

#[tokio::test]
async fn test_proxy_state_echoed_on_access_challenge() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = ChallengeAuthHandler::new();
    handler.add_user("challengeuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("server config");
    let server = RadiusServer::new(server_config).await.expect("server");
    let server_addr = server.local_addr().expect("server addr");

    tokio::spawn(async move {
        server.run().await.ok();
    });
    sleep(Duration::from_millis(500)).await;

    let mut packet = create_access_request("challengeuser", "password", b"testing123", 3);
    let expected = add_three_proxy_states(&mut packet);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("send");

    assert_eq!(response.code, Code::AccessChallenge);
    assert_eq!(extract_proxy_states(&response), expected);
}

#[tokio::test]
async fn test_proxy_state_echoed_on_accounting_response() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;

    let auth_handler = SimpleAuthHandler::new();
    let acct_impl = Arc::new(SimpleAccountingHandler::new());
    let acct_handler = acct_impl.clone() as Arc<dyn AccountingHandler>;

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("server config")
        .with_accounting_handler(acct_handler);
    let server = RadiusServer::new(server_config).await.expect("server");
    let server_addr = server.local_addr().expect("server addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";
    let mut packet =
        create_accounting_request(AcctStatusType::Start, "session-proxy-1", "psuser", 4, secret);
    let expected = add_three_proxy_states(&mut packet);
    // Recompute Accounting Request authenticator after adding Proxy-State.
    packet.authenticator = calculate_accounting_request_authenticator(&packet, secret);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("send");

    assert_eq!(response.code, Code::AccountingResponse);
    assert_eq!(extract_proxy_states(&response), expected);
}

/// Server-added Proxy-State (e.g. by a downstream proxy on the request leg)
/// must come *after* the client's existing Proxy-State, and the response
/// must still preserve the original client order in the echo. This pins the
/// invariant that `add_attribute` appends — not prepends — and that the
/// echo loop iterates `request.attributes` in receive order.
#[tokio::test]
async fn test_proxy_state_order_preserved_with_many_values() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("psuser", "pspass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("server config");
    let server = RadiusServer::new(server_config).await.expect("server");
    let server_addr = server.local_addr().expect("server addr");

    tokio::spawn(async move {
        server.run().await.ok();
    });
    sleep(Duration::from_millis(500)).await;

    // Use distinguishable byte payloads so a swap or reordering would be
    // caught by the equality assertion (not just a length match).
    let values: Vec<Vec<u8>> = (0u8..7)
        .map(|i| vec![0xC0, 0xFF, 0xEE, i, i.wrapping_mul(3)])
        .collect();

    let mut packet = create_access_request("psuser", "pspass", b"testing123", 5);
    for v in &values {
        packet.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, v.clone())
                .expect("Proxy-State attribute"),
        );
    }

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("send");

    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(extract_proxy_states(&response), values);
}
