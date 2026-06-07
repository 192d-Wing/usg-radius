//! End-to-End Backend Authentication Tests
//!
//! These tests verify complete authentication flows with different backend handlers:
//! - Simple in-memory authentication
//!
//! Tests cover:
//! - PAP authentication (User-Password)
//! - CHAP authentication (CHAP-Password)
//! - Attribute retrieval and injection
//! - End-to-end RADIUS packet flow
//!
//! Note: PostgreSQL and LDAP end-to-end tests are in their respective integration test files
//! (postgres_integration_tests.rs and ldap_integration_tests.rs) as they require Docker.

use radius_proto::auth::{encrypt_user_password, generate_request_authenticator};
use radius_proto::chap::{ChapChallenge, ChapResponse, compute_chap_response};
use radius_proto::{Attribute, AttributeType, Code, Packet};
use radius_server::{AuthHandler, Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;

/// Helper to create PAP Access-Request
fn create_pap_request(username: &str, password: &str, secret: &[u8], id: u8) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, id, req_auth);

    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name"),
    );

    let encrypted_pwd = encrypt_user_password(password, secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password"),
    );

    packet.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address"),
    );

    packet
}

/// Helper to create CHAP Access-Request
fn create_chap_request(username: &str, password: &str, id: u8, chap_id: u8) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, id, req_auth);

    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name"),
    );

    let challenge = ChapChallenge::from_authenticator(&req_auth);
    let response_hash = compute_chap_response(chap_id, password, challenge.as_bytes());
    let chap_response = ChapResponse {
        ident: chap_id,
        response: response_hash,
    };

    packet.add_attribute(
        Attribute::new(AttributeType::ChapPassword as u8, chap_response.to_bytes())
            .expect("Failed to create CHAP-Password"),
    );

    packet.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address"),
    );

    packet
}

/// Helper to send packet to server and get response
async fn send_and_receive(
    packet: Packet,
    server_addr: SocketAddr,
) -> Result<Packet, Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket;

    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let packet_bytes = packet.encode()?;

    client_socket.send_to(&packet_bytes, server_addr).await?;

    let mut response_buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(
        Duration::from_secs(5),
        client_socket.recv_from(&mut response_buf),
    )
    .await??;

    let (len, _) = timeout;
    let response = Packet::decode(&response_buf[..len])?;

    Ok(response)
}

#[tokio::test]
async fn test_e2e_simple_auth_pap_success() {
    // Create simple auth handler with test user
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    // Create minimal config
    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0, // Random port
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    // Start server
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Spawn server task
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create and send PAP request
    let secret = b"testing123";
    let request = create_pap_request("testuser", "testpass", secret, 1);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Accept
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_e2e_simple_auth_pap_failure() {
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Wrong password
    let secret = b"testing123";
    let request = create_pap_request("testuser", "wrongpass", secret, 1);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Reject
    assert_eq!(response.code, Code::AccessReject);
}

#[tokio::test]
async fn test_e2e_simple_auth_chap_success() {
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create and send CHAP request
    let _secret = b"testing123";
    let request = create_chap_request("testuser", "testpass", 1, 42);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Accept
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_e2e_simple_auth_chap_failure() {
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("testuser", "testpass");

    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Wrong password
    let _secret = b"testing123";
    let request = create_chap_request("testuser", "wrongpass", 1, 42);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Reject
    assert_eq!(response.code, Code::AccessReject);
}

#[tokio::test]
async fn test_e2e_simple_auth_unknown_user() {
    let auth_handler = SimpleAuthHandler::new();
    // No users added

    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";
    let request = create_pap_request("nonexistent", "anypass", secret, 1);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Reject
    assert_eq!(response.code, Code::AccessReject);
}

#[tokio::test]
async fn test_e2e_simple_auth_accept_attributes() {
    // Create handler with custom accept attributes
    struct TestAuthHandler {
        simple: SimpleAuthHandler,
    }

    impl AuthHandler for TestAuthHandler {
        fn authenticate(&self, username: &str, password: &str) -> bool {
            self.simple.authenticate(username, password)
        }

        fn get_accept_attributes(&self, _username: &str) -> Vec<Attribute> {
            vec![
                Attribute::integer(AttributeType::ServiceType as u8, 2)
                    .expect("Failed to create Service-Type"),
                Attribute::integer(AttributeType::SessionTimeout as u8, 3600)
                    .expect("Failed to create Session-Timeout"),
            ]
        }
    }

    let mut simple = SimpleAuthHandler::new();
    simple.add_user("testuser", "testpass");
    let auth_handler = TestAuthHandler { simple };

    let config = Config {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        secret: "testing123".to_string(),
        clients: vec![],
        ..Default::default()
    };

    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))
        .expect("Failed to create server config");

    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let secret = b"testing123";
    let request = create_pap_request("testuser", "testpass", secret, 1);
    let response = send_and_receive(request, server_addr)
        .await
        .expect("Failed to get response");

    // Verify Access-Accept with attributes
    assert_eq!(response.code, Code::AccessAccept);

    // Check for Service-Type attribute (type 6)
    let service_type = response
        .attributes
        .iter()
        .find(|attr| attr.attr_type == AttributeType::ServiceType as u8);
    assert!(
        service_type.is_some(),
        "Service-Type attribute should be present"
    );

    // Check for Session-Timeout attribute (type 27)
    let session_timeout = response
        .attributes
        .iter()
        .find(|attr| attr.attr_type == AttributeType::SessionTimeout as u8);
    assert!(
        session_timeout.is_some(),
        "Session-Timeout attribute should be present"
    );
}

// PostgreSQL and LDAP tests would go here but require Docker
// They are tested separately in postgres_integration_tests.rs and ldap_integration_tests.rs

#[test]
fn test_e2e_test_infrastructure() {
    // Verify the test infrastructure compiles
    // This is a compile-time check
}
