//! OCSP Certificate Status Checker Example
//!
//! This example demonstrates how to use the OCSP client to check
//! certificate revocation status in real-time.
//!
//! Usage:
//!   cargo run --example ocsp_check --features revocation -- <cert_path> <issuer_path>
//!
//! Example:
//!   cargo run --example ocsp_check --features revocation -- client.pem ca.pem

#[cfg(feature = "revocation")]
use radius_proto::revocation::ocsp::{
    CertificateStatus, OcspClient, OcspRequestBuilder, OcspResponse, OcspResponseStatus,
};

#[cfg(feature = "revocation")]
use radius_proto::revocation::RevocationError;

#[cfg(feature = "revocation")]
use std::fs;

#[cfg(feature = "revocation")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <cert_path> <issuer_path>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} client.pem ca.pem", args[0]);
        std::process::exit(1);
    }

    let cert_path = &args[1];
    let issuer_path = &args[2];

    println!("OCSP Certificate Status Checker");
    println!("================================\n");

    // Load certificate and issuer
    println!("Loading certificate: {}", cert_path);
    let cert_pem = fs::read_to_string(cert_path)?;
    let cert_der = pem_to_der(&cert_pem)?;

    println!("Loading issuer: {}", issuer_path);
    let issuer_pem = fs::read_to_string(issuer_path)?;
    let issuer_der = pem_to_der(&issuer_pem)?;

    // Extract OCSP URL from certificate
    println!("\nExtracting OCSP URL from certificate...");
    let ocsp_url = OcspClient::extract_ocsp_url(&cert_der)?;
    println!("OCSP Responder URL: {}", ocsp_url);

    // Build OCSP request
    println!("\nBuilding OCSP request...");
    let request_builder = OcspRequestBuilder::new(&cert_der, &issuer_der)?;

    // Add nonce for replay protection (recommended)
    let nonce = generate_nonce();
    let request_builder = request_builder.with_nonce(nonce.clone());

    let request = request_builder.build()?;
    println!("OCSP request size: {} bytes", request.len());
    println!("Nonce included: yes (replay protection enabled)");

    // Create OCSP client with 10 second timeout
    println!("\nCreating OCSP client...");
    let client = OcspClient::new(10)?;

    // Send OCSP request
    println!("Querying OCSP responder: {}", ocsp_url);
    println!("(This may take a few seconds...)");

    let response_bytes = client.query(&ocsp_url, &request, 10 * 1024 * 1024)?; // 10 MB max
    let response = OcspResponse::parse(&response_bytes)?;
    println!("Response Size: {} bytes", response_bytes.len());

    // Display response
    println!("\nOCSP Response");
    println!("=============");
    display_response(&response, &nonce)?;

    // Check certificate status
    match response.cert_status {
        Some(CertificateStatus::Good) => {
            println!("\n✅ Certificate is VALID (not revoked)");
            Ok(())
        }
        Some(CertificateStatus::Revoked {
            revocation_time,
            reason,
        }) => {
            println!("\n❌ Certificate is REVOKED");
            println!("   Revocation time: {:?}", revocation_time);
            if let Some(r) = reason {
                println!("   Reason code: {}", r);
                println!("   Reason: {}", revocation_reason_name(r));
            }
            Err("Certificate has been revoked".into())
        }
        Some(CertificateStatus::Unknown) => {
            println!("\n⚠️  Certificate status is UNKNOWN");
            println!("   The OCSP responder does not know about this certificate.");
            Err("Certificate status unknown".into())
        }
        None => {
            println!("\n⚠️  No certificate status in response");
            Err("Invalid OCSP response".into())
        }
    }
}

#[cfg(feature = "revocation")]
fn display_response(response: &OcspResponse, expected_nonce: &[u8]) -> Result<(), RevocationError> {
    // Response status
    println!("Status: {:?}", response.status);

    if response.status != OcspResponseStatus::Successful {
        println!("\n❌ OCSP response indicates an error:");
        match response.status {
            OcspResponseStatus::MalformedRequest => println!("   The request was malformed"),
            OcspResponseStatus::InternalError => {
                println!("   The responder encountered an internal error")
            }
            OcspResponseStatus::TryLater => println!("   The responder is temporarily unavailable"),
            OcspResponseStatus::SigRequired => println!("   The request must be signed"),
            OcspResponseStatus::Unauthorized => println!("   The request is unauthorized"),
            _ => println!("   Unknown error status"),
        }
        return Ok(());
    }

    // Certificate status
    if let Some(ref cert_status) = response.cert_status {
        print!("Certificate Status: ");
        match cert_status {
            CertificateStatus::Good => println!("Good ✅"),
            CertificateStatus::Revoked { .. } => println!("Revoked ❌"),
            CertificateStatus::Unknown => println!("Unknown ⚠️"),
        }
    }

    // Validity window (thisUpdate / nextUpdate); only the outcome is printed
    if response.next_update.is_some() {
        // Calculate freshness
        let now = std::time::SystemTime::now();
        if now < response.this_update {
            println!("⚠️  Response not yet valid!");
        } else if let Some(next) = response.next_update {
            if now > next {
                println!("⚠️  Response has expired!");
            } else {
                let remaining: std::time::Duration = next.duration_since(now).unwrap_or_default();
                println!("Response fresh for: {} seconds", remaining.as_secs());
            }
        }
    }

    // Nonce verification
    if let Some(ref response_nonce) = response.nonce {
        print!("Nonce: present");
        if response_nonce == expected_nonce {
            println!(" ✅ (verified - replay protection active)");
        } else {
            println!(" ❌ (MISMATCH - possible replay attack!)");
        }
    } else {
        println!("Nonce: not present ⚠️  (no replay protection)");
    }

    Ok(())
}

#[cfg(feature = "revocation")]
fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Simple PEM parser - extract base64 between BEGIN/END markers
    let lines: Vec<&str> = pem.lines().collect();
    let mut base64_lines = Vec::new();
    let mut in_cert = false;

    for line in lines {
        if line.starts_with("-----BEGIN") {
            in_cert = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_cert && !line.is_empty() {
            base64_lines.push(line);
        }
    }

    let base64_str = base64_lines.join("");

    // Decode base64
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD.decode(&base64_str)?;

    Ok(der)
}

#[cfg(feature = "revocation")]
fn generate_nonce() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate a simple nonce from current time
    // In production, use a cryptographically secure random number generator
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let nonce = format!("{:032x}", now);
    nonce.as_bytes().to_vec()
}

#[cfg(feature = "revocation")]
fn revocation_reason_name(code: u8) -> &'static str {
    match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unknown",
    }
}

#[cfg(not(feature = "revocation"))]
fn main() {
    eprintln!("This example requires the 'revocation' feature to be enabled.");
    eprintln!("Run with: cargo run --example ocsp_check --features revocation");
    std::process::exit(1);
}
