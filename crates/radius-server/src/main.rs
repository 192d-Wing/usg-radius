use clap::Parser;
use radius_server::server::AuthHandler;
use radius_server::{Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::process;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// USG RADIUS Server - RFC 2865 RADIUS Authentication Server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "usg_radius")]
struct Cli {
    /// Path to configuration file
    #[arg(value_name = "CONFIG", default_value = "config.json")]
    config_path: String,

    /// Validate configuration and exit (doesn't start server)
    #[arg(short, long)]
    validate: bool,

    /// Print version information and exit
    #[arg(short = 'V', long)]
    version: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle --version flag
    if cli.version {
        println!("USG RADIUS Server v{}", env!("CARGO_PKG_VERSION"));
        println!("RFC 2865 RADIUS Authentication Server");
        println!("");
        println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
        println!("License: {}", env!("CARGO_PKG_LICENSE"));
        process::exit(0);
    }

    // Load or create configuration (without logging first)
    let config = match Config::from_file(&cli.config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            // Initialize basic logging to show config creation messages
            tracing_subscriber::registry()
                .with(EnvFilter::new("info"))
                .with(tracing_subscriber::fmt::layer())
                .init();

            // If validation mode, just report error
            if cli.validate {
                eprintln!("❌ Configuration validation failed!");
                eprintln!("   Error: {}", e);
                process::exit(1);
            }

            warn!("Could not load config file from: {}", cli.config_path);
            info!("Creating example configuration at: {}", cli.config_path);

            let example_config = Config::example();
            if let Err(e) = example_config.to_file(&cli.config_path) {
                error!("Error creating example config: {}", e);
                process::exit(1);
            }

            info!("Please edit {} and restart the server", cli.config_path);
            process::exit(0);
        }
    };

    // If validate-only mode, validate and exit
    if cli.validate {
        println!("✓ Configuration validated successfully!");
        println!("");
        println!("Configuration summary:");
        println!("  Listen: {}:{}", config.listen_address, config.listen_port);
        println!("  Clients: {}", config.clients.len());
        println!("  Users: {}", config.users.len());
        println!(
            "  Log level: {}",
            config.log_level.as_deref().unwrap_or("info")
        );
        println!("  Strict RFC compliance: {}", config.strict_rfc_compliance);
        if let Some(ref path) = config.audit_log_path {
            println!("  Audit log: {}", path);
        }
        println!("");

        // Show client list
        if !config.clients.is_empty() {
            println!("Authorized clients:");
            for client in &config.clients {
                let status = if client.enabled { "✓" } else { "✗" };
                let name = client.name.as_deref().unwrap_or("(unnamed)");
                println!("  {} {} - {}", status, client.address, name);
            }
        } else {
            println!("⚠️  WARNING: No authorized clients configured!");
        }

        process::exit(0);
    }

    // Initialize tracing with configured log level
    let log_level = if let Some(ref level) = config.log_level {
        level.as_str()
    } else if config.verbose {
        "debug" // For backward compatibility with verbose flag
    } else {
        "info"
    };

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("USG RADIUS Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Based on RFC 2865 (RADIUS)");
    info!("Loaded configuration from: {}", cli.config_path);
    info!("");

    // Create authentication handler
    let mut auth_handler = SimpleAuthHandler::new();
    for user in &config.users {
        auth_handler.add_user(&user.username, &user.password);
        info!("Added user: {}", user.username);
    }

    // Display client configuration
    if config.clients.is_empty() {
        warn!("");
        warn!("⚠️  WARNING: No authorized clients configured!");
        warn!("   Server will accept requests from ANY IP address.");
        warn!("   Add clients to config.json for production use.");
    } else {
        info!("");
        info!("Authorized clients:");
        for client in &config.clients {
            let status = if client.enabled { "✓" } else { "✗" };
            let name = client.name.as_deref().unwrap_or("(unnamed)");
            info!("  {} {} - {}", status, client.address, name);
        }
    }

    // If EAP is configured, wrap the SimpleAuthHandler in an EapAuthHandler so the
    // server speaks EAP-TLS / EAP-TEAP. Otherwise use the plain PAP handler.
    let handler: Arc<dyn AuthHandler> = match &config.eap {
        None => Arc::new(auth_handler),
        Some(eap_cfg) => {
            #[cfg(not(feature = "tls"))]
            {
                let _ = eap_cfg;
                error!("config.eap is set but the binary was built without the `tls` feature");
                process::exit(1);
            }
            #[cfg(feature = "tls")]
            {
                use radius_proto::eap::eap_tls::TlsCertificateConfig;
                use radius_server::EapAuthHandler;

                let cert_cfg = TlsCertificateConfig::new(
                    eap_cfg.tls.cert_path.clone(),
                    eap_cfg.tls.key_path.clone(),
                    eap_cfg.tls.ca_path.clone(),
                    eap_cfg.tls.require_client_cert,
                );
                let mut eap = EapAuthHandler::new(Arc::new(auth_handler));
                if eap_cfg.enable_teap {
                    if let Err(e) = eap.configure_teap("", cert_cfg.clone()) {
                        error!("Failed to configure EAP-TEAP: {}", e);
                        process::exit(1);
                    }
                    info!("EAP-TEAP enabled (cert: {})", eap_cfg.tls.cert_path);
                }
                if eap_cfg.enable_tls {
                    if let Err(e) = eap.configure_tls("", cert_cfg) {
                        error!("Failed to configure EAP-TLS: {}", e);
                        process::exit(1);
                    }
                    info!("EAP-TLS enabled (cert: {})", eap_cfg.tls.cert_path);
                }
                Arc::new(eap)
            }
        }
    };

    // Create server configuration with client validation
    let server_config = match ServerConfig::from_config(config.clone(), handler) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Invalid configuration: {}", e);
            process::exit(1);
        }
    };

    // Display audit logging status
    if let Some(ref path) = config.audit_log_path {
        info!("");
        info!("Audit logging enabled: {}", path);
    }

    // Create and run server
    let server = match RadiusServer::new(server_config).await {
        Ok(srv) => srv,
        Err(e) => {
            error!("Failed to create server: {}", e);
            process::exit(1);
        }
    };

    info!("");
    info!("Server started successfully!");
    info!("Press Ctrl+C to stop");
    info!("");

    // Spawn a minimal HTTP health server for Kubernetes probes (requires `ha` feature,
    // which is enabled by default). Bound to HEALTH_LISTEN_ADDR (default 0.0.0.0:8080).
    #[cfg(feature = "ha")]
    {
    let health_addr = std::env::var("HEALTH_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    tokio::spawn(async move {
        match health_addr.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                use axum::{routing::get, Router};
                let app = Router::new()
                    .route("/healthz", get(|| async { "ok" }))
                    .route("/readyz", get(|| async { "ok" }))
                    .route("/livez", get(|| async { "ok" }));
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        info!("Health server listening on {}", addr);
                        if let Err(e) = axum::serve(listener, app).await {
                            error!("Health server error: {}", e);
                        }
                    }
                    Err(e) => error!("Failed to bind health server on {}: {}", addr, e),
                }
            }
            Err(e) => error!("Invalid HEALTH_LISTEN_ADDR: {}", e),
        }
    });
    }

    // Run server with graceful shutdown on SIGTERM/SIGINT (Kubernetes sends SIGTERM
    // then waits terminationGracePeriodSeconds before SIGKILL).
    let shutdown = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
            tokio::select! {
                _ = term.recv() => info!("Received SIGTERM, shutting down"),
                _ = int.recv()  => info!("Received SIGINT, shutting down"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received Ctrl-C, shutting down");
        }
    };

    tokio::select! {
        res = server.run() => {
            if let Err(e) = res {
                error!("Server error: {}", e);
                process::exit(1);
            }
        }
        _ = shutdown => {
            info!("Graceful shutdown complete");
        }
    }
}
