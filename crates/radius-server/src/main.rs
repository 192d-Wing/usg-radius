use clap::Parser;
use radius_server::{Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::process;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Start the health-check and Prometheus metrics HTTP servers.
///
/// Driven entirely by environment variables so it maps cleanly onto a Kubernetes
/// ConfigMap/Secret:
///   * `HEALTH_PORT`  — health endpoints (`/health/live`, `/health/ready`). Default
///     `listen_port + 1000`.
///   * `METRICS_PORT` — Prometheus `/metrics`. Default `listen_port + 2000`.
///
/// Both servers bind dual-stack (`[::]`) so the kubelet can probe the pod over IPv4
/// or IPv6. Only compiled with the `observability` feature (pulls in axum). The
/// server is stateless; the session manager is backed by in-memory storage.
#[cfg(feature = "observability")]
async fn start_observability(listen_port: u16) {
    use radius_server::state::{MemoryStateBackend, SharedSessionManager};
    use std::env;

    let health_port = env::var("HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(listen_port.saturating_add(1000));
    let metrics_port = env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(listen_port.saturating_add(2000));

    let session_manager = Arc::new(SharedSessionManager::new(Arc::new(
        MemoryStateBackend::new(),
    )));

    spawn_http_server(
        "health",
        health_port,
        Arc::clone(&session_manager),
        radius_server::start_health_server,
    );
    spawn_http_server(
        "metrics",
        metrics_port,
        session_manager,
        radius_server::start_metrics_server,
    );
}

/// Spawn one of the auxiliary HTTP servers (health or metrics) on `[::]:port`.
#[cfg(feature = "observability")]
fn spawn_http_server<F, Fut>(
    name: &'static str,
    port: u16,
    session_manager: Arc<radius_server::state::SharedSessionManager>,
    run: F,
) where
    F: FnOnce(Arc<radius_server::state::SharedSessionManager>, std::net::SocketAddr) -> Fut
        + Send
        + 'static,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send,
{
    let bind = format!("[::]:{port}");
    match bind.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            info!("Starting {name} server on {bind}");
            tokio::spawn(async move {
                if let Err(e) = run(session_manager, addr).await {
                    warn!("{name} server error: {e}");
                }
            });
        }
        Err(e) => warn!("Invalid {name} bind address {bind}: {e}"),
    }
}

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

    // Create server configuration with client validation
    let server_config = match ServerConfig::from_config(config.clone(), Arc::new(auth_handler)) {
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

    // Start health-check + metrics HTTP servers and connect the state backend.
    // Kubernetes liveness/readiness probes depend on the health endpoints; with
    // externalTrafficPolicy: Local the readiness state gates whether Cilium
    // advertises the anycast VIP from this node.
    #[cfg(feature = "observability")]
    start_observability(config.listen_port).await;

    info!("");
    info!("Server started successfully!");
    info!("Press Ctrl+C to stop");
    info!("");

    // Run server
    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        process::exit(1);
    }
}
