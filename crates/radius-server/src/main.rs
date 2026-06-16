use clap::Parser;
use radius_server::server::AuthHandler;
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
/// Load the optional authorization policy from POLICY_FILE into a shared,
/// live-editable cell. A missing file is fine (empty policy); a file that EXISTS
/// but cannot be read/parsed is fatal (silently starting empty would discard the
/// operator's authorization config — fail-open once enforced).
fn load_policy() -> (
    Arc<std::sync::RwLock<radius_server::PolicyConfig>>,
    Option<Arc<str>>,
) {
    let policy_file: Option<Arc<str>> = std::env::var("POLICY_FILE")
        .ok()
        .map(|p| Arc::from(p.as_str()));
    let loaded = match &policy_file {
        // No exists()-precheck (avoids a TOCTOU): a genuinely-absent file is a
        // fresh start; any other read error, or a parse/validation failure on a
        // file that DOES exist, is fatal — silently enforcing an empty or invalid
        // policy would be a fail-open / lockout hazard.
        Some(path) => match std::fs::read_to_string(path.as_ref()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("POLICY_FILE {path} does not exist yet; starting with an empty policy");
                radius_server::PolicyConfig::default()
            }
            Err(e) => {
                error!("POLICY_FILE {path} could not be read: {e}");
                process::exit(1);
            }
            Ok(s) => match serde_json::from_str::<radius_server::PolicyConfig>(&s) {
                // Validate on load with the SAME rules the PUT API enforces, so a
                // structurally-invalid file can't be loaded and then enforced.
                Ok(p) => match p.validate() {
                    Ok(()) => {
                        info!("Loaded authorization policy from {path}");
                        p
                    }
                    Err(e) => {
                        error!("POLICY_FILE {path} is invalid: {e}");
                        process::exit(1);
                    }
                },
                Err(e) => {
                    error!("POLICY_FILE {path} is not valid JSON: {e}");
                    process::exit(1);
                }
            },
        },
        None => radius_server::PolicyConfig::default(),
    };
    (Arc::new(std::sync::RwLock::new(loaded)), policy_file)
}

#[cfg(feature = "observability")]
async fn start_observability(
    config: &Config,
    policy: Arc<std::sync::RwLock<radius_server::PolicyConfig>>,
    policy_file: Option<Arc<str>>,
    accounting: Arc<dyn radius_server::AccountingHandler>,
) {
    use radius_server::state::{MemoryStateBackend, SharedSessionManager};
    use std::env;

    let listen_port = config.listen_port;
    let health_port = env::var("HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(listen_port.saturating_add(1000));
    let metrics_port = env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(listen_port.saturating_add(2000));
    let mgmt_port = env::var("MGMT_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(listen_port.saturating_add(3000));

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
        Arc::clone(&session_manager),
        radius_server::start_metrics_server,
    );

    // Management API + policy editing for the operator UI. The `policy` cell is
    // shared with the request path (enforcement), so PUT edits take effect live
    // without a restart. Authorization (mTLS + IAM-style ABAC) is opt-in via the
    // `mgmt` config block; see load_access_policy.
    let mgmt_cfg = Arc::new(config.clone());
    let security = load_access_policy(config);

    // Hot-reload the IAM access policy on SIGHUP (Unix) so operators can update it
    // — e.g. after a ConfigMap change — without restarting the server.
    #[cfg(unix)]
    if let (Some(cell), Some(path)) = (
        security.access_policy.clone(),
        config
            .mgmt
            .as_ref()
            .and_then(|m| m.access_policy_file.clone()),
    ) {
        spawn_access_policy_reloader(cell, path);
    }

    let bind = format!("[::]:{mgmt_port}");
    match bind.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            info!("Starting management server on {bind}");
            tokio::spawn(async move {
                if let Err(e) = radius_server::start_mgmt_server(
                    mgmt_cfg,
                    session_manager,
                    policy,
                    policy_file,
                    security,
                    Some(accounting),
                    addr,
                )
                .await
                {
                    warn!("management server error: {e}");
                }
            });
        }
        Err(e) => warn!("Invalid management bind address {bind}: {e}"),
    }
}

/// Load the IAM-style access policy referenced by `config.mgmt.access_policy_file`
/// into a [`MgmtSecurity`] bundle. A configured-but-broken policy file is fatal
/// (consistent with [`load_policy`]) — refusing to start beats silently running an
/// unenforced or partially-parsed access policy.
#[cfg(feature = "observability")]
fn load_access_policy(config: &Config) -> radius_server::MgmtSecurity {
    use radius_server::{AccessPolicy, MgmtSecurity};

    let Some(mgmt) = &config.mgmt else {
        return MgmtSecurity::default();
    };
    let access_policy = mgmt.access_policy_file.as_ref().map(|path| {
        let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
            error!("mgmt.access_policy_file {path} could not be read: {e}");
            process::exit(1);
        });
        let parsed: AccessPolicy = serde_json::from_str(&raw).unwrap_or_else(|e| {
            error!("mgmt.access_policy_file {path} is not valid JSON: {e}");
            process::exit(1);
        });
        if let Err(e) = parsed.validate() {
            error!("mgmt.access_policy_file {path} is invalid: {e}");
            process::exit(1);
        }
        info!("Loaded management access policy from {path}");
        // Held in a swappable cell so SIGHUP can reload it without a restart.
        Arc::new(std::sync::RwLock::new(Arc::new(parsed)))
    });

    // Audit denials to the same JSON audit log the request path uses.
    let audit = radius_server::AuditLogger::new(config.audit_log_path.clone())
        .map(Arc::new)
        .ok();

    MgmtSecurity {
        access_policy,
        trust_forwarded_identity: mgmt.trust_forwarded_identity,
        audit,
    }
}

/// Spawn a task that reloads the IAM access policy from `path` into `cell` on every
/// SIGHUP. A failed reload (unreadable/invalid file) keeps the currently-enforced
/// policy and logs the error — a bad edit can never disable authorization.
#[cfg(all(feature = "observability", unix))]
fn spawn_access_policy_reloader(cell: radius_server::SharedAccessPolicy, path: String) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let mut hup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!("could not install SIGHUP handler for access-policy reload: {e}");
                return;
            }
        };
        info!("SIGHUP will reload the management access policy from {path}");
        while hup.recv().await.is_some() {
            match radius_server::reload_access_policy(&cell, &path) {
                Ok(()) => info!("reloaded management access policy from {path} (SIGHUP)"),
                Err(e) => error!("SIGHUP access-policy reload failed (keeping current): {e}"),
            }
        }
    });
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
// `version` is omitted here on purpose: the struct defines its own `-V/--version`
// field below (with custom output), so letting clap auto-generate `--version` too
// would create a duplicate `version` argument (panics clap's debug asserts).
#[command(author, about, long_about = None)]
#[command(name = "usg-radius")]
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
        println!();
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
        println!();
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
        println!();

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
    // Load the authorization policy once and share the cell between the request
    // path (enforcement) and the management API (live editing).
    let (policy, policy_file) = load_policy();

    // Shared in-memory accounting session store. The request path records
    // Start/Interim/Stop into it; the management API reads the same store for its
    // live-session view (`GET /api/v1/sessions`).
    let accounting = Arc::new(radius_server::SimpleAccountingHandler::new());

    // Reap sessions that never received a Stop (and went silent past the timeout)
    // so the live-session view doesn't accumulate stale entries.
    {
        let acct = Arc::clone(&accounting);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                let removed = acct.cleanup_stale_sessions();
                if removed > 0 {
                    info!("reaped {removed} stale accounting session(s)");
                }
            }
        });
    }

    let server_config = match ServerConfig::from_config(config.clone(), handler) {
        Ok(cfg) => cfg
            .with_policy(Arc::clone(&policy))
            .with_accounting_handler(accounting.clone()),
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

    // The RADIUS server is created per-transport below (UDP binds a socket here;
    // RadSec terminates TLS in its own listener). `server_config` is moved into
    // whichever transport is selected.

    // Start health-check + metrics HTTP servers and connect the state backend.
    // Kubernetes liveness/readiness probes depend on the health endpoints; with
    // externalTrafficPolicy: Local the readiness state gates whether Cilium
    // advertises the anycast VIP from this node.
    #[cfg(feature = "observability")]
    start_observability(
        &config,
        Arc::clone(&policy),
        policy_file,
        accounting.clone(),
    )
    .await;
    #[cfg(not(feature = "observability"))]
    let _ = (policy_file, &accounting);

    info!("");
    info!("Server started successfully!");
    info!("Press Ctrl+C to stop");
    info!("");

    // Run server with graceful shutdown on SIGTERM/SIGINT (Kubernetes sends SIGTERM
    // then waits terminationGracePeriodSeconds before SIGKILL).
    let shutdown = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
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

    // Select the transport per the SERVER-CONTRACT (G-1): RadSec is the locked,
    // FIPS-posture transport; plain UDP is a transitional, non-FIPS fallback.
    match config.transport {
        radius_server::config::Transport::UdpInsecure => {
            warn!(
                "transport = \"udp-insecure\": plain UDP RADIUS is NOT FIPS-approved \
                 and is spoofable — use RadSec (transport = \"radsec\") in production"
            );
            let server = match RadiusServer::new(server_config).await {
                Ok(srv) => srv,
                Err(e) => {
                    error!("Failed to create server: {}", e);
                    process::exit(1);
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
        radius_server::config::Transport::Radsec => {
            #[cfg(feature = "tls")]
            {
                let radsec_cfg = match config.radsec.clone() {
                    Some(c) => c,
                    None => {
                        error!(
                            "transport = \"radsec\" but no `radsec` config block was provided \
                             (needs cert_path, key_path, client_ca_path)"
                        );
                        process::exit(1);
                    }
                };
                let server_config = Arc::new(server_config);
                let registry = radius_server::coa::NasRegistry::new();
                tokio::select! {
                    res = radius_server::radsec::run(radsec_cfg, server_config, registry) => {
                        if let Err(e) = res {
                            error!("RadSec listener error: {}", e);
                            process::exit(1);
                        }
                    }
                    _ = shutdown => {
                        info!("Graceful shutdown complete");
                    }
                }
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = server_config;
                error!("transport = \"radsec\" requires building with the `tls` feature");
                process::exit(1);
            }
        }
    }
}
