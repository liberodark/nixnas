use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod auth;
mod commands;
mod error;
mod nix;
mod services;
mod state;
mod web;

use api::{AppState, build_router};
use services::metrics::MetricsStore;
use services::monitoring::MonitoringService;
use services::smart_cache::SmartCache;
use web::{WebState, build_web_router};

/// NixOS NAS management daemon with web interface.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Listen address (ip:port)
    #[arg(
        short,
        long,
        env = "NIXNAS_LISTEN_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    listen: String,

    /// Path to state file
    #[arg(
        short,
        long,
        env = "NIXNAS_STATE_PATH",
        default_value = "/var/lib/nixnas/state.json"
    )]
    state_path: String,

    /// Directory for generated Nix configuration files
    #[arg(
        short,
        long,
        env = "NIXNAS_NIX_OUTPUT_DIR",
        default_value = "/etc/nixos"
    )]
    output_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nixnas_daemon=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting NixNAS daemon v{}...", env!("CARGO_PKG_VERSION"));

    if let Some(parent) = std::path::Path::new(&cli.state_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let app_state = Arc::new(
        AppState::new(&cli.state_path, &cli.output_dir)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize state: {}", e))?,
    );

    let metrics_store = Arc::new(MetricsStore::new());
    Arc::clone(&metrics_store).start_collection();

    let smart_cache = Arc::new(SmartCache::new());

    let web_state = Arc::new(WebState {
        state_manager: app_state.state_manager.clone(),
        auth: app_state.auth.clone(),
        smb: app_state.smb.clone(),
        nfs: app_state.nfs.clone(),
        nix: app_state.nix.clone(),
        metrics: metrics_store,
        smart_cache: smart_cache.clone(),
    });

    if app_state.auth.needs_setup().await {
        tracing::warn!(
            "Initial setup required - default admin password will be set on first login"
        );
    }

    let monitoring = Arc::new(MonitoringService::new(
        app_state.state_manager.clone(),
        smart_cache,
    ));
    monitoring.start();

    let api_router = build_router(app_state);
    let web_router = build_web_router(web_state);

    let app = web_router.merge(api_router);

    let addr: SocketAddr = cli.listen.parse()?;
    tracing::info!("Listening on http://{}", addr);
    tracing::info!("Web UI: http://{}/", addr);
    tracing::info!("API: http://{}/api/rpc", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
