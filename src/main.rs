mod config;
mod control;
mod http;
mod persistence;
mod policy;
mod qbittorrent;
mod types;

use std::sync::Arc;

use anyhow::Result;
use tokio::signal;
use tracing::info;

use crate::{
    config::AppConfig, control::ControlLoop, http::HttpServer, persistence::Persistence,
    policy::PolicyEngine, qbittorrent::QbittorrentClient,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(AppConfig::load(None)?);
    config.init_tracing()?;

    info!("configuration loaded");

    let persistence = Arc::new(Persistence::connect(&config.database).await?);
    persistence.run_migrations().await?;

    let qbittorrent = Arc::new(QbittorrentClient::new(
        config.qbittorrent.clone(),
        config.qbittorrent.request_timeout,
    )?);
    qbittorrent.authenticate().await?;

    let policy = Arc::new(PolicyEngine::new(config.policy.clone()));
    let http_server = HttpServer::new(config.clone(), persistence.clone());
    let control_loop = ControlLoop::new(config, persistence, qbittorrent, policy);

    let http_handle = tokio::spawn(async move { http_server.run().await });
    let control_handle = tokio::spawn(async move { control_loop.run().await });

    tokio::select! {
        result = http_handle => {
            result??;
        }
        result = control_handle => {
            result??;
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                let _ = stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
