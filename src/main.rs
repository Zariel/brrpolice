mod config;
mod control;
mod http;
mod persistence;
mod policy;
mod qbittorrent;
mod runtime;
mod types;

use std::sync::Arc;

use anyhow::Result;
use tokio::{signal, sync::watch};
use tracing::{error, info};

use crate::{
    config::AppConfig, control::ControlLoop, http::HttpServer, persistence::Persistence,
    policy::PolicyEngine, qbittorrent::QbittorrentClient, runtime::ServiceState,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(AppConfig::load(None)?);
    config.init_tracing()?;

    info!("configuration loaded");

    let persistence = Arc::new(Persistence::connect(&config.database).await?);
    persistence.run_migrations().await?;

    let state = Arc::new(ServiceState::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let qbittorrent = Arc::new(QbittorrentClient::new(
        config.qbittorrent.clone(),
        config.filters.clone(),
        config.policy.min_total_seeders,
        config.qbittorrent.request_timeout,
    )?);
    qbittorrent.authenticate().await?;

    let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
    let http_server = HttpServer::new(
        config.clone(),
        persistence.clone(),
        state.clone(),
        shutdown_rx.clone(),
    );
    let control_loop = ControlLoop::new(config, persistence, qbittorrent, policy, shutdown_rx);

    state.mark_ready();
    info!("startup complete");

    let mut http_handle = tokio::spawn(async move { http_server.run().await });
    let mut control_handle = tokio::spawn(async move { control_loop.run().await });

    tokio::select! {
        result = &mut http_handle => {
            state.begin_shutdown();
            let _ = shutdown_tx.send(true);
            result??;
        }
        result = &mut control_handle => {
            state.begin_shutdown();
            let _ = shutdown_tx.send(true);
            result??;
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
            state.begin_shutdown();
            let _ = shutdown_tx.send(true);
            if let Err(error) = http_handle.await? {
                error!(?error, "http server shutdown failed");
                return Err(error);
            }
            if let Err(error) = control_handle.await? {
                error!(?error, "control loop shutdown failed");
                return Err(error);
            }
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
