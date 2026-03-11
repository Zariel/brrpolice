mod config;
mod control;
mod http;
mod metrics;
mod persistence;
mod policy;
mod qbittorrent;
mod runtime;
mod types;

use std::sync::Arc;

use anyhow::{Context, Result};
use secrecy::SecretString;
use tokio::{signal, sync::watch};
use tracing::{error, info};

use crate::{
    config::AppConfig, control::ControlLoop, http::HttpServer, metrics::AppMetrics,
    persistence::Persistence, policy::PolicyEngine, qbittorrent::QbittorrentClient,
    runtime::ServiceState,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(AppConfig::load(None)?);
    config.init_tracing()?;

    info!(resolved_config = %config.fingerprint(), "resolved configuration loaded");

    let persistence = Arc::new(Persistence::connect(&config.database).await?);
    persistence.run_migrations().await?;
    persistence
        .update_service_meta(env!("CARGO_PKG_VERSION"), &config.fingerprint())
        .await?;
    let state = Arc::new(ServiceState::new());
    let metrics = Arc::new(AppMetrics::new());
    state.mark_database_ready();
    metrics.set_sqlite_size_bytes(persistence.sqlite_size_bytes().await?);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let qb_password = if config.qbittorrent.username.trim().is_empty() {
        SecretString::from(String::new())
    } else {
        SecretString::from(std::env::var(&config.qbittorrent.password_env).with_context(
            || {
                format!(
                    "missing qbittorrent password env `{}`",
                    config.qbittorrent.password_env
                )
            },
        )?)
    };

    let qbittorrent = Arc::new(QbittorrentClient::new(
        config.qbittorrent.clone(),
        qb_password,
        config.filters.clone(),
        config.policy.min_total_seeders,
        config.qbittorrent.request_timeout,
        metrics.clone(),
    )?);

    let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
    let http_server = HttpServer::new(
        config.clone(),
        persistence.clone(),
        state.clone(),
        metrics.clone(),
        shutdown_rx.clone(),
    );
    let control_loop = ControlLoop::new(
        config,
        persistence,
        qbittorrent,
        policy,
        state.clone(),
        metrics,
        shutdown_rx,
    );

    let http_handle = tokio::spawn(async move { http_server.run().await });
    let control_handle = tokio::spawn(async move { control_loop.run().await });

    info!("startup complete; readiness will follow control-loop initialization");

    run_until_shutdown(
        state,
        shutdown_tx,
        http_handle,
        control_handle,
        shutdown_signal(),
    )
    .await
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

async fn run_until_shutdown<F>(
    state: Arc<ServiceState>,
    shutdown_tx: watch::Sender<bool>,
    mut http_handle: tokio::task::JoinHandle<Result<()>>,
    mut control_handle: tokio::task::JoinHandle<Result<()>>,
    shutdown_signal: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        result = &mut http_handle => {
            state.begin_shutdown();
            let _ = shutdown_tx.send(true);
            let primary = result?;
            let mut primary_error = None;
            if let Err(error) = primary {
                primary_error = Some(error);
            }
            if let Err(error) = control_handle.await? {
                error!(?error, "control loop shutdown failed");
                if primary_error.is_none() {
                    return Err(error);
                }
            }
            if let Some(error) = primary_error {
                return Err(error);
            }
        }
        result = &mut control_handle => {
            state.begin_shutdown();
            let _ = shutdown_tx.send(true);
            let primary = result?;
            let mut primary_error = None;
            if let Err(error) = primary {
                primary_error = Some(error);
            }
            if let Err(error) = http_handle.await? {
                error!(?error, "http server shutdown failed");
                if primary_error.is_none() {
                    return Err(error);
                }
            }
            if let Some(error) = primary_error {
                return Err(error);
            }
        }
        _ = shutdown_signal => {
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::{sync::watch, time::Duration};

    use crate::{run_until_shutdown, runtime::ServiceState};

    #[tokio::test]
    async fn waits_for_sibling_task_when_one_task_exits_first() {
        let state = Arc::new(ServiceState::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sibling_finished = Arc::new(AtomicBool::new(false));
        let sibling_flag = sibling_finished.clone();
        let control_handle = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let _ = shutdown_rx.changed().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            sibling_flag.store(true, Ordering::Relaxed);
            Ok::<(), anyhow::Error>(())
        });
        let http_handle = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

        let result = run_until_shutdown(
            state,
            shutdown_tx,
            http_handle,
            control_handle,
            std::future::pending(),
        )
        .await;

        assert!(result.is_ok());
        assert!(sibling_finished.load(Ordering::Relaxed));
    }
}
