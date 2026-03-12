use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use brrpolice::{
    config::{AppConfig, QbittorrentConfig},
    control::ControlLoop,
    http::HttpServer,
    metrics::AppMetrics,
    persistence::Persistence,
    policy::PolicyEngine,
    qbittorrent::QbittorrentClient,
    runtime::ServiceState,
};
use secrecy::SecretString;
use tokio::{signal, sync::watch};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli_args()?;
    if let Some(host) = cli.http_host {
        // Safe because this happens before any threads are spawned.
        unsafe {
            std::env::set_var("BRRPOLICE_HTTP__HOST", host);
        }
    }
    if let Some(port) = cli.http_port {
        // Safe because this happens before any threads are spawned.
        unsafe {
            std::env::set_var("BRRPOLICE_HTTP__PORT", port.to_string());
        }
    }

    let config = Arc::new(AppConfig::load(cli.config)?);
    config.init_tracing()?;

    info!(resolved_config = %config.fingerprint(), "resolved configuration loaded");
    warn_nondefault_resiliency_config(&config);

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
        SecretString::from(
            std::env::var(&config.qbittorrent.password_env).with_context(|| {
                format!(
                    "missing qbittorrent password env `{}`",
                    config.qbittorrent.password_env
                )
            })?,
        )
    };

    let qbittorrent = Arc::new(QbittorrentClient::new(
        config.qbittorrent.clone(),
        qb_password,
        config.filters.clone(),
        config.policy.min_total_seeders,
        metrics.clone(),
    )?);

    let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
    let http_server = HttpServer::new(
        config.clone(),
        persistence.clone(),
        qbittorrent.clone(),
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

fn warn_nondefault_resiliency_config(config: &AppConfig) {
    let defaults = QbittorrentConfig::default();
    if config.qbittorrent.transient_retries != defaults.transient_retries {
        warn!(
            configured = config.qbittorrent.transient_retries,
            default = defaults.transient_retries,
            setting = "qbittorrent.transient_retries",
            "resiliency setting differs from default"
        );
    }
    if config.qbittorrent.pool_idle_timeout != defaults.pool_idle_timeout {
        warn!(
            configured_seconds = config.qbittorrent.pool_idle_timeout.as_secs(),
            default_seconds = defaults.pool_idle_timeout.as_secs(),
            setting = "qbittorrent.pool_idle_timeout",
            "resiliency setting differs from default"
        );
    }
    if config.qbittorrent.poll_interval != defaults.poll_interval {
        warn!(
            configured_seconds = config.qbittorrent.poll_interval.as_secs(),
            default_seconds = defaults.poll_interval.as_secs(),
            setting = "qbittorrent.poll_interval",
            "resiliency setting differs from default"
        );
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CliArgs {
    config: Option<PathBuf>,
    http_host: Option<String>,
    http_port: Option<u16>,
}

fn parse_cli_args() -> Result<CliArgs> {
    parse_cli_args_from(std::env::args().skip(1))
}

fn parse_cli_args_from<I>(args: I) -> Result<CliArgs>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = CliArgs::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--config" => {
                let Some(value) = iter.next() else {
                    anyhow::bail!("missing value for --config");
                };
                parsed.config = Some(PathBuf::from(value));
            }
            "--http-host" => {
                let Some(value) = iter.next() else {
                    anyhow::bail!("missing value for --http-host");
                };
                parsed.http_host = Some(value);
            }
            "--http-port" => {
                let Some(value) = iter.next() else {
                    anyhow::bail!("missing value for --http-port");
                };
                parsed.http_port = Some(value.parse().context("invalid --http-port value")?);
            }
            other => {
                anyhow::bail!(
                    "unexpected argument `{other}`; use --config, --http-host, --http-port, or run score simulation via `cargo run -p score-simulator -- ...`"
                );
            }
        }
    }
    Ok(parsed)
}

fn print_usage() {
    println!(concat!(
        "brrpolice usage:\n",
        "  brrpolice [--config <path>] [--http-host <host>] [--http-port <port>]\n",
        "\n",
        "examples:\n",
        "  brrpolice --config /etc/brrpolice/config.toml\n",
        "  brrpolice --http-host 0.0.0.0 --http-port 9090\n",
        "  cargo run -p score-simulator -- --help\n",
    ));
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

    use tokio::sync::watch;

    use crate::run_until_shutdown;
    use crate::{CliArgs, parse_cli_args_from};
    use brrpolice::runtime::ServiceState;

    #[tokio::test]
    async fn waits_for_sibling_task_when_one_task_exits_first() {
        let state = Arc::new(ServiceState::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sibling_finished = Arc::new(AtomicBool::new(false));
        let sibling_flag = sibling_finished.clone();
        let control_handle = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let _ = shutdown_rx.changed().await;
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

    #[test]
    fn parses_cli_config_and_http_overrides() {
        let parsed = parse_cli_args_from([
            "--config".to_string(),
            "/tmp/config.toml".to_string(),
            "--http-host".to_string(),
            "127.0.0.1".to_string(),
            "--http-port".to_string(),
            "10090".to_string(),
        ])
        .unwrap();

        assert_eq!(
            parsed,
            CliArgs {
                config: Some("/tmp/config.toml".into()),
                http_host: Some("127.0.0.1".to_string()),
                http_port: Some(10090),
            }
        );
    }

    #[test]
    fn rejects_unknown_cli_flags() {
        let error = parse_cli_args_from(["--wat".to_string()]).unwrap_err();
        assert!(error.to_string().contains("unexpected argument"));
    }
}
