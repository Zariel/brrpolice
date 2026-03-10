use std::sync::Arc;

use anyhow::Result;
use tokio::{sync::watch, time};
use tracing::{debug, info};

use crate::{
    config::AppConfig, persistence::Persistence, policy::PolicyEngine,
    qbittorrent::QbittorrentClient,
};

pub struct ControlLoop {
    config: Arc<AppConfig>,
    persistence: Arc<Persistence>,
    qbittorrent: Arc<QbittorrentClient>,
    policy: Arc<PolicyEngine>,
    shutdown: watch::Receiver<bool>,
}

impl ControlLoop {
    pub fn new(
        config: Arc<AppConfig>,
        persistence: Arc<Persistence>,
        qbittorrent: Arc<QbittorrentClient>,
        policy: Arc<PolicyEngine>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            persistence,
            qbittorrent,
            policy,
            shutdown,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut interval = time::interval(self.config.qbittorrent.poll_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        info!("control loop started");

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let torrents = self.qbittorrent.list_in_scope_torrents().await?;
                    let decisions = self.policy.evaluate();
                    let _ = &self.persistence;
                    debug!(
                        torrent_count = torrents.len(),
                        decision_count = decisions.len(),
                        "control loop tick completed"
                    );
                }
                _ = self.shutdown.changed() => {
                    info!("control loop stopping");
                    return Ok(());
                }
            }
        }
    }
}
