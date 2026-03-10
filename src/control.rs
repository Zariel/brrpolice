use std::sync::Arc;

use anyhow::Result;
use tokio::time;
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
}

impl ControlLoop {
    pub fn new(
        config: Arc<AppConfig>,
        persistence: Arc<Persistence>,
        qbittorrent: Arc<QbittorrentClient>,
        policy: Arc<PolicyEngine>,
    ) -> Self {
        Self {
            config,
            persistence,
            qbittorrent,
            policy,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut interval = time::interval(self.config.qbittorrent.poll_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        info!("control loop started");

        loop {
            interval.tick().await;
            let torrents = self.qbittorrent.list_in_scope_torrents().await?;
            let decisions = self.policy.evaluate();
            let _ = &self.persistence;
            debug!(
                torrent_count = torrents.len(),
                decision_count = decisions.len(),
                "control loop tick completed"
            );
        }
    }
}
