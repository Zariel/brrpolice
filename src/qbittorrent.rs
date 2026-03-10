use std::{env, time::Duration};

use anyhow::{Context, Result};
use reqwest::{Client, Url};
use tracing::debug;

use crate::{config::QbittorrentConfig, types::TorrentSummary};

#[derive(Clone)]
pub struct QbittorrentClient {
    config: QbittorrentConfig,
    client: Client,
    base_url: Url,
}

impl QbittorrentClient {
    pub fn new(config: QbittorrentConfig, timeout: Duration) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).context("invalid qbittorrent.base_url")?;
        let client = Client::builder().timeout(timeout).build()?;

        Ok(Self {
            config,
            client,
            base_url,
        })
    }

    pub async fn authenticate(&self) -> Result<()> {
        let _password = env::var(&self.config.password_env).with_context(|| {
            format!(
                "missing qbittorrent password env `{}`",
                self.config.password_env
            )
        })?;
        debug!(base_url = %self.base_url, "qbittorrent authentication placeholder");
        let _ = &self.client;
        Ok(())
    }

    pub async fn list_in_scope_torrents(&self) -> Result<Vec<TorrentSummary>> {
        Ok(Vec::new())
    }
}
