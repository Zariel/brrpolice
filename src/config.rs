#![allow(dead_code)]

use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use config::{Config, Environment, File, FileFormat};
use humantime::parse_duration;
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub qbittorrent: QbittorrentConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub filters: FiltersConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl AppConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let file = path
            .or_else(|| env::var_os("BRRPOLICE_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        let builder = Config::builder()
            .set_default("qbittorrent.base_url", "http://qbittorrent:8080")?
            .set_default("qbittorrent.username", "admin")?
            .set_default("qbittorrent.password_env", "QBITTORRENT_PASSWORD")?
            .set_default("qbittorrent.poll_interval", "30s")?
            .set_default("qbittorrent.request_timeout", "10s")?
            .set_default("policy.slow_rate_bps", 262_144_u64)?
            .set_default("policy.min_progress_delta", 0.0025_f64)?
            .set_default("policy.new_peer_grace_period", "5m")?
            .set_default("policy.min_observation_duration", "20m")?
            .set_default("policy.bad_for_duration", "15m")?
            .set_default("policy.decay_window", "60m")?
            .set_default("policy.ignore_peer_progress_at_or_above", 0.95_f64)?
            .set_default("policy.min_total_seeders", 3_u32)?
            .set_default("policy.reban_cooldown", "30m")?
            .set_default(
                "policy.ban_ladder.durations",
                vec!["1h", "6h", "24h", "168h"],
            )?
            .set_default("database.path", "/data/brrpolice.sqlite")?
            .set_default("database.busy_timeout", "5s")?
            .set_default("http.bind", "0.0.0.0:9090")?
            .set_default("logging.level", "info")?
            .set_default("logging.format", "json")?
            .add_source(
                File::new(file.to_string_lossy().as_ref(), FileFormat::Toml).required(false),
            )
            .add_source(Environment::with_prefix("BRRPOLICE").separator("__"));

        let raw = builder.build()?;
        let parsed = raw.try_deserialize::<AppConfig>()?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn init_tracing(&self) -> Result<()> {
        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new(self.logging.level.clone()))
            .context("failed to initialize tracing env filter")?;

        match self.logging.format.as_str() {
            "json" => fmt().with_env_filter(env_filter).json().init(),
            "plain" | "text" => fmt().with_env_filter(env_filter).init(),
            other => bail!("unsupported logging format `{other}`"),
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.qbittorrent.base_url.trim().is_empty() {
            bail!("qbittorrent.base_url must not be empty");
        }
        if self.qbittorrent.username.trim().is_empty() {
            bail!("qbittorrent.username must not be empty");
        }
        if self.qbittorrent.password_env.trim().is_empty() {
            bail!("qbittorrent.password_env must not be empty");
        }
        if self.policy.slow_rate_bps == 0 {
            bail!("policy.slow_rate_bps must be positive");
        }
        if !(0.0..=1.0).contains(&self.policy.ignore_peer_progress_at_or_above) {
            bail!("policy.ignore_peer_progress_at_or_above must be between 0.0 and 1.0");
        }
        if self.policy.min_progress_delta < 0.0 {
            bail!("policy.min_progress_delta must not be negative");
        }
        if self.policy.ban_ladder.durations.is_empty() {
            bail!("policy.ban_ladder.durations must not be empty");
        }
        if self.policy.bad_for_duration > self.policy.decay_window {
            bail!("policy.bad_for_duration must be less than or equal to policy.decay_window");
        }
        if self.http.bind.parse::<SocketAddr>().is_err() {
            bail!("http.bind must be a valid socket address");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct QbittorrentConfig {
    pub base_url: String,
    pub username: String,
    pub password_env: String,
    #[serde(deserialize_with = "deserialize_duration")]
    pub poll_interval: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub request_timeout: Duration,
}

impl Default for QbittorrentConfig {
    fn default() -> Self {
        Self {
            base_url: "http://qbittorrent:8080".to_string(),
            username: "admin".to_string(),
            password_env: "QBITTORRENT_PASSWORD".to_string(),
            poll_interval: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub slow_rate_bps: u64,
    pub min_progress_delta: f64,
    #[serde(deserialize_with = "deserialize_duration")]
    pub new_peer_grace_period: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub min_observation_duration: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub bad_for_duration: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub decay_window: Duration,
    pub ignore_peer_progress_at_or_above: f64,
    pub min_total_seeders: u32,
    #[serde(deserialize_with = "deserialize_duration")]
    pub reban_cooldown: Duration,
    #[serde(default)]
    pub ban_ladder: BanLadderConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            slow_rate_bps: 262_144,
            min_progress_delta: 0.0025,
            new_peer_grace_period: Duration::from_secs(300),
            min_observation_duration: Duration::from_secs(1_200),
            bad_for_duration: Duration::from_secs(900),
            decay_window: Duration::from_secs(3_600),
            ignore_peer_progress_at_or_above: 0.95,
            min_total_seeders: 3,
            reban_cooldown: Duration::from_secs(1_800),
            ban_ladder: BanLadderConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BanLadderConfig {
    #[serde(default, deserialize_with = "deserialize_duration_vec")]
    pub durations: Vec<Duration>,
}

impl Default for BanLadderConfig {
    fn default() -> Self {
        Self {
            durations: vec![
                Duration::from_secs(3_600),
                Duration::from_secs(21_600),
                Duration::from_secs(86_400),
                Duration::from_secs(604_800),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FiltersConfig {
    #[serde(default)]
    pub include_categories: Vec<String>,
    #[serde(default)]
    pub exclude_categories: Vec<String>,
    #[serde(default)]
    pub include_tags: Vec<String>,
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    #[serde(default)]
    pub allowlist_peer_ips: Vec<String>,
    #[serde(default)]
    pub allowlist_peer_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    #[serde(deserialize_with = "deserialize_duration")]
    pub busy_timeout: Duration,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/data/brrpolice.sqlite"),
            busy_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub bind: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9090".to_string(),
        }
    }
}

impl HttpConfig {
    pub fn bind_addr(&self) -> Result<SocketAddr> {
        self.bind
            .parse::<SocketAddr>()
            .context("failed to parse http.bind")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
        }
    }
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_duration(&raw).map_err(serde::de::Error::custom)
}

fn deserialize_duration_vec<'de, D>(deserializer: D) -> Result<Vec<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<String>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|value| parse_duration(&value).map_err(serde::de::Error::custom))
        .collect()
}
