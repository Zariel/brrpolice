#![allow(dead_code)]

use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use config::{Config, File, FileFormat};
use humantime::parse_duration;
use ipnet::IpNet;
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
        Self::load_from_path_with_env(&file, &read_env_var)
    }

    fn load_from_path_with_env<F>(path: &Path, read_env: &F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        Self::from_builder_with_env(
            Config::builder()
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
                    File::new(path.to_string_lossy().as_ref(), FileFormat::Toml).required(false),
                ),
            read_env,
        )
    }

    fn from_builder_with_env<F>(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
        read_env: &F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let raw = builder.build()?;
        let mut parsed = raw.try_deserialize::<AppConfig>()?;
        parsed.apply_env_overrides(read_env)?;
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

    fn apply_env_overrides<F>(&mut self, read_env: &F) -> Result<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        apply_string_override(
            "BRRPOLICE_QBITTORRENT__BASE_URL",
            &mut self.qbittorrent.base_url,
            read_env,
        );
        apply_string_override(
            "BRRPOLICE_QBITTORRENT__USERNAME",
            &mut self.qbittorrent.username,
            read_env,
        );
        apply_string_override(
            "BRRPOLICE_QBITTORRENT__PASSWORD_ENV",
            &mut self.qbittorrent.password_env,
            read_env,
        );
        apply_duration_override(
            "BRRPOLICE_QBITTORRENT__POLL_INTERVAL",
            &mut self.qbittorrent.poll_interval,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_QBITTORRENT__REQUEST_TIMEOUT",
            &mut self.qbittorrent.request_timeout,
            read_env,
        )?;

        apply_u64_override(
            "BRRPOLICE_POLICY__SLOW_RATE_BPS",
            &mut self.policy.slow_rate_bps,
            read_env,
        )?;
        apply_f64_override(
            "BRRPOLICE_POLICY__MIN_PROGRESS_DELTA",
            &mut self.policy.min_progress_delta,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_POLICY__NEW_PEER_GRACE_PERIOD",
            &mut self.policy.new_peer_grace_period,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_POLICY__MIN_OBSERVATION_DURATION",
            &mut self.policy.min_observation_duration,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_POLICY__BAD_FOR_DURATION",
            &mut self.policy.bad_for_duration,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_POLICY__DECAY_WINDOW",
            &mut self.policy.decay_window,
            read_env,
        )?;
        apply_f64_override(
            "BRRPOLICE_POLICY__IGNORE_PEER_PROGRESS_AT_OR_ABOVE",
            &mut self.policy.ignore_peer_progress_at_or_above,
            read_env,
        )?;
        apply_u32_override(
            "BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS",
            &mut self.policy.min_total_seeders,
            read_env,
        )?;
        apply_duration_override(
            "BRRPOLICE_POLICY__REBAN_COOLDOWN",
            &mut self.policy.reban_cooldown,
            read_env,
        )?;
        apply_duration_list_override(
            "BRRPOLICE_POLICY__BAN_LADDER__DURATIONS",
            &mut self.policy.ban_ladder.durations,
            read_env,
        )?;

        apply_list_override(
            "BRRPOLICE_FILTERS__INCLUDE_CATEGORIES",
            &mut self.filters.include_categories,
            read_env,
        );
        apply_list_override(
            "BRRPOLICE_FILTERS__EXCLUDE_CATEGORIES",
            &mut self.filters.exclude_categories,
            read_env,
        );
        apply_list_override(
            "BRRPOLICE_FILTERS__INCLUDE_TAGS",
            &mut self.filters.include_tags,
            read_env,
        );
        apply_list_override(
            "BRRPOLICE_FILTERS__EXCLUDE_TAGS",
            &mut self.filters.exclude_tags,
            read_env,
        );
        apply_list_override(
            "BRRPOLICE_FILTERS__ALLOWLIST_PEER_IPS",
            &mut self.filters.allowlist_peer_ips,
            read_env,
        );
        apply_list_override(
            "BRRPOLICE_FILTERS__ALLOWLIST_PEER_CIDRS",
            &mut self.filters.allowlist_peer_cidrs,
            read_env,
        );

        apply_path_override(
            "BRRPOLICE_DATABASE__PATH",
            &mut self.database.path,
            read_env,
        );
        apply_duration_override(
            "BRRPOLICE_DATABASE__BUSY_TIMEOUT",
            &mut self.database.busy_timeout,
            read_env,
        )?;

        apply_string_override("BRRPOLICE_HTTP__BIND", &mut self.http.bind, read_env);
        apply_string_override(
            "BRRPOLICE_LOGGING__LEVEL",
            &mut self.logging.level,
            read_env,
        );
        apply_string_override(
            "BRRPOLICE_LOGGING__FORMAT",
            &mut self.logging.format,
            read_env,
        );

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.qbittorrent.base_url.trim().is_empty() {
            bail!("qbittorrent.base_url must not be empty");
        }
        let base_url = reqwest::Url::parse(&self.qbittorrent.base_url)
            .context("qbittorrent.base_url must be a valid URL")?;
        match base_url.scheme() {
            "http" | "https" => {}
            scheme => bail!("qbittorrent.base_url scheme must be http or https, got `{scheme}`"),
        }

        if self.qbittorrent.username.trim().is_empty() {
            bail!("qbittorrent.username must not be empty");
        }
        if self.qbittorrent.password_env.trim().is_empty() {
            bail!("qbittorrent.password_env must not be empty");
        }
        validate_env_var_name(&self.qbittorrent.password_env)?;
        require_positive_duration(self.qbittorrent.poll_interval, "qbittorrent.poll_interval")?;
        require_positive_duration(
            self.qbittorrent.request_timeout,
            "qbittorrent.request_timeout",
        )?;
        if self.qbittorrent.request_timeout > self.qbittorrent.poll_interval {
            bail!(
                "qbittorrent.request_timeout must be less than or equal to qbittorrent.poll_interval"
            );
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
        if self.policy.min_progress_delta > 1.0 {
            bail!("policy.min_progress_delta must not exceed 1.0");
        }
        if self.policy.ban_ladder.durations.is_empty() {
            bail!("policy.ban_ladder.durations must not be empty");
        }
        require_positive_duration(
            self.policy.new_peer_grace_period,
            "policy.new_peer_grace_period",
        )?;
        require_positive_duration(
            self.policy.min_observation_duration,
            "policy.min_observation_duration",
        )?;
        require_positive_duration(self.policy.bad_for_duration, "policy.bad_for_duration")?;
        require_positive_duration(self.policy.decay_window, "policy.decay_window")?;
        require_positive_duration(self.policy.reban_cooldown, "policy.reban_cooldown")?;
        if self.policy.bad_for_duration > self.policy.decay_window {
            bail!("policy.bad_for_duration must be less than or equal to policy.decay_window");
        }
        if self.policy.min_total_seeders == 0 {
            bail!("policy.min_total_seeders must be at least 1");
        }
        for (index, duration) in self.policy.ban_ladder.durations.iter().enumerate() {
            require_positive_duration(*duration, &format!("policy.ban_ladder.durations[{index}]"))?;
        }
        if self.http.bind.parse::<SocketAddr>().is_err() {
            bail!("http.bind must be a valid socket address");
        }
        require_positive_duration(self.database.busy_timeout, "database.busy_timeout")?;
        validate_ip_allowlists(&self.filters)?;
        validate_logging_format(&self.logging.format)?;

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

fn require_positive_duration(duration: Duration, field_name: &str) -> Result<()> {
    if duration.is_zero() {
        bail!("{field_name} must be greater than zero");
    }

    Ok(())
}

fn apply_string_override<F>(key: &str, target: &mut String, read_env: &F)
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = value;
    }
}

fn apply_path_override<F>(key: &str, target: &mut PathBuf, read_env: &F)
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = PathBuf::from(value);
    }
}

fn apply_duration_override<F>(key: &str, target: &mut Duration, read_env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = parse_duration(&value)
            .with_context(|| format!("invalid duration in environment variable `{key}`"))?;
    }

    Ok(())
}

fn apply_duration_list_override<F>(
    key: &str,
    target: &mut Vec<Duration>,
    read_env: &F,
) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = split_env_list(&value)
            .into_iter()
            .map(|item| {
                parse_duration(&item)
                    .with_context(|| format!("invalid duration in environment variable `{key}`"))
            })
            .collect::<Result<Vec<_>>>()?;
    }

    Ok(())
}

fn apply_u64_override<F>(key: &str, target: &mut u64, read_env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = value
            .parse()
            .with_context(|| format!("invalid u64 in environment variable `{key}`"))?;
    }

    Ok(())
}

fn apply_u32_override<F>(key: &str, target: &mut u32, read_env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = value
            .parse()
            .with_context(|| format!("invalid u32 in environment variable `{key}`"))?;
    }

    Ok(())
}

fn apply_f64_override<F>(key: &str, target: &mut f64, read_env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = value
            .parse()
            .with_context(|| format!("invalid f64 in environment variable `{key}`"))?;
    }

    Ok(())
}

fn apply_list_override<F>(key: &str, target: &mut Vec<String>, read_env: &F)
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = read_env(key) {
        *target = split_env_list(&value);
    }
}

fn read_env_var(key: &str) -> Option<String> {
    env::var(key).ok().map(|value| value.trim().to_string())
}

fn split_env_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn validate_env_var_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        bail!("qbittorrent.password_env must not be empty");
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        bail!("qbittorrent.password_env must start with a letter or underscore");
    }

    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        bail!("qbittorrent.password_env must contain only ASCII letters, digits, and underscores");
    }

    Ok(())
}

fn validate_ip_allowlists(filters: &FiltersConfig) -> Result<()> {
    for value in &filters.allowlist_peer_ips {
        value
            .parse::<IpAddr>()
            .with_context(|| format!("invalid allowlisted peer IP `{value}`"))?;
    }

    for value in &filters.allowlist_peer_cidrs {
        value
            .parse::<IpNet>()
            .with_context(|| format!("invalid allowlisted peer CIDR `{value}`"))?;
    }

    Ok(())
}

fn validate_logging_format(format: &str) -> Result<()> {
    match format {
        "json" | "plain" | "text" => Ok(()),
        other => bail!("unsupported logging format `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::Path, time::Duration};

    use super::AppConfig;
    use tempfile::tempdir;

    #[test]
    fn loads_defaults_when_no_file_exists() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("missing.toml");

        let config = load_test_config(&config_path, HashMap::new()).unwrap();

        assert_eq!(config.qbittorrent.base_url, "http://qbittorrent:8080");
        assert_eq!(config.policy.slow_rate_bps, 262_144);
        assert_eq!(
            config.policy.ban_ladder.durations,
            vec![
                Duration::from_secs(3_600),
                Duration::from_secs(21_600),
                Duration::from_secs(86_400),
                Duration::from_secs(604_800)
            ]
        );
    }

    #[test]
    fn loads_values_from_toml_file() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
base_url = "https://qb.example.internal"
username = "alice"
password_env = "QB_PASSWORD"
poll_interval = "45s"
request_timeout = "5s"

[policy]
slow_rate_bps = 1024
min_progress_delta = 0.01
new_peer_grace_period = "10m"
min_observation_duration = "25m"
bad_for_duration = "20m"
decay_window = "90m"
ignore_peer_progress_at_or_above = 0.9
min_total_seeders = 5
reban_cooldown = "45m"

[policy.ban_ladder]
durations = ["2h", "12h"]

[filters]
allowlist_peer_ips = ["127.0.0.1"]
allowlist_peer_cidrs = ["10.0.0.0/24"]

[database]
path = "/tmp/test.sqlite"
busy_timeout = "7s"

[http]
bind = "127.0.0.1:9191"

[logging]
level = "debug"
format = "plain"
"#,
        );

        let config = load_test_config(&config_path, HashMap::new()).unwrap();

        assert_eq!(config.qbittorrent.username, "alice");
        assert_eq!(config.policy.slow_rate_bps, 1024);
        assert_eq!(config.filters.allowlist_peer_cidrs, vec!["10.0.0.0/24"]);
        assert_eq!(config.http.bind, "127.0.0.1:9191");
        assert_eq!(config.logging.format, "plain");
    }

    #[test]
    fn environment_overrides_toml_values() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
username = "from-file"
poll_interval = "45s"
request_timeout = "10s"

[policy]
slow_rate_bps = 2048

[filters]
allowlist_peer_ips = ["127.0.0.1"]
"#,
        );

        let config = load_test_config(
            &config_path,
            HashMap::from([
                (
                    "BRRPOLICE_QBITTORRENT__USERNAME".to_string(),
                    "from-env".to_string(),
                ),
                (
                    "BRRPOLICE_POLICY__SLOW_RATE_BPS".to_string(),
                    "4096".to_string(),
                ),
                (
                    "BRRPOLICE_FILTERS__ALLOWLIST_PEER_IPS".to_string(),
                    "192.168.1.10,192.168.1.11".to_string(),
                ),
            ]),
        )
        .unwrap();

        assert_eq!(config.qbittorrent.username, "from-env");
        assert_eq!(config.policy.slow_rate_bps, 4096);
        assert_eq!(
            config.filters.allowlist_peer_ips,
            vec!["192.168.1.10", "192.168.1.11"]
        );
    }

    #[test]
    fn rejects_invalid_cidr() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[filters]
allowlist_peer_cidrs = ["10.0.0.0/99"]
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(error.to_string().contains("invalid allowlisted peer CIDR"));
    }

    #[test]
    fn rejects_invalid_qbittorrent_threshold_combinations() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
poll_interval = "5s"
request_timeout = "10s"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(error.to_string().contains("request_timeout"));
    }

    #[test]
    fn rejects_unsupported_logging_format() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[logging]
format = "yaml"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(error.to_string().contains("unsupported logging format"));
    }

    fn write_config(dir: &Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("config.toml");
        fs::write(&path, content).unwrap();
        path
    }

    fn load_test_config(
        path: &Path,
        overrides: HashMap<String, String>,
    ) -> anyhow::Result<AppConfig> {
        AppConfig::load_from_path_with_env(path, &|key| overrides.get(key).cloned())
    }
}
