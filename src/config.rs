#![allow(dead_code)]

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use config::{Config, Environment, File, FileFormat, Map};
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
        let env_path = std::env::var_os("BRRPOLICE_CONFIG").map(PathBuf::from);
        let (file, require_file) = match (path, env_path) {
            (Some(path), _) => (path, true),
            (None, Some(path)) => (path, true),
            (None, None) => (PathBuf::from("config.toml"), false),
        };
        Self::load_from_path_with_env_source(&file, None, require_file)
    }

    fn load_from_path_with_env_source(
        path: &Path,
        env_source: Option<Map<String, String>>,
        require_file: bool,
    ) -> Result<Self> {
        let raw = Config::builder()
            .set_default("qbittorrent.base_url", "http://qbittorrent:8080")?
            .set_default("qbittorrent.username", "")?
            .set_default("qbittorrent.password_env", "")?
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
                File::new(path.to_string_lossy().as_ref(), FileFormat::Toml).required(require_file),
            )
            .add_source(environment_source(env_source))
            .build()
            .with_context(|| format!("failed to load configuration file `{}`", path.display()))?;
        let parsed = raw.try_deserialize::<AppConfig>()?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn init_tracing(&self) -> Result<()> {
        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new(default_env_filter_expression(&self.logging.level)))
            .context("failed to initialize tracing env filter")?;

        match self.logging.format.as_str() {
            "json" => fmt().with_env_filter(env_filter).json().init(),
            "plain" | "text" => fmt().with_env_filter(env_filter).init(),
            other => bail!("unsupported logging format `{other}`"),
        }

        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        fn join(values: &[String]) -> String {
            values.join(",")
        }

        format!(
            concat!(
                "qb.base_url={}\n",
                "qb.username={}\n",
                "qb.password_env={}\n",
                "qb.poll_interval={}\n",
                "qb.request_timeout={}\n",
                "policy.slow_rate_bps={}\n",
                "policy.min_progress_delta={:.6}\n",
                "policy.new_peer_grace_period={}\n",
                "policy.min_observation_duration={}\n",
                "policy.bad_for_duration={}\n",
                "policy.decay_window={}\n",
                "policy.ignore_peer_progress_at_or_above={:.6}\n",
                "policy.min_total_seeders={}\n",
                "policy.reban_cooldown={}\n",
                "policy.ban_ladder={}\n",
                "filters.include_categories={}\n",
                "filters.exclude_categories={}\n",
                "filters.include_tags={}\n",
                "filters.exclude_tags={}\n",
                "filters.allowlist_peer_ips={}\n",
                "filters.allowlist_peer_cidrs={}\n",
                "database.path={}\n",
                "database.busy_timeout={}\n",
                "http.bind={}\n",
                "logging.level={}\n",
                "logging.format={}\n"
            ),
            self.qbittorrent.base_url,
            self.qbittorrent.username,
            self.qbittorrent.password_env,
            self.qbittorrent.poll_interval.as_secs(),
            self.qbittorrent.request_timeout.as_secs(),
            self.policy.slow_rate_bps,
            self.policy.min_progress_delta,
            self.policy.new_peer_grace_period.as_secs(),
            self.policy.min_observation_duration.as_secs(),
            self.policy.bad_for_duration.as_secs(),
            self.policy.decay_window.as_secs(),
            self.policy.ignore_peer_progress_at_or_above,
            self.policy.min_total_seeders,
            self.policy.reban_cooldown.as_secs(),
            self.policy
                .ban_ladder
                .durations
                .iter()
                .map(|duration| duration.as_secs().to_string())
                .collect::<Vec<_>>()
                .join(","),
            join(&self.filters.include_categories),
            join(&self.filters.exclude_categories),
            join(&self.filters.include_tags),
            join(&self.filters.exclude_tags),
            join(&self.filters.allowlist_peer_ips),
            join(&self.filters.allowlist_peer_cidrs),
            self.database.path.display(),
            self.database.busy_timeout.as_secs(),
            self.http.bind,
            self.logging.level,
            self.logging.format,
        )
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
        if !base_url.username().is_empty() || base_url.password().is_some() {
            bail!("qbittorrent.base_url must not include URL credentials");
        }

        let username = self.qbittorrent.username.trim();
        let password_env = self.qbittorrent.password_env.trim();
        match (username.is_empty(), password_env.is_empty()) {
            (true, true) => {}
            (false, false) => validate_env_var_name(password_env)?,
            _ => {
                bail!(
                    "qbittorrent.username and qbittorrent.password_env must either both be set or both be unset"
                );
            }
        }
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

fn default_env_filter_expression(level: &str) -> String {
    let level = level.trim();
    let base_level = if level.is_empty() { "info" } else { level };
    format!("{base_level},hyper_util::client::legacy::pool=warn")
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
            username: String::new(),
            password_env: String::new(),
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
    parse_duration(raw.trim()).map_err(serde::de::Error::custom)
}

fn deserialize_duration_vec<'de, D>(deserializer: D) -> Result<Vec<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<String>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|value| parse_duration(value.trim()).map_err(serde::de::Error::custom))
        .collect()
}

fn require_positive_duration(duration: Duration, field_name: &str) -> Result<()> {
    if duration.is_zero() {
        bail!("{field_name} must be greater than zero");
    }

    Ok(())
}

fn environment_source(source: Option<Map<String, String>>) -> Environment {
    let mut env = Environment::with_prefix("BRRPOLICE")
        .prefix_separator("_")
        .separator("__")
        .ignore_empty(true)
        .list_separator(",")
        .try_parsing(true);
    for key in [
        "policy.ban_ladder.durations",
        "filters.include_categories",
        "filters.exclude_categories",
        "filters.include_tags",
        "filters.exclude_tags",
        "filters.allowlist_peer_ips",
        "filters.allowlist_peer_cidrs",
    ] {
        env = env.with_list_parse_key(key);
    }
    env.source(source)
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
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
        time::Duration,
    };

    use super::AppConfig;
    use tempfile::tempdir;

    #[test]
    fn loads_defaults_when_no_file_exists() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("missing.toml");

        let config = load_test_config(&config_path, HashMap::new()).unwrap();

        assert_eq!(config.qbittorrent.base_url, "http://qbittorrent:8080");
        assert_eq!(config.qbittorrent.username, "");
        assert_eq!(config.qbittorrent.password_env, "");
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
    fn defaults_http_bind_to_all_interfaces() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("missing.toml");

        let config = load_test_config(&config_path, HashMap::new()).unwrap();

        assert_eq!(config.http.bind, "0.0.0.0:9090");
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
                    "BRRPOLICE_QBITTORRENT__PASSWORD_ENV".to_string(),
                    "QB_PASSWORD".to_string(),
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
        assert_eq!(config.qbittorrent.password_env, "QB_PASSWORD");
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
    fn rejects_invalid_password_env_name() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
username = "admin"
password_env = "1NOT_VALID"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(error.to_string().contains("password_env must start"));
    }

    #[test]
    fn rejects_username_without_password_env() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
username = "admin"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must either both be set or both be unset")
        );
    }

    #[test]
    fn rejects_password_env_without_username() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
password_env = "QBITTORRENT_PASSWORD"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must either both be set or both be unset")
        );
    }

    #[test]
    fn rejects_base_url_with_embedded_credentials() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
base_url = "http://admin:secret@qbittorrent:8080"
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("qbittorrent.base_url must not include URL credentials")
        );
    }

    #[test]
    fn rejects_empty_ban_ladder() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[policy.ban_ladder]
durations = []
"#,
        );

        let error = load_test_config(&config_path, HashMap::new()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ban_ladder.durations must not be empty")
        );
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

    #[test]
    fn debug_logging_filter_suppresses_hyper_connection_pool_noise() {
        let filter = super::default_env_filter_expression("debug");
        assert!(filter.contains("hyper_util::client::legacy::pool=warn"));
    }

    #[test]
    fn fingerprint_is_stable_and_changes_when_config_changes() {
        let temp_dir = tempdir().unwrap();
        let baseline =
            load_test_config(&temp_dir.path().join("missing.toml"), HashMap::new()).unwrap();
        let changed = load_test_config(
            &temp_dir.path().join("missing.toml"),
            HashMap::from([(
                "BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS".to_string(),
                "7".to_string(),
            )]),
        )
        .unwrap();

        assert_eq!(
            baseline.fingerprint(),
            load_test_config(&temp_dir.path().join("missing.toml"), HashMap::new())
                .unwrap()
                .fingerprint()
        );
        assert_ne!(baseline.fingerprint(), changed.fingerprint());
    }

    #[test]
    fn errors_when_config_env_path_is_missing() {
        let temp_dir = tempdir().unwrap();
        let missing_path = temp_dir.path().join("missing.toml");
        let error = load_test_config_via_env_var(missing_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("failed to load configuration file")
                && chain.contains("missing.toml")
                && chain.contains("not found")
        );
    }

    #[test]
    fn errors_when_config_env_path_has_parse_error() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("invalid.toml");
        fs::write(
            &config_path,
            r#"
[qbittorrent
base_url = "http://qbittorrent:8080"
"#,
        )
        .unwrap();

        let error = load_test_config_via_env_var(config_path).unwrap_err();
        assert!(format!("{error:#}").contains("failed to load configuration file"));
    }

    #[test]
    fn errors_when_config_env_path_has_validation_error() {
        let temp_dir = tempdir().unwrap();
        let config_path = write_config(
            temp_dir.path(),
            r#"
[qbittorrent]
poll_interval = "5s"
request_timeout = "10s"
"#,
        );

        let error = load_test_config_via_env_var(config_path).unwrap_err();
        assert!(format!("{error:#}").contains("request_timeout"));
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
        AppConfig::load_from_path_with_env_source(path, Some(overrides.into_iter().collect()), false)
    }

    fn load_test_config_via_env_var(path: PathBuf) -> anyhow::Result<AppConfig> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().unwrap();
        unsafe {
            std::env::set_var("BRRPOLICE_CONFIG", path);
        }
        let result = AppConfig::load(None);
        unsafe {
            std::env::remove_var("BRRPOLICE_CONFIG");
        }
        result
    }
}
