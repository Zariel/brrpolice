use std::{
    collections::BTreeSet,
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use tracing::debug;

use crate::{
    config::{FiltersConfig, QbittorrentConfig},
    persistence::ActiveBanRecord,
    types::{PeerObservationId, PeerSnapshot, TorrentPeer, TorrentSummary},
};

const AUTH_LOGIN_PATH: &str = "api/v2/auth/login";
const APP_VERSION_PATH: &str = "api/v2/app/version";
const WEBAPI_VERSION_PATH: &str = "api/v2/app/webapiVersion";
const APP_PREFERENCES_PATH: &str = "api/v2/app/preferences";
const APP_SET_PREFERENCES_PATH: &str = "api/v2/app/setPreferences";
const TORRENTS_INFO_PATH: &str = "api/v2/torrents/info";
const SYNC_TORRENT_PEERS_PATH: &str = "api/v2/sync/torrentPeers";
const TRANSFER_BAN_PEERS_PATH: &str = "api/v2/transfer/banPeers";

#[derive(Clone)]
pub struct QbittorrentClient {
    config: QbittorrentConfig,
    password: String,
    filters: FiltersConfig,
    min_total_seeders: u32,
    client: Client,
    base_url: Url,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanSyncResult {
    pub banned_ips: Vec<IpAddr>,
}

impl QbittorrentClient {
    pub fn new(
        config: QbittorrentConfig,
        password: String,
        filters: FiltersConfig,
        min_total_seeders: u32,
        timeout: Duration,
    ) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).context("invalid qbittorrent.base_url")?;
        let client = Client::builder()
            .cookie_store(true)
            .timeout(timeout)
            .build()?;

        Ok(Self {
            config,
            password,
            filters,
            min_total_seeders,
            client,
            base_url,
        })
    }

    pub async fn authenticate(&self) -> Result<()> {
        let response = self
            .client
            .post(self.api_url(AUTH_LOGIN_PATH)?)
            .form(&[
                ("username", self.config.username.as_str()),
                ("password", self.password.as_str()),
            ])
            .send()
            .await
            .context("qbittorrent login request failed")?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read qbittorrent login response")?;
        if status != StatusCode::OK || body.trim() != "Ok." {
            bail!(
                "qbittorrent login failed: status={} body={}",
                status,
                body.trim()
            );
        }
        debug!(
            login_url = %self.api_url(AUTH_LOGIN_PATH)?,
            base_url = %self.base_url,
            "qbittorrent authentication succeeded"
        );
        Ok(())
    }

    pub async fn list_in_scope_torrents(&self) -> Result<Vec<TorrentSummary>> {
        let mut url = self.torrent_info_url()?;
        url.query_pairs_mut().append_pair("filter", "seeding");
        let body = self.authenticated_get_text(url).await?;
        let torrents = self.parse_torrents(&body)?;
        Ok(self.filter_in_scope_torrents(torrents))
    }

    pub async fn list_torrent_peers(&self, torrent_hash: &str) -> Result<Vec<TorrentPeer>> {
        let url = self.torrent_peers_url(torrent_hash, 0)?;
        let body = self.authenticated_get_text(url).await?;
        self.normalize_torrent_peers(torrent_hash, &body)
    }

    pub async fn apply_peer_ban(
        &self,
        ban: &ActiveBanRecord,
        active_bans: &[ActiveBanRecord],
    ) -> Result<BanSyncResult> {
        let ban_url = self.ban_peers_url()?;
        let peers = self.encode_ban_peers(&[(ban.peer_ip, ban.peer_port)]);
        self.send_authenticated(|| {
            self.client
                .post(ban_url.clone())
                .form(&[("peers", peers.clone())])
        })
        .await
        .with_context(|| {
            format!(
                "failed to apply qbittorrent peer ban for {}:{}",
                ban.peer_ip, ban.peer_port
            )
        })?;

        let banned_ips = self.managed_banned_ips(active_bans.iter().chain(std::iter::once(ban)));
        self.sync_banned_ips(&banned_ips).await.with_context(|| {
            format!(
                "failed to persist managed banned IPs after banning {}:{}",
                ban.peer_ip, ban.peer_port
            )
        })
    }

    pub async fn reconcile_expired_bans(
        &self,
        active_bans: &[ActiveBanRecord],
    ) -> Result<BanSyncResult> {
        let banned_ips = self.managed_banned_ips(active_bans.iter());
        self.sync_banned_ips(&banned_ips).await.with_context(|| {
            format!(
                "failed to reconcile qbittorrent banned IPs from {} active bans",
                active_bans.len()
            )
        })
    }

    async fn authenticated_get_text(&self, url: Url) -> Result<String> {
        let response = self
            .send_authenticated(|| self.client.get(url.clone()))
            .await?;
        response
            .text()
            .await
            .context("failed to read qbittorrent response body")
    }

    async fn send_authenticated<F>(&self, build: F) -> Result<reqwest::Response>
    where
        F: Fn() -> RequestBuilder,
    {
        let response = build().send().await.context("qbittorrent request failed")?;
        if response.status() == StatusCode::FORBIDDEN {
            self.authenticate().await?;
            let retried = build()
                .send()
                .await
                .context("qbittorrent authenticated retry failed")?;
            return Self::ensure_success(retried).await;
        }

        Self::ensure_success(response).await
    }

    async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        bail!(
            "qbittorrent request failed: status={} body={}",
            status,
            body.trim()
        );
    }

    fn api_url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .context("failed to build qbittorrent api url")
    }

    fn torrent_info_url(&self) -> Result<Url> {
        self.api_url(TORRENTS_INFO_PATH)
    }

    fn torrent_peers_url(&self, hash: &str, rid: u64) -> Result<Url> {
        let mut url = self.api_url(SYNC_TORRENT_PEERS_PATH)?;
        url.query_pairs_mut()
            .append_pair("hash", hash)
            .append_pair("rid", &rid.to_string());
        Ok(url)
    }

    fn ban_peers_url(&self) -> Result<Url> {
        self.api_url(TRANSFER_BAN_PEERS_PATH)
    }

    fn set_preferences_url(&self) -> Result<Url> {
        self.api_url(APP_SET_PREFERENCES_PATH)
    }

    fn parse_torrents(&self, body: &str) -> Result<Vec<TorrentSummary>> {
        let torrents: Vec<QbTorrent> =
            serde_json::from_str(body).context("invalid torrent list payload")?;
        Ok(torrents
            .into_iter()
            .map(|torrent| TorrentSummary {
                hash: torrent.hash,
                name: torrent.name,
                total_seeders: torrent.num_complete.max(0) as u32,
                category: empty_string_to_none(torrent.category),
                tags: split_tags(&torrent.tags),
            })
            .collect())
    }

    fn filter_in_scope_torrents(&self, torrents: Vec<TorrentSummary>) -> Vec<TorrentSummary> {
        torrents
            .into_iter()
            .filter(|torrent| self.is_torrent_in_scope(torrent))
            .collect()
    }

    fn is_torrent_in_scope(&self, torrent: &TorrentSummary) -> bool {
        if torrent.total_seeders < self.min_total_seeders {
            return false;
        }

        if matches_list(
            torrent.category.as_deref(),
            &self.filters.exclude_categories,
        ) {
            return false;
        }

        if torrent
            .tags
            .iter()
            .any(|tag| matches_list(Some(tag.as_str()), &self.filters.exclude_tags))
        {
            return false;
        }

        let has_include_rules =
            !self.filters.include_categories.is_empty() || !self.filters.include_tags.is_empty();
        if !has_include_rules {
            return true;
        }

        matches_list(
            torrent.category.as_deref(),
            &self.filters.include_categories,
        ) || torrent
            .tags
            .iter()
            .any(|tag| matches_list(Some(tag.as_str()), &self.filters.include_tags))
    }

    fn parse_torrent_peers(&self, body: &str) -> Result<QbTorrentPeersResponse> {
        serde_json::from_str(body).context("invalid torrent peers payload")
    }

    fn normalize_torrent_peers(&self, torrent_hash: &str, body: &str) -> Result<Vec<TorrentPeer>> {
        let peers = self.parse_torrent_peers(body)?;
        let mut normalized = peers
            .peers
            .into_iter()
            .map(|(peer_key, peer)| self.normalize_peer(torrent_hash, &peer_key, peer))
            .collect::<Result<Vec<_>>>()?;
        normalized.sort_by(|left, right| {
            left.observation_id
                .peer_ip
                .cmp(&right.observation_id.peer_ip)
                .then(
                    left.observation_id
                        .peer_port
                        .cmp(&right.observation_id.peer_port),
                )
        });
        Ok(normalized)
    }

    fn normalize_peer(
        &self,
        torrent_hash: &str,
        peer_key: &str,
        peer: QbPeer,
    ) -> Result<TorrentPeer> {
        let ip = peer
            .ip
            .parse::<IpAddr>()
            .with_context(|| format!("invalid peer ip `{}`", peer.ip))?;
        if let Some(address) = parse_peer_key(peer_key) {
            if address.ip() != ip || address.port() != peer.port {
                bail!(
                    "peer key `{peer_key}` does not match body endpoint `{ip}:{}`",
                    peer.port
                );
            }
        }
        let client_name = empty_string_to_none(peer.client.trim().to_string());
        let peer = PeerSnapshot {
            ip,
            port: peer.port,
            progress: peer.progress.clamp(0.0, 1.0),
            up_rate_bps: peer.up_speed,
        };

        Ok(TorrentPeer {
            observation_id: PeerObservationId {
                torrent_hash: torrent_hash.to_string(),
                peer_ip: peer.ip,
                peer_port: peer.port,
            },
            peer,
            client_name,
        })
    }

    fn encode_ban_peers(&self, peers: &[(IpAddr, u16)]) -> String {
        peers
            .iter()
            .map(|(ip, port)| format!("{ip}:{port}"))
            .collect::<Vec<_>>()
            .join("|")
    }

    fn encode_banned_ips_preferences(&self, banned_ips: &[IpAddr]) -> Result<String> {
        Ok(serde_json::json!({
            "banned_IPs": banned_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
        })
        .to_string())
    }

    fn managed_banned_ips<'a>(
        &self,
        active_bans: impl IntoIterator<Item = &'a ActiveBanRecord>,
    ) -> Vec<IpAddr> {
        active_bans
            .into_iter()
            .map(|ban| ban.peer_ip)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    async fn sync_banned_ips(&self, banned_ips: &[IpAddr]) -> Result<BanSyncResult> {
        let preferences_url = self.set_preferences_url()?;
        let payload = self.encode_banned_ips_preferences(banned_ips)?;
        self.send_authenticated(|| {
            self.client
                .post(preferences_url.clone())
                .form(&[("json", payload.clone())])
        })
        .await?;

        Ok(BanSyncResult {
            banned_ips: banned_ips.to_vec(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct QbTorrent {
    hash: String,
    name: String,
    category: String,
    tags: String,
    num_complete: i64,
}

#[derive(Debug, Deserialize, PartialEq)]
struct QbTorrentPeersResponse {
    rid: u64,
    full_update: Option<bool>,
    show_flags: Option<bool>,
    peers: HashMap<String, QbPeer>,
    peers_removed: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct QbPeer {
    client: String,
    peer_id_client: Option<String>,
    connection: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    dl_speed: u64,
    files: Option<String>,
    flags: Option<String>,
    flags_desc: Option<String>,
    host_name: Option<String>,
    ip: String,
    port: u16,
    progress: f64,
    relevance: Option<f64>,
    downloaded: Option<u64>,
    uploaded: Option<u64>,
    up_speed: u64,
}

fn empty_string_to_none(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn split_tags(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn matches_list(value: Option<&str>, filter_values: &[String]) -> bool {
    value
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .is_some_and(|entry| filter_values.iter().any(|candidate| candidate == entry))
}

fn parse_peer_key(key: &str) -> Option<SocketAddr> {
    key.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        APP_PREFERENCES_PATH, APP_VERSION_PATH, AUTH_LOGIN_PATH, BanSyncResult, QbPeer,
        QbTorrentPeersResponse, QbittorrentClient, SYNC_TORRENT_PEERS_PATH, TORRENTS_INFO_PATH,
        TRANSFER_BAN_PEERS_PATH, WEBAPI_VERSION_PATH, parse_peer_key,
    };
    use crate::{
        config::{FiltersConfig, QbittorrentConfig},
        persistence::ActiveBanRecord,
        types::{PeerObservationId, TorrentSummary},
    };

    #[test]
    fn builds_expected_contract_endpoints() {
        let client = test_client();

        assert_eq!(
            client.api_url(AUTH_LOGIN_PATH).unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/auth/login"
        );
        assert_eq!(
            client.api_url(APP_VERSION_PATH).unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/app/version"
        );
        assert_eq!(
            client.api_url(WEBAPI_VERSION_PATH).unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/app/webapiVersion"
        );
        assert_eq!(
            client.api_url(APP_PREFERENCES_PATH).unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/app/preferences"
        );
        assert_eq!(
            client.set_preferences_url().unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/app/setPreferences"
        );
        assert_eq!(
            client.torrent_info_url().unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/torrents/info"
        );
        assert_eq!(
            client.torrent_peers_url("abc123", 14).unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/sync/torrentPeers?hash=abc123&rid=14"
        );
        assert_eq!(
            client.ban_peers_url().unwrap().as_str(),
            "http://qbittorrent:8080/api/v2/transfer/banPeers"
        );
        assert_eq!(SYNC_TORRENT_PEERS_PATH, "api/v2/sync/torrentPeers");
        assert_eq!(TORRENTS_INFO_PATH, "api/v2/torrents/info");
        assert_eq!(TRANSFER_BAN_PEERS_PATH, "api/v2/transfer/banPeers");
    }

    #[test]
    fn parses_torrent_list_contract() {
        let client = test_client();
        let torrents = client
            .parse_torrents(
                r#"[
                    {
                        "hash":"abc123",
                        "name":"Example Torrent",
                        "category":"tv",
                        "tags":"seed,public",
                        "num_complete":17
                    },
                    {
                        "hash":"def456",
                        "name":"No Category",
                        "category":"",
                        "tags":"",
                        "num_complete":0
                    }
                ]"#,
            )
            .unwrap();

        assert_eq!(torrents.len(), 2);
        assert_eq!(torrents[0].hash, "abc123");
        assert_eq!(torrents[0].name, "Example Torrent");
        assert_eq!(torrents[0].category.as_deref(), Some("tv"));
        assert_eq!(
            torrents[0].tags,
            vec!["seed".to_string(), "public".to_string()]
        );
        assert_eq!(torrents[0].total_seeders, 17);
        assert_eq!(torrents[1].category, None);
        assert!(torrents[1].tags.is_empty());
    }

    #[test]
    fn filters_torrents_by_scope_rules() {
        let client = scoped_test_client(FiltersConfig {
            include_categories: vec!["tv".to_string()],
            exclude_categories: vec!["linux".to_string()],
            include_tags: vec!["keep".to_string()],
            exclude_tags: vec!["skip".to_string()],
            allowlist_peer_ips: vec![],
            allowlist_peer_cidrs: vec![],
        });

        let filtered = client.filter_in_scope_torrents(vec![
            torrent_summary("a", Some("tv"), &["public"], 5),
            torrent_summary("b", Some("music"), &["keep"], 5),
            torrent_summary("c", Some("linux"), &["keep"], 5),
            torrent_summary("d", Some("tv"), &["skip"], 5),
            torrent_summary("e", Some("tv"), &["public"], 2),
            torrent_summary("f", Some("books"), &["public"], 5),
        ]);

        assert_eq!(
            filtered
                .into_iter()
                .map(|torrent| torrent.hash)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn includes_all_non_excluded_torrents_when_no_include_filters_are_set() {
        let client = test_client();

        let filtered = client.filter_in_scope_torrents(vec![
            torrent_summary("a", Some("tv"), &["public"], 3),
            torrent_summary("b", Some("tv"), &["skip"], 3),
        ]);

        assert_eq!(
            filtered
                .into_iter()
                .map(|torrent| torrent.hash)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn parses_torrent_peers_contract_keys() {
        let client = test_client();
        let peers = client
            .parse_torrent_peers(
                r#"{
                    "rid": 15,
                    "full_update": true,
                    "show_flags": true,
                    "peers": {
                        "10.0.0.10:51413": {
                            "client": "qBittorrent/5.0.0",
                            "peer_id_client": "qBittorrent",
                            "connection": "uTP",
                            "country": "United Kingdom",
                            "country_code": "gb",
                            "dl_speed": 32768,
                            "files": "0 (100%)",
                            "flags": "D",
                            "flags_desc": "remote interested",
                            "host_name": "example.test",
                            "ip": "10.0.0.10",
                            "port": 51413,
                            "progress": 0.42,
                            "relevance": 0.91,
                            "downloaded": 1048576,
                            "uploaded": 524288,
                            "up_speed": 65536
                        }
                    },
                    "peers_removed": []
                }"#,
            )
            .unwrap();

        assert_eq!(
            peers,
            QbTorrentPeersResponse {
                rid: 15,
                full_update: Some(true),
                show_flags: Some(true),
                peers: [(
                    "10.0.0.10:51413".to_string(),
                    QbPeer {
                        client: "qBittorrent/5.0.0".to_string(),
                        peer_id_client: Some("qBittorrent".to_string()),
                        connection: Some("uTP".to_string()),
                        country: Some("United Kingdom".to_string()),
                        country_code: Some("gb".to_string()),
                        dl_speed: 32768,
                        files: Some("0 (100%)".to_string()),
                        flags: Some("D".to_string()),
                        flags_desc: Some("remote interested".to_string()),
                        host_name: Some("example.test".to_string()),
                        ip: "10.0.0.10".to_string(),
                        port: 51413,
                        progress: 0.42,
                        relevance: Some(0.91),
                        downloaded: Some(1048576),
                        uploaded: Some(524288),
                        up_speed: 65536,
                    }
                )]
                .into_iter()
                .collect(),
                peers_removed: Some(vec![]),
            }
        );
    }

    #[test]
    fn normalizes_torrent_peers_into_internal_models() {
        let client = test_client();
        let peers = client
            .normalize_torrent_peers(
                "abc123",
                r#"{
                    "rid": 15,
                    "peers": {
                        "10.0.0.11:51414": {
                            "client": " qBittorrent/5.0.0 ",
                            "ip": "10.0.0.11",
                            "port": 51414,
                            "progress": 1.2,
                            "dl_speed": 0,
                            "up_speed": 32768
                        },
                        "10.0.0.10:51413": {
                            "client": "",
                            "ip": "10.0.0.10",
                            "port": 51413,
                            "progress": -0.2,
                            "dl_speed": 0,
                            "up_speed": 16384
                        }
                    }
                }"#,
            )
            .unwrap();

        assert_eq!(
            peers
                .iter()
                .map(|peer| peer.observation_id.clone())
                .collect::<Vec<_>>(),
            vec![
                PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.10".parse().unwrap(),
                    peer_port: 51413,
                },
                PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.11".parse().unwrap(),
                    peer_port: 51414,
                },
            ]
        );
        assert_eq!(peers[0].peer.progress, 0.0);
        assert_eq!(peers[0].peer.up_rate_bps, 16384);
        assert_eq!(peers[0].client_name, None);
        assert_eq!(peers[1].peer.progress, 1.0);
        assert_eq!(peers[1].peer.up_rate_bps, 32768);
        assert_eq!(peers[1].client_name.as_deref(), Some("qBittorrent/5.0.0"));
    }

    #[test]
    fn rejects_invalid_peer_ip_during_normalization() {
        let client = test_client();
        let error = client
            .normalize_torrent_peers(
                "abc123",
                r#"{
                    "rid": 15,
                    "peers": {
                        "not-an-ip:51413": {
                            "client": "qBittorrent/5.0.0",
                            "ip": "not-an-ip",
                            "port": 51413,
                            "progress": 0.42,
                            "dl_speed": 32768,
                            "up_speed": 65536
                        }
                    }
                }"#,
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("invalid peer ip `not-an-ip`"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_mismatched_peer_key_during_normalization() {
        let client = test_client();
        let error = client
            .normalize_torrent_peers(
                "abc123",
                r#"{
                    "rid": 15,
                    "peers": {
                        "10.0.0.10:51413": {
                            "client": "qBittorrent/5.0.0",
                            "ip": "10.0.0.11",
                            "port": 51413,
                            "progress": 0.42,
                            "dl_speed": 32768,
                            "up_speed": 65536
                        }
                    }
                }"#,
            )
            .unwrap_err();

        assert!(
            error.to_string().contains(
                "peer key `10.0.0.10:51413` does not match body endpoint `10.0.0.11:51413`"
            ),
            "{error:#}"
        );
    }

    #[test]
    fn parses_peer_keys_when_qbittorrent_uses_socket_addresses() {
        assert_eq!(
            parse_peer_key("10.0.0.10:51413"),
            Some("10.0.0.10:51413".parse().unwrap())
        );
        assert_eq!(
            parse_peer_key("[2001:db8::1]:51413"),
            Some("[2001:db8::1]:51413".parse().unwrap())
        );
        assert_eq!(parse_peer_key("not-a-socket"), None);
    }

    #[test]
    fn encodes_ban_peers_and_banned_ip_preferences() {
        let client = test_client();

        assert_eq!(
            client.encode_ban_peers(&[
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 51413),
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)), 51414),
            ]),
            "10.0.0.10:51413|10.0.0.11:51414"
        );

        assert_eq!(
            client
                .encode_banned_ips_preferences(&[
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
                ])
                .unwrap(),
            r#"{"banned_IPs":"10.0.0.10\n10.0.0.11"}"#
        );
    }

    #[test]
    fn deduplicates_and_sorts_managed_banned_ips() {
        let client = test_client();

        assert_eq!(
            client.managed_banned_ips([
                &active_ban("10.0.0.11", 51414, "torrent:def456"),
                &active_ban("10.0.0.10", 51413, "torrent:abc123"),
                &active_ban("10.0.0.10", 51415, "torrent:ghi789"),
            ]),
            vec![
                "10.0.0.10".parse::<IpAddr>().unwrap(),
                "10.0.0.11".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    fn test_client() -> QbittorrentClient {
        scoped_test_client(FiltersConfig::default())
    }

    fn scoped_test_client(filters: FiltersConfig) -> QbittorrentClient {
        QbittorrentClient::new(
            QbittorrentConfig {
                base_url: "http://qbittorrent:8080/".to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: std::time::Duration::from_secs(30),
                request_timeout: std::time::Duration::from_secs(10),
            },
            "secret".to_string(),
            filters,
            3,
            std::time::Duration::from_secs(10),
        )
        .unwrap()
    }

    fn torrent_summary(
        hash: &str,
        category: Option<&str>,
        tags: &[&str],
        total_seeders: u32,
    ) -> TorrentSummary {
        TorrentSummary {
            hash: hash.to_string(),
            name: format!("torrent-{hash}"),
            total_seeders,
            category: category.map(str::to_string),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn authenticate_posts_credentials_and_accepts_ok_response() {
        let (base_url, server) = spawn_server(vec![ExpectedRequest {
            method: "POST",
            path: "/api/v2/auth/login",
            must_contain: vec!["username=admin", "password=secret"],
            response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
        }])
        .await;

        let client = network_test_client(&base_url);
        client.authenticate().await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_requests_retry_after_login_and_reuse_cookie() {
        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/version",
                must_contain: vec![],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/version",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n5.0.4",
            },
        ])
        .await;

        let client = network_test_client(&base_url);
        let version = client
            .authenticated_get_text(client.api_url(APP_VERSION_PATH).unwrap())
            .await
            .unwrap();
        assert_eq!(version, "5.0.4");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn list_in_scope_torrents_requests_seeding_filter_and_applies_scope_rules() {
        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"a\",\"name\":\"Allowed category\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5},{\"hash\":\"b\",\"name\":\"Allowed tag\",\"category\":\"music\",\"tags\":\" keep ,misc \",\"num_complete\":6},{\"hash\":\"c\",\"name\":\"Excluded category\",\"category\":\"linux\",\"tags\":\"keep\",\"num_complete\":6},{\"hash\":\"d\",\"name\":\"Excluded tag\",\"category\":\"tv\",\"tags\":\"skip\",\"num_complete\":6},{\"hash\":\"e\",\"name\":\"Too small\",\"category\":\"tv\",\"tags\":\"keep\",\"num_complete\":2}]",
            },
        ])
        .await;

        let client = network_scoped_test_client(
            &base_url,
            FiltersConfig {
                include_categories: vec!["tv".to_string()],
                exclude_categories: vec!["linux".to_string()],
                include_tags: vec!["keep".to_string()],
                exclude_tags: vec!["skip".to_string()],
                allowlist_peer_ips: vec![],
                allowlist_peer_cidrs: vec![],
            },
        );
        let torrents = client.list_in_scope_torrents().await.unwrap();

        assert_eq!(
            torrents
                .into_iter()
                .map(|torrent| torrent.hash)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "b".to_string()]
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn list_torrent_peers_requests_sync_endpoint_and_normalizes_peers() {
        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec![],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51413\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51413,\"progress\":0.42,\"dl_speed\":32768,\"up_speed\":65536},\"10.0.0.11:51414\":{\"client\":\"\",\"ip\":\"10.0.0.11\",\"port\":51414,\"progress\":0.9,\"dl_speed\":1024,\"up_speed\":2048}},\"peers_removed\":[]}",
            },
        ])
        .await;

        let client = network_test_client(&base_url);
        let peers = client.list_torrent_peers("abc123").await.unwrap();

        assert_eq!(
            peers
                .iter()
                .map(|peer| peer.observation_id.clone())
                .collect::<Vec<_>>(),
            vec![
                PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.10".parse().unwrap(),
                    peer_port: 51413,
                },
                PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.11".parse().unwrap(),
                    peer_port: 51414,
                },
            ]
        );
        assert_eq!(peers[0].client_name.as_deref(), Some("qBittorrent/5.0.0"));
        assert_eq!(peers[1].client_name, None);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn apply_peer_ban_posts_endpoint_ban_and_syncs_preferences() {
        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["cookie: SID=abc", "peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["cookie: SID=abc", "json=", "10.0.0.10", "10.0.0.11"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
        ])
        .await;

        let client = network_test_client(&base_url);
        let ban = active_ban("10.0.0.10", 51413, "torrent:abc123");
        let result = client
            .apply_peer_ban(
                &ban,
                &[
                    ban.clone(),
                    active_ban("10.0.0.11", 51414, "torrent:def456"),
                    active_ban("10.0.0.10", 51415, "torrent:ghi789"),
                ],
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            BanSyncResult {
                banned_ips: vec![
                    "10.0.0.10".parse::<IpAddr>().unwrap(),
                    "10.0.0.11".parse::<IpAddr>().unwrap(),
                ],
            }
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn reconcile_expired_bans_syncs_remaining_managed_ips() {
        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json="],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["cookie: SID=abc", "json=", "10.0.0.11", "10.0.0.12"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
        ])
        .await;

        let client = network_test_client(&base_url);
        let result = client
            .reconcile_expired_bans(&[
                active_ban("10.0.0.12", 51416, "torrent:xyz999"),
                active_ban("10.0.0.11", 51414, "torrent:def456"),
                active_ban("10.0.0.11", 51415, "torrent:ghi789"),
            ])
            .await
            .unwrap();

        assert_eq!(
            result,
            BanSyncResult {
                banned_ips: vec![
                    "10.0.0.11".parse::<IpAddr>().unwrap(),
                    "10.0.0.12".parse::<IpAddr>().unwrap(),
                ],
            }
        );

        server.await.unwrap();
    }

    #[derive(Clone)]
    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        must_contain: Vec<&'static str>,
        response: &'static str,
    }

    async fn spawn_server(
        expected_requests: Vec<ExpectedRequest>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for expected in expected_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut stream).await.unwrap();
                assert!(request.starts_with(&format!("{} {} ", expected.method, expected.path)));
                for needle in expected.must_contain {
                    assert!(
                        request.contains(needle),
                        "request missing `{needle}`: {request}"
                    );
                }
                stream
                    .write_all(expected.response.as_bytes())
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        (format!("http://{address}/"), handle)
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> io::Result<String> {
        let mut buffer = Vec::new();
        let mut header = [0_u8; 1024];
        loop {
            let read = stream.read(&mut header).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&header[..read]);
            if let Some(request) = complete_request(&buffer) {
                return Ok(request);
            }
        }
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    fn complete_request(buffer: &[u8]) -> Option<String> {
        let marker = b"\r\n\r\n";
        let header_end = buffer
            .windows(marker.len())
            .position(|window| window == marker)?;
        let header_end = header_end + marker.len();
        let request = String::from_utf8_lossy(buffer).to_string();
        let content_length = request
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if buffer.len() >= header_end + content_length {
            Some(request)
        } else {
            None
        }
    }

    fn network_test_client(base_url: &str) -> QbittorrentClient {
        network_scoped_test_client(base_url, FiltersConfig::default())
    }

    fn network_scoped_test_client(base_url: &str, filters: FiltersConfig) -> QbittorrentClient {
        QbittorrentClient::new(
            QbittorrentConfig {
                base_url: base_url.to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: std::time::Duration::from_secs(30),
                request_timeout: std::time::Duration::from_secs(10),
            },
            "secret".to_string(),
            filters,
            3,
            std::time::Duration::from_secs(10),
        )
        .unwrap()
    }

    fn active_ban(peer_ip: &str, peer_port: u16, scope: &str) -> ActiveBanRecord {
        ActiveBanRecord {
            peer_ip: peer_ip.parse().unwrap(),
            peer_port,
            scope: scope.to_string(),
            offence_number: 1,
            reason: "slow_non_progressing".to_string(),
            created_at: std::time::UNIX_EPOCH,
            expires_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(3600),
            reconciled_at: None,
        }
    }
}
