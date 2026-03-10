use std::{collections::HashMap, env, net::IpAddr, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use tracing::debug;

use crate::{config::QbittorrentConfig, types::TorrentSummary};

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
    client: Client,
    base_url: Url,
}

impl QbittorrentClient {
    pub fn new(config: QbittorrentConfig, timeout: Duration) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).context("invalid qbittorrent.base_url")?;
        let client = Client::builder()
            .cookie_store(true)
            .timeout(timeout)
            .build()?;

        Ok(Self {
            config,
            client,
            base_url,
        })
    }

    pub async fn authenticate(&self) -> Result<()> {
        let password = env::var(&self.config.password_env).with_context(|| {
            format!(
                "missing qbittorrent password env `{}`",
                self.config.password_env
            )
        })?;
        let response = self
            .client
            .post(self.api_url(AUTH_LOGIN_PATH)?)
            .form(&[
                ("username", self.config.username.as_str()),
                ("password", password.as_str()),
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
        Ok(Vec::new())
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

    fn parse_torrent_peers(&self, body: &str) -> Result<QbTorrentPeersResponse> {
        serde_json::from_str(body).context("invalid torrent peers payload")
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
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        env, io,
        net::{IpAddr, Ipv4Addr},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        APP_PREFERENCES_PATH, APP_VERSION_PATH, AUTH_LOGIN_PATH, QbPeer, QbTorrentPeersResponse,
        QbittorrentClient, SYNC_TORRENT_PEERS_PATH, TORRENTS_INFO_PATH, TRANSFER_BAN_PEERS_PATH,
        WEBAPI_VERSION_PATH,
    };
    use crate::config::QbittorrentConfig;

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

    fn test_client() -> QbittorrentClient {
        QbittorrentClient::new(
            QbittorrentConfig {
                base_url: "http://qbittorrent:8080/".to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: std::time::Duration::from_secs(30),
                request_timeout: std::time::Duration::from_secs(10),
            },
            std::time::Duration::from_secs(10),
        )
        .unwrap()
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
        let previous = env::var_os("QBITTORRENT_PASSWORD");
        unsafe { env::set_var("QBITTORRENT_PASSWORD", "secret") };

        let client = network_test_client(&base_url);
        client.authenticate().await.unwrap();

        restore_env("QBITTORRENT_PASSWORD", previous);
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
        let previous = env::var_os("QBITTORRENT_PASSWORD");
        unsafe { env::set_var("QBITTORRENT_PASSWORD", "secret") };

        let client = network_test_client(&base_url);
        let version = client
            .authenticated_get_text(client.api_url(APP_VERSION_PATH).unwrap())
            .await
            .unwrap();
        assert_eq!(version, "5.0.4");

        restore_env("QBITTORRENT_PASSWORD", previous);
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
        QbittorrentClient::new(
            QbittorrentConfig {
                base_url: base_url.to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: std::time::Duration::from_secs(30),
                request_timeout: std::time::Duration::from_secs(10),
            },
            std::time::Duration::from_secs(10),
        )
        .unwrap()
    }

    fn restore_env(key: &str, previous: Option<std::ffi::OsString>) {
        if let Some(value) = previous {
            unsafe { env::set_var(key, value) };
        } else {
            unsafe { env::remove_var(key) };
        }
    }
}
