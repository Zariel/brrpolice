use std::{net::IpAddr, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use humantime::format_rfc3339_seconds;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{error, info};

use crate::{
    config::AppConfig,
    metrics::AppMetrics,
    persistence::{ActiveBanRecord, Persistence},
    qbittorrent::QbittorrentClient,
    runtime::ServiceState,
};

#[derive(Clone)]
struct HttpState {
    metrics: Arc<AppMetrics>,
    persistence: Arc<Persistence>,
    qbittorrent: Arc<QbittorrentClient>,
    service_state: Arc<ServiceState>,
}

pub struct HttpServer {
    config: Arc<AppConfig>,
    state: HttpState,
    shutdown: watch::Receiver<bool>,
}

impl HttpServer {
    pub fn new(
        config: Arc<AppConfig>,
        persistence: Arc<Persistence>,
        qbittorrent: Arc<QbittorrentClient>,
        service_state: Arc<ServiceState>,
        metrics: Arc<AppMetrics>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            state: HttpState {
                metrics,
                persistence,
                qbittorrent,
                service_state,
            },
            shutdown,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let app = build_router(self.state);
        let bind_addr = self.config.http.bind_addr()?;
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        info!(%bind_addr, "http server listening");
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = self.shutdown.changed().await;
            })
            .await?;
        Ok(())
    }
}

fn build_router(state: HttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/admin/state", get(admin_state))
        .route("/admin/bans", delete(clear_all_bans))
        .route("/admin/bans/{peer_ip}/{peer_port}", delete(clear_ban))
        .with_state(state)
}

#[derive(Serialize)]
struct ReadinessGates {
    live: bool,
    shutting_down: bool,
    persistence_ready: bool,
    database_ready: bool,
    qbittorrent_ready: bool,
    recovery_complete: bool,
    poll_loop_entered: bool,
    runtime_healthy: bool,
}

#[derive(Serialize)]
struct ReadinessResponse {
    ready: bool,
    message: String,
    failing_gates: Vec<&'static str>,
    gates: ReadinessGates,
}

#[derive(Serialize)]
struct AdminStateResponse {
    ready: bool,
    gates: ReadinessGates,
    active_ban_count: usize,
    pending_ban_intent_count: usize,
    active_bans: Vec<ActiveBanView>,
}

#[derive(Serialize)]
struct ActiveBanView {
    peer_ip: IpAddr,
    peer_port: u16,
    scope: String,
    offence_number: u32,
    reason: String,
    created_at: String,
    expires_at: String,
    reconciled_at: Option<String>,
}

#[derive(Deserialize)]
struct ClearBanQuery {
    scope: String,
}

#[derive(Serialize)]
struct ClearBanResponse {
    cleared: bool,
    peer_ip: IpAddr,
    peer_port: u16,
    scope: String,
    active_ban_count: usize,
    managed_banned_ip_count: usize,
}

#[derive(Serialize)]
struct ClearAllBansResponse {
    cleared_count: usize,
    active_ban_count: usize,
    managed_banned_ip_count: usize,
}

async fn healthz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.service_state.is_live() {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "shutting down")
    }
}

async fn readyz(State(state): State<HttpState>) -> impl IntoResponse {
    let persistence_ready = state.persistence.is_ready().await;
    let gates = ReadinessGates {
        live: state.service_state.is_live(),
        shutting_down: state.service_state.is_shutting_down(),
        persistence_ready,
        database_ready: state.service_state.is_database_ready(),
        qbittorrent_ready: state.service_state.is_qbittorrent_ready(),
        recovery_complete: state.service_state.is_recovery_complete(),
        poll_loop_entered: state.service_state.is_poll_loop_entered(),
        runtime_healthy: state.service_state.is_runtime_healthy(),
    };
    let mut failing_gates = Vec::new();
    if !gates.live {
        failing_gates.push("live");
    }
    if gates.shutting_down {
        failing_gates.push("shutting_down");
    }
    if !gates.persistence_ready {
        failing_gates.push("persistence_ready");
    }
    if !gates.database_ready {
        failing_gates.push("database_ready");
    }
    if !gates.qbittorrent_ready {
        failing_gates.push("qbittorrent_ready");
    }
    if !gates.recovery_complete {
        failing_gates.push("recovery_complete");
    }
    if !gates.poll_loop_entered {
        failing_gates.push("poll_loop_entered");
    }
    if !gates.runtime_healthy {
        failing_gates.push("runtime_healthy");
    }

    let ready = state.service_state.is_ready() && persistence_ready;
    let message = if ready {
        "ready".to_string()
    } else {
        format!("not ready: {}", failing_gates.join(", "))
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            ready,
            message,
            failing_gates,
            gates,
        }),
    )
}

async fn metrics(State(state): State<HttpState>) -> Response {
    metrics_response(&state.metrics, state.metrics.render())
}

async fn admin_state(State(state): State<HttpState>) -> impl IntoResponse {
    let persistence_ready = state.persistence.is_ready().await;
    let gates = ReadinessGates {
        live: state.service_state.is_live(),
        shutting_down: state.service_state.is_shutting_down(),
        persistence_ready,
        database_ready: state.service_state.is_database_ready(),
        qbittorrent_ready: state.service_state.is_qbittorrent_ready(),
        recovery_complete: state.service_state.is_recovery_complete(),
        poll_loop_entered: state.service_state.is_poll_loop_entered(),
        runtime_healthy: state.service_state.is_runtime_healthy(),
    };

    let now = SystemTime::now();
    let all_bans = match state.persistence.load_active_bans().await {
        Ok(bans) => bans,
        Err(error) => {
            error!(?error, "failed to load active bans for admin state");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to load active bans"
                })),
            )
                .into_response();
        }
    };
    let active_bans = managed_active_bans(&all_bans, now);
    let pending_ban_intent_count = match state.persistence.load_pending_ban_intents().await {
        Ok(intents) => intents.len(),
        Err(error) => {
            error!(?error, "failed to load pending ban intents for admin state");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to load pending ban intents"
                })),
            )
                .into_response();
        }
    };

    let response = AdminStateResponse {
        ready: state.service_state.is_ready() && persistence_ready,
        gates,
        active_ban_count: active_bans.len(),
        pending_ban_intent_count,
        active_bans: active_bans.into_iter().map(active_ban_view).collect(),
    };
    (StatusCode::OK, Json(response)).into_response()
}

async fn clear_ban(
    State(state): State<HttpState>,
    Path((peer_ip, peer_port)): Path<(IpAddr, u16)>,
    Query(query): Query<ClearBanQuery>,
) -> impl IntoResponse {
    if query.scope.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "scope query parameter is required"
            })),
        )
            .into_response();
    }

    let now = SystemTime::now();
    let all_bans = match state.persistence.load_active_bans().await {
        Ok(bans) => bans,
        Err(error) => {
            error!(?error, "failed to load active bans for clear ban");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to load active bans"
                })),
            )
                .into_response();
        }
    };

    let previous_managed = managed_active_bans(&all_bans, now);
    if !all_bans.iter().any(|ban| {
        ban.peer_ip == peer_ip
            && ban.peer_port == peer_port
            && ban.scope == query.scope
            && ban.reconciled_at.is_none()
    }) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "active ban not found"
            })),
        )
            .into_response();
    }
    let remaining_managed = previous_managed
        .iter()
        .filter(|ban| {
            !(ban.peer_ip == peer_ip && ban.peer_port == peer_port && ban.scope == query.scope)
        })
        .cloned()
        .collect::<Vec<_>>();

    let sync_result = match state
        .qbittorrent
        .reconcile_expired_bans(&remaining_managed, &previous_managed)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            error!(?error, "failed to reconcile qbittorrent bans for clear ban");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "failed to reconcile qbittorrent ban list"
                })),
            )
                .into_response();
        }
    };

    match state
        .persistence
        .mark_active_ban_reconciled(peer_ip, peer_port, &query.scope, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "active ban changed concurrently; retry request"
                })),
            )
                .into_response();
        }
        Err(error) => {
            error!(?error, "failed to persist clear ban");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to update active ban state"
                })),
            )
                .into_response();
        }
    }

    let active_ban_count = match state.persistence.count_active_bans().await {
        Ok(count) => count,
        Err(error) => {
            error!(?error, "failed to refresh active ban count");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ban cleared but failed to refresh active ban count"
                })),
            )
                .into_response();
        }
    };
    state.metrics.set_active_bans(active_ban_count);

    (
        StatusCode::OK,
        Json(ClearBanResponse {
            cleared: true,
            peer_ip,
            peer_port,
            scope: query.scope,
            active_ban_count,
            managed_banned_ip_count: sync_result.banned_ips.len(),
        }),
    )
        .into_response()
}

async fn clear_all_bans(State(state): State<HttpState>) -> impl IntoResponse {
    let now = SystemTime::now();
    let all_bans = match state.persistence.load_active_bans().await {
        Ok(bans) => bans,
        Err(error) => {
            error!(?error, "failed to load active bans for clear all");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to load active bans"
                })),
            )
                .into_response();
        }
    };
    let previous_managed = managed_active_bans(&all_bans, now);
    let pending_clear = all_bans
        .into_iter()
        .filter(|ban| ban.reconciled_at.is_none())
        .collect::<Vec<_>>();

    let sync_result = match state
        .qbittorrent
        .reconcile_expired_bans(&[], &previous_managed)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            error!(?error, "failed to reconcile qbittorrent bans for clear all");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "failed to reconcile qbittorrent ban list"
                })),
            )
                .into_response();
        }
    };

    for ban in &pending_clear {
        if let Err(error) = state
            .persistence
            .mark_active_ban_reconciled(ban.peer_ip, ban.peer_port, &ban.scope, now)
            .await
        {
            error!(
                ?error,
                peer_ip = %ban.peer_ip,
                peer_port = ban.peer_port,
                scope = %ban.scope,
                "failed to persist clear all ban"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "failed to update active ban state"
                })),
            )
                .into_response();
        }
    }

    let active_ban_count = match state.persistence.count_active_bans().await {
        Ok(count) => count,
        Err(error) => {
            error!(?error, "failed to refresh active ban count after clear all");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "bans cleared but failed to refresh active ban count"
                })),
            )
                .into_response();
        }
    };
    state.metrics.set_active_bans(active_ban_count);

    (
        StatusCode::OK,
        Json(ClearAllBansResponse {
            cleared_count: pending_clear.len(),
            active_ban_count,
            managed_banned_ip_count: sync_result.banned_ips.len(),
        }),
    )
        .into_response()
}

fn managed_active_bans(records: &[ActiveBanRecord], as_of: SystemTime) -> Vec<ActiveBanRecord> {
    records
        .iter()
        .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at > as_of)
        .cloned()
        .collect()
}

fn active_ban_view(record: ActiveBanRecord) -> ActiveBanView {
    ActiveBanView {
        peer_ip: record.peer_ip,
        peer_port: record.peer_port,
        scope: record.scope,
        offence_number: record.offence_number,
        reason: record.reason,
        created_at: format_rfc3339_seconds(record.created_at).to_string(),
        expires_at: format_rfc3339_seconds(record.expires_at).to_string(),
        reconciled_at: record
            .reconciled_at
            .map(|time| format_rfc3339_seconds(time).to_string()),
    }
}

fn metrics_response(metrics: &AppMetrics, rendered: Result<String, std::fmt::Error>) -> Response {
    let (status, body) = match rendered {
        Ok(body) => (StatusCode::OK, body),
        Err(_) => {
            metrics.record_metrics_encode_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "# metrics encoding failed\n".to_string(),
            )
        }
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use axum::{
        Router,
        body::{self, Body},
        http::{Request, StatusCode, header},
    };
    use secrecy::SecretString;
    use serde_json::Value;
    use tower::util::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    use crate::{
        config::{DatabaseConfig, FiltersConfig, QbittorrentConfig},
        metrics::AppMetrics,
        persistence::{ActiveBanRecord, Persistence},
        qbittorrent::QbittorrentClient,
        runtime::ServiceState,
    };

    use super::{HttpState, build_router, metrics_response};

    #[tokio::test]
    async fn healthz_is_ok_when_service_is_live() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_service_unavailable_when_not_ready() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.get("ready").and_then(Value::as_bool), Some(false));
        assert!(
            payload
                .get("failing_gates")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| item == "database_ready")
                        && items.iter().any(|item| item == "qbittorrent_ready")
                        && items.iter().any(|item| item == "recovery_complete")
                        && items.iter().any(|item| item == "poll_loop_entered")
                })
        );
    }

    #[tokio::test]
    async fn readyz_returns_gate_diagnostics_when_ready() {
        let persistence = Arc::new(
            Persistence::connect(&DatabaseConfig {
                path: PathBuf::from(":memory:"),
                busy_timeout: Duration::from_secs(1),
            })
            .await
            .unwrap(),
        );
        persistence.run_migrations().await.unwrap();

        let service_state = Arc::new(ServiceState::new());
        service_state.mark_database_ready();
        service_state.mark_qbittorrent_ready();
        service_state.mark_recovery_complete();
        service_state.mark_poll_loop_entered();

        let app = build_router(HttpState {
            metrics: Arc::new(AppMetrics::new()),
            persistence,
            qbittorrent: test_qbittorrent_client("http://127.0.0.1:1"),
            service_state,
        });

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.get("ready").and_then(Value::as_bool), Some(true));
        assert_eq!(
            payload.get("message").and_then(Value::as_str),
            Some("ready")
        );
        assert_eq!(
            payload
                .get("failing_gates")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_content_type() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("# TYPE brrpolice_active_bans gauge"));
        assert!(body.contains("brrpolice_peers_evaluated"));
    }

    #[test]
    fn metrics_returns_500_and_records_counter_when_encoding_fails() {
        let metrics = AppMetrics::new();
        let response = metrics_response(&metrics, Err(std::fmt::Error));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("brrpolice_metrics_encode_errors_total 1"));
    }

    #[tokio::test]
    async fn admin_state_returns_active_ban_snapshot() {
        let (app, persistence) = test_router_with_qb("http://127.0.0.1:1").await;
        let now = SystemTime::now();
        persistence
            .upsert_active_ban(&active_ban(
                "10.0.0.10",
                51413,
                "torrent:abc123",
                now - Duration::from_secs(60),
                now + Duration::from_secs(3600),
            ))
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload.get("active_ban_count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            payload
                .get("pending_ban_intent_count")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            payload["active_bans"][0]["scope"].as_str(),
            Some("torrent:abc123")
        );
    }

    #[tokio::test]
    async fn clear_ban_reconciles_qb_and_marks_ban_reconciled() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/app/preferences"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"banned_IPs":"10.0.0.10\n10.0.0.11\n198.51.100.0/24"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/app/setPreferences"))
            .and(body_string_contains("10.0.0.11"))
            .and(body_string_contains("198.51.100.0%2F24"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let (app, persistence) = test_router_with_qb(&server.uri()).await;
        let now = SystemTime::now();
        persistence
            .upsert_active_ban(&active_ban(
                "10.0.0.10",
                51413,
                "torrent:abc123",
                now - Duration::from_secs(60),
                now + Duration::from_secs(3600),
            ))
            .await
            .unwrap();
        persistence
            .upsert_active_ban(&active_ban(
                "10.0.0.11",
                51414,
                "torrent:def456",
                now - Duration::from_secs(30),
                now + Duration::from_secs(3600),
            ))
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/bans/10.0.0.10/51413?scope=torrent%3Aabc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.get("cleared").and_then(Value::as_bool), Some(true));
        assert_eq!(
            payload.get("active_ban_count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            payload
                .get("managed_banned_ip_count")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(persistence.count_active_bans().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn clear_all_bans_reconciles_qb_and_marks_all_reconciled() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/app/preferences"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"banned_IPs":"10.0.0.10\n10.0.0.11\n198.51.100.0/24"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/app/setPreferences"))
            .and(body_string_contains("198.51.100.0%2F24"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let (app, persistence) = test_router_with_qb(&server.uri()).await;
        let now = SystemTime::now();
        persistence
            .upsert_active_ban(&active_ban(
                "10.0.0.10",
                51413,
                "torrent:abc123",
                now - Duration::from_secs(60),
                now + Duration::from_secs(3600),
            ))
            .await
            .unwrap();
        persistence
            .upsert_active_ban(&active_ban(
                "10.0.0.11",
                51414,
                "torrent:def456",
                now - Duration::from_secs(30),
                now + Duration::from_secs(3600),
            ))
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/bans")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload.get("cleared_count").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            payload.get("active_ban_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            payload
                .get("managed_banned_ip_count")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(persistence.count_active_bans().await.unwrap(), 0);
    }

    async fn test_router() -> Router {
        test_router_with_qb("http://127.0.0.1:1").await.0
    }

    async fn test_router_with_qb(base_url: &str) -> (Router, Arc<Persistence>) {
        let persistence = Arc::new(
            Persistence::connect(&DatabaseConfig {
                path: PathBuf::from(":memory:"),
                busy_timeout: Duration::from_secs(1),
            })
            .await
            .unwrap(),
        );
        persistence.run_migrations().await.unwrap();
        let service_state = Arc::new(ServiceState::new());
        let metrics = Arc::new(AppMetrics::new());
        let qbittorrent = test_qbittorrent_client(base_url);

        (
            build_router(HttpState {
                metrics,
                persistence: persistence.clone(),
                qbittorrent,
                service_state,
            }),
            persistence,
        )
    }

    fn test_qbittorrent_client(base_url: &str) -> Arc<QbittorrentClient> {
        let mut config = QbittorrentConfig::default();
        config.base_url = base_url.to_string();
        config.request_timeout = Duration::from_secs(1);
        config.poll_interval = Duration::from_secs(1);
        Arc::new(
            QbittorrentClient::new(
                config,
                SecretString::from(String::new()),
                FiltersConfig::default(),
                0,
                Duration::from_secs(1),
                Arc::new(AppMetrics::new()),
            )
            .unwrap(),
        )
    }

    fn active_ban(
        peer_ip: &str,
        peer_port: u16,
        scope: &str,
        created_at: SystemTime,
        expires_at: SystemTime,
    ) -> ActiveBanRecord {
        ActiveBanRecord {
            peer_ip: peer_ip.parse().unwrap(),
            peer_port,
            scope: scope.to_string(),
            offence_number: 1,
            reason: "slow_non_progressing".to_string(),
            created_at,
            expires_at,
            reconciled_at: None,
        }
    }
}
