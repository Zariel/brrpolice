use std::{convert::Infallible, net::IpAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use humantime::parse_duration;
use serde::Deserialize;
use tokio::sync::watch;
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;

use crate::{
    config::{AppConfig, DebugPolicyTraceConfig},
    trace_publisher::{PolicyTracePublisher, SubscribeError, TraceSubscriptionFilter},
};

const NDJSON_CONTENT_TYPE: &str = "application/x-ndjson";

#[derive(Clone)]
struct DebugTraceState {
    config: DebugPolicyTraceConfig,
    publisher: Arc<PolicyTracePublisher>,
}

pub struct DebugTraceServer {
    config: Arc<AppConfig>,
    publisher: Arc<PolicyTracePublisher>,
    shutdown: watch::Receiver<bool>,
}

impl DebugTraceServer {
    pub fn new(
        config: Arc<AppConfig>,
        publisher: Arc<PolicyTracePublisher>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            publisher,
            shutdown,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let trace_config = self.config.debug.policy_trace.clone();
        if !trace_config.enabled {
            info!("debug policy trace endpoint disabled");
            let _ = self.shutdown.changed().await;
            return Ok(());
        }

        let bind_addr = trace_config.bind_addr()?;
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        info!(%bind_addr, "debug policy trace server listening");
        axum::serve(
            listener,
            build_router(trace_config, self.publisher).into_make_service(),
        )
        .with_graceful_shutdown(async move {
            let _ = self.shutdown.changed().await;
        })
        .await?;
        Ok(())
    }
}

fn build_router(config: DebugPolicyTraceConfig, publisher: Arc<PolicyTracePublisher>) -> Router {
    Router::new()
        .route("/debug/policy-trace/stream", get(stream_policy_trace))
        .with_state(DebugTraceState { config, publisher })
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    duration: Option<String>,
    peer_ip: Option<IpAddr>,
    torrent_hash: Option<String>,
    sample: Option<f64>,
    include_names: Option<bool>,
}

async fn stream_policy_trace(
    State(state): State<DebugTraceState>,
    Query(query): Query<StreamQuery>,
) -> Response {
    let options = match stream_options(&state.config, query) {
        Ok(options) => options,
        Err((status, message)) => return (status, message).into_response(),
    };
    let _include_names_requested = options.include_names;

    let subscription = match state.publisher.subscribe_with_filter(options.filter) {
        Ok(subscription) => subscription,
        Err(SubscribeError::Disabled) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "policy trace stream disabled",
            )
                .into_response();
        }
        Err(SubscribeError::ClientLimitReached { max_clients }) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                format!("policy trace client limit reached: max_clients={max_clients}"),
            )
                .into_response();
        }
    };

    let client_id = subscription.client_id;
    let publisher = state.publisher;
    let stream = ReceiverStream::new(subscription.receiver)
        .take_until(tokio::time::sleep(options.duration))
        .map(move |record| {
            let mut payload = String::new();
            if let Some(dropped_count) = publisher.take_dropped_for_client(client_id)
                && dropped_count > 0
            {
                payload.push_str(
                    &serde_json::json!({
                        "record_type": "dropped_records",
                        "schema_version": 1,
                        "client_id": client_id,
                        "dropped_count": dropped_count,
                    })
                    .to_string(),
                );
                payload.push('\n');
            }
            payload.push_str(&record);
            payload.push('\n');
            Ok::<Bytes, Infallible>(Bytes::from(payload))
        });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, NDJSON_CONTENT_TYPE)
        .body(Body::from_stream(stream))
        .expect("trace stream response is valid")
}

fn stream_duration(
    config: &DebugPolicyTraceConfig,
    query_duration: Option<&str>,
) -> std::result::Result<Duration, (StatusCode, String)> {
    let Some(raw_duration) = query_duration else {
        return Ok(config.max_duration);
    };
    let requested = parse_duration(raw_duration.trim()).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid duration query parameter: {error}"),
        )
    })?;
    if requested.is_zero() {
        return Err((
            StatusCode::BAD_REQUEST,
            "duration query parameter must be greater than zero".to_string(),
        ));
    }

    Ok(requested.min(config.max_duration))
}

struct StreamOptions {
    duration: Duration,
    filter: TraceSubscriptionFilter,
    include_names: bool,
}

fn stream_options(
    config: &DebugPolicyTraceConfig,
    query: StreamQuery,
) -> std::result::Result<StreamOptions, (StatusCode, String)> {
    let duration = stream_duration(config, query.duration.as_deref())?;
    let sample_rate = query.sample.unwrap_or(config.default_sample_rate);
    if !sample_rate.is_finite() || !(0.0..=1.0).contains(&sample_rate) {
        return Err((
            StatusCode::BAD_REQUEST,
            "sample query parameter must be between 0.0 and 1.0".to_string(),
        ));
    }

    Ok(StreamOptions {
        duration,
        filter: TraceSubscriptionFilter {
            peer_ip: query.peer_ip,
            torrent_hash: query
                .torrent_hash
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            sample_rate,
        },
        include_names: query.include_names.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::{Duration, UNIX_EPOCH},
    };

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    use crate::{
        config::DebugPolicyTraceConfig,
        policy_trace::{
            POLICY_TRACE_SCHEMA_VERSION, PolicyTraceRecord, PolicyTraceRecordType,
            TraceDecisionOutput, TraceGuardrailInputs, TraceOffenceHistory, TracePeer,
            TracePeerSessionState, TracePolicyInputs, TraceSimulatorHints, TraceTorrent,
            trace_timestamp,
        },
        trace_publisher::PolicyTracePublisher,
        types::{
            BanDisposition, OffenceIdentity, PeerEvaluation, PeerObservationId, PeerSessionState,
        },
    };

    #[tokio::test]
    async fn stream_returns_ndjson_records() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=50ms")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            super::NDJSON_CONTENT_TYPE
        );

        assert_eq!(
            publisher.publish(&sample_record()).unwrap(),
            crate::trace_publisher::PublishOutcome::Published {
                delivered: 1,
                dropped: 0
            }
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record: PolicyTraceRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(record.policy_trace_id, "debug-http-test");
    }

    #[tokio::test]
    async fn stream_enforces_client_limit() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let _held_client = publisher.subscribe().unwrap();
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn stream_filters_by_peer_ip() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=50ms&peer_ip=203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut other = sample_record();
        other.peer.ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)));
        publisher.publish(&other).unwrap();
        publisher.publish(&sample_record()).unwrap();

        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record: PolicyTraceRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            record.peer.ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
    }

    #[tokio::test]
    async fn stream_filters_by_torrent_hash() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=50ms&torrent_hash=torrent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut other = sample_record();
        other.torrent.hash = "other".to_string();
        publisher.publish(&other).unwrap();
        publisher.publish(&sample_record()).unwrap();

        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record: PolicyTraceRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(record.torrent.hash, "torrent");
    }

    #[tokio::test]
    async fn stream_sample_zero_filters_all_records() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let app = super::build_router(test_config(Duration::from_millis(20)), publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=20ms&sample=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        publisher.publish(&sample_record()).unwrap();

        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn stream_rejects_invalid_filter_queries() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?sample=1.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?peer_ip=not-an-ip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn stream_include_names_does_not_override_configured_redaction() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 4));
        let mut config = test_config(Duration::from_millis(50));
        config.redact_torrent_name = true;
        let app = super::build_router(config, publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=50ms&include_names=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut record = sample_record();
        record.torrent.name = None;
        publisher.publish(&record).unwrap();

        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let delivered: PolicyTraceRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(delivered.torrent.name, None);
    }

    #[tokio::test]
    async fn stream_reports_dropped_records_for_slow_clients() {
        let publisher = Arc::new(PolicyTracePublisher::new(true, 1, 1));
        let app = super::build_router(test_config(Duration::from_millis(50)), publisher.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/policy-trace/stream?duration=50ms")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let record = sample_record();
        assert_eq!(
            publisher.publish(&record).unwrap(),
            crate::trace_publisher::PublishOutcome::Published {
                delivered: 1,
                dropped: 0
            }
        );
        assert_eq!(
            publisher.publish(&record).unwrap(),
            crate::trace_publisher::PublishOutcome::Published {
                delivered: 0,
                dropped: 1
            }
        );

        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let notice: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(notice["record_type"], "dropped_records");
        assert_eq!(notice["schema_version"], 1);
        assert_eq!(notice["client_id"], 1);
        assert_eq!(notice["dropped_count"], 1);
        let delivered: PolicyTraceRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(delivered.policy_trace_id, "debug-http-test");
    }

    #[tokio::test]
    async fn duration_query_is_capped_by_config() {
        let config = test_config(Duration::from_millis(1));

        assert_eq!(
            super::stream_duration(&config, Some("10m")).unwrap(),
            Duration::from_millis(1)
        );
        assert!(super::stream_duration(&config, Some("0s")).is_err());
        assert!(super::stream_duration(&config, Some("not-a-duration")).is_err());
    }

    fn test_config(max_duration: Duration) -> DebugPolicyTraceConfig {
        DebugPolicyTraceConfig {
            enabled: true,
            max_duration,
            ..DebugPolicyTraceConfig::default()
        }
    }

    fn sample_record() -> PolicyTraceRecord {
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let session = PeerSessionState {
            observation_id: PeerObservationId {
                torrent_hash: "torrent".to_string(),
                peer_ip,
                peer_port: 51413,
            },
            offence_identity: OffenceIdentity {
                torrent_hash: "torrent".to_string(),
                peer_ip,
            },
            first_seen_at: observed_at - Duration::from_secs(60),
            last_seen_at: observed_at,
            baseline_progress: 0.1,
            latest_progress: 0.1,
            rolling_avg_up_rate_bps: 1024,
            observed_duration: Duration::from_secs(60),
            bad_duration: Duration::from_secs(30),
            ban_score: 0.5,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_amplifier: 0.0,
            sample_count: 1,
            last_torrent_seeder_count: 3,
            last_exemption_reason: None,
            bannable_since: None,
            last_ban_decision_at: None,
        };
        let evaluation = PeerEvaluation {
            session: session.clone(),
            progress_delta: 0.0,
            sample_duration: Duration::from_secs(60),
            sample_up_rate_bps: 1024,
            is_bad_sample: true,
            is_bannable: false,
            sample_score_risk: 0.8,
            effective_sample_score_risk: 0.8,
        };
        let policy = crate::config::PolicyConfig::default();

        PolicyTraceRecord {
            record_type: PolicyTraceRecordType::PeerObservation,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            observed_at: trace_timestamp(observed_at),
            service_version: "0.1.0-test".to_string(),
            policy_trace_id: "debug-http-test".to_string(),
            config_fingerprint: "fingerprint".to_string(),
            torrent: TraceTorrent {
                hash: "torrent".to_string(),
                name: None,
                tracker: None,
                total_size_bytes: None,
                category: None,
                tags: Vec::new(),
                total_seeders: 3,
                in_scope: true,
            },
            peer: TracePeer {
                ip: Some(peer_ip),
                port: 51413,
                progress: 0.1,
                up_rate_bps: 1024,
            },
            prior_session: None,
            evaluated_session: TracePeerSessionState::from(&session),
            policy_inputs: TracePolicyInputs::from(&policy),
            guardrail_inputs: TraceGuardrailInputs {
                exemption_reason: None,
                allowlisted_peer: false,
                active_ban: false,
                reban_cooldown_remaining_ms: None,
                offence_history: TraceOffenceHistory {
                    offence_count: 0,
                    last_ban_expires_at: None,
                },
            },
            decision_output: TraceDecisionOutput::from_evaluation_and_disposition(
                &evaluation,
                &BanDisposition::NotBannableYet {
                    observed_duration: Duration::from_secs(60),
                    required_observation: policy.score.min_observation_duration,
                    bad_duration: Duration::ZERO,
                    required_bad_duration: policy.score.sustain_duration,
                },
            ),
            simulator_hints: TraceSimulatorHints::from_evaluation(&evaluation, &policy),
        }
    }
}
