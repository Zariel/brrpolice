use std::sync::Arc;

use anyhow::Result;
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::info;

use crate::{
    config::AppConfig, metrics::AppMetrics, persistence::Persistence, runtime::ServiceState,
};

#[derive(Clone)]
struct HttpState {
    metrics: Arc<AppMetrics>,
    persistence: Arc<Persistence>,
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
        service_state: Arc<ServiceState>,
        metrics: Arc<AppMetrics>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            state: HttpState {
                metrics,
                persistence,
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

    let ready = failing_gates.is_empty();
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
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use axum::{
        Router,
        body::{self, Body},
        http::{Request, StatusCode, header},
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    use crate::{
        config::DatabaseConfig, metrics::AppMetrics, persistence::Persistence,
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

    async fn test_router() -> Router {
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

        build_router(HttpState {
            metrics,
            persistence,
            service_state,
        })
    }
}
