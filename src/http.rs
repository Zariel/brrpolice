use std::sync::Arc;

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
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

async fn healthz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.service_state.is_live() {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "shutting down")
    }
}

async fn readyz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.service_state.is_ready()
        && !state.service_state.is_shutting_down()
        && state.persistence.is_ready().await
    {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics(State(state): State<HttpState>) -> Response {
    let body = state
        .metrics
        .render()
        .unwrap_or_else(|_| "# metrics encoding failed\n".to_string());
    let mut response = Response::new(Body::from(body));
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
    use tower::util::ServiceExt;

    use crate::{
        config::DatabaseConfig, metrics::AppMetrics, persistence::Persistence,
        runtime::ServiceState,
    };

    use super::{HttpState, build_router};

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
