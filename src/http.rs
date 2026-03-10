use std::sync::Arc;

use anyhow::Result;
use axum::{Router, extract::State, response::IntoResponse, routing::get};
use tracing::info;

use crate::{config::AppConfig, persistence::Persistence};

#[derive(Clone)]
struct HttpState {
    persistence: Arc<Persistence>,
}

pub struct HttpServer {
    config: Arc<AppConfig>,
    state: HttpState,
}

impl HttpServer {
    pub fn new(config: Arc<AppConfig>, persistence: Arc<Persistence>) -> Self {
        Self {
            config,
            state: HttpState { persistence },
        }
    }

    pub async fn run(self) -> Result<()> {
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics))
            .with_state(self.state);

        let bind_addr = self.config.http.bind_addr()?;
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        info!(%bind_addr, "http server listening");
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn healthz() -> impl IntoResponse {
    "ok"
}

async fn readyz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.persistence.is_ready().await {
        "ready"
    } else {
        "not ready"
    }
}

async fn metrics() -> impl IntoResponse {
    "# metrics exporter not wired yet\n"
}
