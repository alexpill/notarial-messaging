use std::sync::Arc;

mod config;
mod db;
mod en;
mod error;
mod hsm;
mod middleware;
mod routes;
mod state;
mod utils;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = config::AppConfig::from_env()?;
    let pool = db::init_pool(&config.database_url)?;
    let hsm = hsm::HsmSimulator::from_env()?;

    // The notaire enrollment token is the EN's bootstrap authority to designate
    // notaires (POST /enroll/notaire). Printed once here — in dev it's the fixed
    // value from .env; in prod it's a random per-boot operator secret.
    tracing::info!(
        "Notaire enrollment token (POST /enroll/notaire): {}",
        config.notaire_enrollment_token
    );

    let state = Arc::new(state::AppState::new(pool, hsm, config.clone())?);
    let app = routes::build_router(state);

    let addr = format!("{}:{}", config.server_host, config.server_port);
    tracing::info!("server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
