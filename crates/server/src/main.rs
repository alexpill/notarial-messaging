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

    // The server holds no Root LRA. Bootstrap is the operator's job: run
    // `demo-cli scenario` (or a dedicated bootstrap command) which seeds a
    // Root LRA directly in SQLite and enrolls the first notaire. The EN's
    // job stops at storing `(SN, SI, pk, lra_id)` — no LRA key lives here.

    let state = Arc::new(state::AppState::new(pool, hsm, config.clone())?);
    let app = routes::build_router(state);

    let addr = format!("{}:{}", config.server_host, config.server_port);
    tracing::info!("server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
