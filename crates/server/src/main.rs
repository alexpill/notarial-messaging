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

    let en_url = format!("http://{}:{}", config.server_host, config.server_port);
    let (root_lra_kp, root_lra_sn) = en::registry::seed_root_lra(&pool, &en_url).await?;
    tracing::info!("Root LRA seeded — SN: {}", root_lra_sn);

    let state = Arc::new(state::AppState::new(pool, hsm, config.clone(), root_lra_kp.signing_key, root_lra_sn)?);
    let app = routes::build_router(state);

    let addr = format!("{}:{}", config.server_host, config.server_port);
    tracing::info!("server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
