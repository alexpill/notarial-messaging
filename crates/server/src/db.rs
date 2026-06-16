// r2d2 + spawn_blocking instead of diesel-async: SQLite is single-writer and
// gains nothing from async I/O. r2d2 manages a synchronous connection pool;
// spawn_blocking offloads each query to Tokio's thread pool.

pub mod models;
pub mod schema;

use crate::error::AppError;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

pub fn init_pool(database_url: &str) -> Result<DbPool, AppError> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder()
        .max_size(5)
        .build(manager)
        .map_err(|e| AppError::Config(format!("failed to create DB pool: {e}")))?;

    // run_pending_migrations is idempotent — Diesel tracks applied migrations in __diesel_schema_migrations.
    let mut conn = pool.get()
        .map_err(|e| AppError::Database(e.to_string()))?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| AppError::Database(format!("migration failed: {e}")))?;

    tracing::info!("database initialized: {}", database_url);
    Ok(pool)
}

/// Creates a single-connection in-memory pool and runs migrations. Use in tests only.
pub fn init_pool_for_test() -> Result<DbPool, AppError> {
    let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
    let pool = Pool::builder()
        .max_size(1)
        .build(manager)
        .map_err(|e| AppError::Config(format!("test pool: {e}")))?;
    let mut conn = pool.get()
        .map_err(|e| AppError::Database(e.to_string()))?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| AppError::Database(format!("test migration: {e}")))?;
    Ok(pool)
}

/// Runs a synchronous Diesel closure on Tokio's blocking thread pool.
///
/// ```rust
/// let users = run_db(&state.db, |conn| {
///     identities::table
///         .filter(identities::revoked_at.is_null())
///         .load::<Identity>(conn)
/// }).await?;
/// ```
pub async fn run_db<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut SqliteConnection) -> Result<T, diesel::result::Error> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let mut conn = pool.get()
            .map_err(|e| AppError::Database(e.to_string()))?;
        f(&mut conn).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Database(format!("spawn_blocking panicked: {e}")))?
}
