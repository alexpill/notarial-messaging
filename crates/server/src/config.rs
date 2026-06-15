use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub frontend_origin: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://./notarial.db".to_string()),
            server_host: std::env::var("SERVER_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| AppError::Config("SERVER_PORT: invalid port number".to_string()))?,
            frontend_origin: std::env::var("FRONTEND_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
        })
    }
}
