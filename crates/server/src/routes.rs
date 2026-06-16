pub mod actes;
pub mod authentication;
pub mod enrollment;
pub mod messages;
pub mod participants;
pub mod ws;

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(state.config.frontend_origin.parse::<axum::http::HeaderValue>().unwrap())
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        // LocalPKI EN
        .route("/enroll", post(enrollment::enroll))
        .route("/enroll/prepare", post(enrollment::prepare_tbs))
        .route("/enroll/self", post(enrollment::enroll_self))
        .route("/auth/verify", post(authentication::verify))
        .route("/identity/:sn", get(enrollment::get_identity))
        // Actes
        .route("/actes", get(actes::list_actes).post(actes::create_acte))
        .route("/actes/:id", get(actes::get_acte))
        .route("/actes/:id/keys", get(actes::get_acte_key))
        // Participants
        .route("/actes/:id/participants", post(participants::add_participant))
        // Messages
        .route("/actes/:id/messages", post(messages::send_message))
        .route("/actes/:id/messages", get(messages::list_messages))
        // Merkle log
        .route("/actes/:id/merkle", get(messages::get_merkle_root))
        // WebSocket
        .route("/ws/ticket", post(ws::issue_ticket))
        .route("/ws/:acte_id", get(ws::ws_handler))
        .layer(cors)
        .with_state(state)
}
