// WebSocket /ws/:acte_id — real-time notification channel.
//
// The WebSocket only pushes a message_id on new messages; it does NOT carry
// ciphertexts. Clients fetch the ciphertext via GET /actes/:id/messages after
// receiving a notification. This keeps the WebSocket stateless with respect to data.
//
// Auth: browsers cannot send custom headers on WS upgrades, so we accept the
// session token either as a standard Authorization: Bearer header (CLI, curl) or
// as a ?token= query parameter (browser JS clients).

use crate::{en::registry, error::AppError, state::AppState};
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    extract::ws::WebSocket,
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// Upgrades the connection to WebSocket. Client must be authenticated and a participant.
pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Query(query): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    // Accept token from Authorization header (HTTP clients) or query string (browser WS).
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
        .or(query.token)
        .ok_or(AppError::Unauthorized)?;

    let session = registry::lookup_session(&state.db, token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let now = crate::utils::unix_now().map_err(|_| AppError::Unauthorized)?;
    if session.expires_at < now {
        return Err(AppError::Unauthorized);
    }

    let caller_sn = session.sn;

    registry::get_participant_key(&state.db, acte_id.clone(), caller_sn)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let rx = {
        let mut channels = state
            .ws_channels
            .lock()
            .map_err(|_| AppError::Database("ws_channels lock poisoned".into()))?;
        channels
            .entry(acte_id)
            .or_insert_with(|| broadcast::channel(64).0)
            .subscribe()
    };

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, rx)))
}

async fn handle_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    use axum::extract::ws::Message;

    loop {
        match rx.recv().await {
            Ok(msg) => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            // Client too slow — skip missed notifications, they can poll via GET.
            Err(broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}
