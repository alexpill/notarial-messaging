// WebSocket /ws/:acte_id — real-time notification channel.
//
// The WebSocket only pushes a message_id on new messages; it does NOT carry
// ciphertexts. Clients fetch the ciphertext via GET /actes/:id/messages after
// receiving a notification. This keeps the WebSocket stateless with respect to data.

use crate::{en::registry, error::AppError, middleware::AuthenticatedSn, state::AppState};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    extract::ws::WebSocket,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Upgrades the connection to WebSocket. Client must be authenticated and a participant.
pub async fn ws_handler(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
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
