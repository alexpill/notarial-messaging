// WebSocket /ws/:acte_id — real-time notification channel.
//
// The WebSocket only pushes a message_id on new messages; it does NOT carry
// ciphertexts. Clients fetch the ciphertext via GET /actes/:id/messages after
// receiving a notification. This keeps the WebSocket stateless with respect to data.
//
// Auth: browsers cannot set custom headers on WS upgrades, so we use a ticket
// flow — clients trade their session token for a single-use 30-second ticket
// via `POST /ws/ticket` (Bearer auth), then connect with `?ticket=...`. Tickets
// appearing in access logs are worthless: they're consumed on first use and
// expire within 30s anyway. The session token itself never touches the URL.

use crate::{
    en::registry, error::AppError, middleware::AuthenticatedSn, state::{AppState, WsTicket},
};
use axum::{
    Json,
    extract::{Path, Query, State, WebSocketUpgrade},
    extract::ws::WebSocket,
    response::Response,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

const WS_TICKET_TTL_SECS: i64 = 30;

#[derive(Debug, Serialize)]
pub struct WsTicketResponse {
    pub ticket: String,
    pub expires_at: i64,
}

/// Issues a fresh single-use ticket bound to the caller's SN. The ticket is
/// kept in process memory only — a multi-process deployment would replace this
/// store with shared state (Redis, etc.), but the PoC stays single-process.
pub async fn issue_ticket(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
) -> Result<Json<WsTicketResponse>, AppError> {
    let now = crate::utils::unix_now()?;
    let expires_at = now + WS_TICKET_TTL_SECS;

    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let ticket = hex::encode(raw);

    {
        let mut tickets = state
            .ws_tickets
            .lock()
            .map_err(|_| AppError::Database("ws_tickets lock poisoned".into()))?;
        // Opportunistic GC — drop expired entries so the map doesn't grow forever
        // for clients that grab tickets without ever using them.
        tickets.retain(|_, t| t.expires_at >= now);
        tickets.insert(ticket.clone(), WsTicket { sn: caller_sn, expires_at });
    }

    Ok(Json(WsTicketResponse { ticket, expires_at }))
}

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub ticket: Option<String>,
}

/// Upgrades the connection to WebSocket. The caller must present a fresh,
/// non-expired ticket previously obtained from POST /ws/ticket. Tickets are
/// removed from the store on use — replay attempts with a logged ticket fail.
pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let ticket = query.ticket.ok_or(AppError::Unauthorized)?;
    let now = crate::utils::unix_now().map_err(|_| AppError::Unauthorized)?;

    let entry = {
        let mut tickets = state
            .ws_tickets
            .lock()
            .map_err(|_| AppError::Database("ws_tickets lock poisoned".into()))?;
        tickets.remove(&ticket)
    }
    .ok_or(AppError::Unauthorized)?;

    if entry.expires_at < now {
        return Err(AppError::Unauthorized);
    }

    let caller_sn = entry.sn;

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
