//! The Silver Messenger relay.
//!
//! The relay is deliberately dumb: it authenticates clients by challenge
//! signature, stores signed public-key bundles, and queues opaque
//! [`Envelope`]s per recipient until the recipient acknowledges them. It never
//! sees plaintext, and because senders are sealed inside the ciphertext it
//! does not even learn who sent a given envelope.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rand::rngs::OsRng;
use silver_protocol::wire::{ClientFrame, ErrorCode, MAX_FRAME_BYTES, ServerFrame, verify_auth};
use silver_protocol::{Envelope, KeyBundle, MAX_CIPHERTEXT_BYTES, UserId};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7777";
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum unacknowledged envelopes kept per recipient.
pub const MAX_QUEUE_PER_USER: usize = 1000;

/// Everything the relay knows. Shared between connections.
#[derive(Default)]
pub struct RelayState {
    inner: Mutex<Inner>,
    next_session: AtomicU64,
}

#[derive(Default)]
struct Inner {
    bundles: HashMap<UserId, KeyBundle>,
    online: HashMap<UserId, Session>,
    queues: HashMap<UserId, VecDeque<Envelope>>,
}

struct Session {
    id: u64,
    tx: mpsc::UnboundedSender<Outbound>,
}

enum Outbound {
    Frame(ServerFrame),
    /// A newer session for the same user replaced this one.
    Close,
}

/// Why the relay refused a client frame.
type Rejection = (ErrorCode, &'static str);

impl RelayState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn online_count(&self) -> usize {
        self.lock().online.len()
    }

    pub fn queued_for(&self, user: &UserId) -> usize {
        self.lock().queues.get(user).map_or(0, VecDeque::len)
    }

    pub fn bundle(&self, user: &UserId) -> Option<KeyBundle> {
        self.lock().bundles.get(user).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The state is small and never poisoned by design; recover anyway.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a freshly authenticated session, replacing any older one for
    /// the same user, and replay all unacknowledged envelopes into it.
    fn register(&self, user: UserId, tx: mpsc::UnboundedSender<Outbound>) -> u64 {
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.lock();
        if let Some(old) = inner.online.insert(user, Session { id, tx: tx.clone() }) {
            let _ = old.tx.send(Outbound::Close);
        }
        if let Some(queue) = inner.queues.get(&user) {
            for envelope in queue {
                let _ = tx.send(Outbound::Frame(ServerFrame::Deliver {
                    envelope: envelope.clone(),
                }));
            }
        }
        id
    }

    fn unregister(&self, user: &UserId, session_id: u64) {
        let mut inner = self.lock();
        if inner.online.get(user).is_some_and(|s| s.id == session_id) {
            inner.online.remove(user);
        }
    }

    fn publish(&self, me: &UserId, bundle: KeyBundle) -> Result<(), Rejection> {
        if bundle.user_id != *me {
            return Err((
                ErrorCode::Forbidden,
                "bundle user_id does not match authenticated user",
            ));
        }
        if bundle.verify().is_err() {
            return Err((ErrorCode::BadSignature, "bundle signature is invalid"));
        }
        self.lock().bundles.insert(*me, bundle);
        Ok(())
    }

    /// Queue an envelope for its recipient and push it if they are online.
    fn route(&self, envelope: Envelope) -> Result<(), Rejection> {
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err((ErrorCode::TooLarge, "ciphertext too large"));
        }
        let mut inner = self.lock();
        let queue = inner.queues.entry(envelope.to).or_default();
        if queue.len() >= MAX_QUEUE_PER_USER {
            return Err((ErrorCode::MailboxFull, "recipient mailbox is full"));
        }
        queue.push_back(envelope.clone());
        if let Some(session) = inner.online.get(&envelope.to) {
            let _ = session
                .tx
                .send(Outbound::Frame(ServerFrame::Deliver { envelope }));
        }
        Ok(())
    }

    fn ack(&self, me: &UserId, id: &str) {
        let mut inner = self.lock();
        if let Some(queue) = inner.queues.get_mut(me) {
            queue.retain(|e| e.id != id);
            if queue.is_empty() {
                inner.queues.remove(me);
            }
        }
    }
}

/// Build the HTTP router: `GET /healthz` and the WebSocket endpoint at `/ws`.
pub fn router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(silver_protocol::wire::WS_PATH, get(ws_handler))
        .with_state(state)
}

/// Serve until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<RelayState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>) {
    let (mut sink, mut stream) = socket.split();

    // --- challenge / response -------------------------------------------
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    if send(&mut sink, &ServerFrame::Challenge { nonce })
        .await
        .is_err()
    {
        return;
    }

    let auth = tokio::time::timeout(AUTH_TIMEOUT, next_frame(&mut stream)).await;
    let user = match auth {
        Ok(Some(Ok(ClientFrame::Auth { user_id, signature }))) => {
            if verify_auth(&user_id, &nonce, &signature).is_err() {
                let _ = send(
                    &mut sink,
                    &ServerFrame::error(ErrorCode::BadSignature, "challenge signature invalid"),
                )
                .await;
                return;
            }
            user_id
        }
        Ok(Some(Ok(_))) => {
            let _ = send(
                &mut sink,
                &ServerFrame::error(ErrorCode::Unauthenticated, "expected auth frame"),
            )
            .await;
            return;
        }
        Ok(Some(Err(e))) => {
            let _ = send(&mut sink, &ServerFrame::error(ErrorCode::Malformed, e)).await;
            return;
        }
        Ok(None) => return,
        Err(_) => {
            debug!("client did not authenticate within {AUTH_TIMEOUT:?}");
            return;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let session_id = state.register(user, tx.clone());
    info!(%user, session_id, "client authenticated");
    if send(&mut sink, &ServerFrame::AuthOk { user_id: user })
        .await
        .is_err()
    {
        state.unregister(&user, session_id);
        return;
    }

    // --- main loop --------------------------------------------------------
    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(Outbound::Frame(frame)) => {
                    if send(&mut sink, &frame).await.is_err() {
                        break;
                    }
                }
                Some(Outbound::Close) => {
                    debug!(%user, session_id, "replaced by a newer session");
                    let _ = sink.close().await;
                    return; // the newer session owns the registry entry now
                }
                None => break,
            },
            inbound = next_frame(&mut stream) => match inbound {
                Some(Ok(frame)) => {
                    if let Some(reply) = handle_frame(&state, &user, frame) {
                        let _ = tx.send(Outbound::Frame(reply));
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Outbound::Frame(ServerFrame::error(ErrorCode::Malformed, e)));
                }
                None => break,
            },
        }
    }

    state.unregister(&user, session_id);
    info!(%user, session_id, "client disconnected");
}

fn handle_frame(state: &RelayState, me: &UserId, frame: ClientFrame) -> Option<ServerFrame> {
    match frame {
        ClientFrame::Auth { .. } => Some(ServerFrame::error(
            ErrorCode::Malformed,
            "already authenticated",
        )),
        ClientFrame::Publish { bundle } => Some(match state.publish(me, bundle) {
            Ok(()) => ServerFrame::Published,
            Err((code, message)) => ServerFrame::error(code, message),
        }),
        ClientFrame::Lookup { user_id } => Some(ServerFrame::LookupResult {
            user_id,
            bundle: state.bundle(&user_id),
        }),
        ClientFrame::Send { envelope } => {
            let id = envelope.id.clone();
            Some(match state.route(envelope) {
                Ok(()) => ServerFrame::Sent { id },
                Err((code, message)) => ServerFrame::error(code, message),
            })
        }
        ClientFrame::Ack { id } => {
            state.ack(me, &id);
            None
        }
        ClientFrame::Ping => Some(ServerFrame::Pong),
    }
}

async fn send(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    frame: &ServerFrame,
) -> Result<(), axum::Error> {
    sink.send(Message::Text(frame.encode().into())).await
}

/// Read the next JSON frame. `None` means the socket closed.
async fn next_frame(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<Result<ClientFrame, String>> {
    loop {
        let msg = match stream.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                debug!("websocket error: {e}");
                return None;
            }
            None => return None,
        };
        let text = match &msg {
            Message::Text(t) => t.as_str().to_owned(),
            Message::Binary(b) => match std::str::from_utf8(b) {
                Ok(s) => s.to_owned(),
                Err(_) => return Some(Err("binary frame is not UTF-8".into())),
            },
            Message::Close(_) => return None,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        return Some(ClientFrame::decode(&text).map_err(|e| {
            warn!("malformed client frame: {e}");
            format!("malformed frame: {e}")
        }));
    }
}
