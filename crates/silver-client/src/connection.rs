//! Background relay connection with reconnect, auth and envelope handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_protocol::wire::{ClientFrame, ServerFrame, auth_signature};

use crate::outbox::Outbox;
use crate::proxy::Proxy;
use crate::tls::{ConnectOptions, connector};
use silver_protocol::{
    Content, Envelope, Identity, KeyBundle, Message, ProtocolError, UserId, now_ms, open, seal,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};

pub const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:7777/ws";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Things the connection task reports to the front end.
#[derive(Debug)]
pub enum ClientEvent {
    /// Authenticated and our key bundle is published.
    Connected { relay_url: String },
    /// The connection dropped or could not be made; another attempt follows
    /// after `retry_in`.
    Disconnected { reason: String, retry_in: Duration },
    /// A decrypted, signature-verified incoming message.
    Message(Message),
    /// The relay accepted the envelope with this id.
    Sent { id: String },
    /// The relay refused the envelope with this id for good (for example the
    /// recipient's mailbox is full); it has been dropped from the outbox.
    Rejected { id: String, reason: String },
    /// A non-fatal problem worth surfacing (undecryptable envelope, relay error).
    Error(String),
}

/// Ids of envelopes the relay has not accepted yet, shared with the front end.
type PendingIds = Arc<Mutex<Vec<String>>>;

fn sync_pending(pending: &PendingIds, outbox: &Outbox) {
    *pending.lock().unwrap_or_else(|e| e.into_inner()) = outbox.ids();
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not connected to relay")]
    NotConnected,
    #[error("relay error: {0}")]
    Relay(String),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("timed out waiting for relay")]
    Timeout,
    #[error("client task has stopped")]
    Stopped,
}

enum Command {
    Send {
        envelope: Envelope,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    Lookup {
        user_id: UserId,
        reply: oneshot::Sender<Result<Option<KeyBundle>, ClientError>>,
    },
    Shutdown,
}

/// Cheap-to-clone handle to the connection task.
#[derive(Clone)]
pub struct Client {
    identity: Arc<Identity>,
    cmd_tx: mpsc::Sender<Command>,
    pending: PendingIds,
}

impl Client {
    /// Start the connection task. Events arrive on the returned receiver.
    /// Fails only if the options cannot be applied (an unreadable CA file,
    /// a corrupt outbox file); connection problems are reported as events.
    pub fn spawn(
        relay_url: String,
        identity: Arc<Identity>,
        options: ConnectOptions,
    ) -> anyhow::Result<(Self, mpsc::Receiver<ClientEvent>)> {
        let connector = connector(&options)?;
        let proxy = options.proxy.as_deref().map(Proxy::parse).transpose()?;
        let outbox = Outbox::load(options.outbox_path.clone())?;
        let pending: PendingIds = Arc::new(Mutex::new(outbox.ids()));
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(256);
        tokio::spawn(run(
            relay_url,
            identity.clone(),
            connector,
            proxy,
            outbox,
            pending.clone(),
            cmd_rx,
            ev_tx,
        ));
        Ok((
            Self {
                identity,
                cmd_tx,
                pending,
            },
            ev_rx,
        ))
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn user_id(&self) -> UserId {
        self.identity.user_id()
    }

    /// Ids of outgoing envelopes the relay has not accepted yet.
    pub fn pending_ids(&self) -> Vec<String> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Fetch and verify someone's key bundle from the relay.
    pub async fn lookup(&self, user_id: UserId) -> Result<Option<KeyBundle>, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Lookup { user_id, reply: tx })
            .await
            .map_err(|_| ClientError::Stopped)?;
        let bundle = tokio::time::timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::NotConnected)??;
        if let Some(b) = &bundle {
            if b.user_id != user_id {
                return Err(ClientError::Relay(
                    "relay returned a bundle for the wrong user".into(),
                ));
            }
            b.verify()?;
        }
        Ok(bundle)
    }

    /// Seal `text` for `to` and queue it for the relay. Resolves once the
    /// envelope is in the outbox, connected or not; [`ClientEvent::Sent`] or
    /// [`ClientEvent::Rejected`] follows once the relay has answered.
    pub async fn send_text(&self, to: &KeyBundle, text: String) -> Result<Envelope, ClientError> {
        let envelope = seal(&self.identity, to, Content::Text { body: text }, now_ms())?;
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Send {
                envelope: envelope.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| ClientError::Stopped)?;
        rx.await.map_err(|_| ClientError::NotConnected)??;
        Ok(envelope)
    }

    /// Close the connection and stop the task.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown).await;
    }
}

enum Exit {
    Shutdown,
    Disconnected(String),
}

#[allow(clippy::too_many_arguments)]
async fn run(
    relay_url: String,
    identity: Arc<Identity>,
    connector: Connector,
    proxy: Option<Proxy>,
    mut outbox: Outbox,
    pending: PendingIds,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev_tx: mpsc::Sender<ClientEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let outcome = session(
            &relay_url,
            &identity,
            connector.clone(),
            proxy.as_ref(),
            &mut outbox,
            &pending,
            &mut cmd_rx,
            &ev_tx,
            &mut backoff,
        )
        .await;
        let reason = match outcome {
            Ok(Exit::Shutdown) => return,
            Ok(Exit::Disconnected(reason)) => reason,
            Err(e) => e.to_string(),
        };
        if ev_tx
            .send(ClientEvent::Disconnected {
                reason,
                retry_in: backoff,
            })
            .await
            .is_err()
        {
            return; // front end is gone
        }

        // Sleep before reconnecting. Sends are queued meanwhile; lookups
        // need the relay and are refused.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::Shutdown) | None => return,
                    Some(Command::Send { envelope, reply }) => {
                        outbox.push(envelope);
                        sync_pending(&pending, &outbox);
                        let _ = reply.send(Ok(()));
                    }
                    Some(Command::Lookup { reply, .. }) => {
                        let _ = reply.send(Err(ClientError::NotConnected));
                    }
                },
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

type Pending = HashMap<UserId, Vec<oneshot::Sender<Result<Option<KeyBundle>, ClientError>>>>;

#[allow(clippy::too_many_arguments)]
async fn session(
    relay_url: &str,
    identity: &Identity,
    connector: Connector,
    proxy: Option<&Proxy>,
    outbox: &mut Outbox,
    pending: &PendingIds,
    cmd_rx: &mut mpsc::Receiver<Command>,
    ev_tx: &mpsc::Sender<ClientEvent>,
    backoff: &mut Duration,
) -> anyhow::Result<Exit> {
    debug!("connecting to {relay_url}");
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        open_websocket(relay_url, connector, proxy),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timed out"))??;
    let (mut sink, mut stream) = ws.split();

    // --- handshake: challenge -> auth -> auth_ok ---------------------------
    let handshake = async {
        let nonce = match next_frame(&mut stream).await? {
            ServerFrame::Challenge { nonce } => nonce,
            other => anyhow::bail!("expected challenge, got {other:?}"),
        };
        let auth = ClientFrame::Auth {
            user_id: identity.user_id(),
            signature: auth_signature(identity, &nonce),
        };
        sink.send(text(&auth)).await?;
        match next_frame(&mut stream).await? {
            ServerFrame::AuthOk { .. } => {}
            ServerFrame::Error { code, message } => {
                anyhow::bail!("auth rejected ({code:?}): {message}")
            }
            other => anyhow::bail!("expected auth_ok, got {other:?}"),
        }
        anyhow::Ok(())
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow::anyhow!("handshake timed out"))??;

    // Publish our bundle. The relay may interleave queued deliveries before it
    // answers, so `Published` is handled in the main loop; only then are we
    // discoverable and report `Connected`.
    sink.send(text(&ClientFrame::Publish {
        bundle: identity.key_bundle(),
    }))
    .await?;
    let mut published = false;

    // --- steady state ------------------------------------------------------
    let mut lookups: Pending = HashMap::new();
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await; // first tick fires immediately; skip it

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None | Some(Command::Shutdown) => {
                    let _ = sink.close().await;
                    return Ok(Exit::Shutdown);
                }
                Some(Command::Send { envelope, reply }) => {
                    // Queue first: if the write fails the envelope is resent
                    // on the next connection.
                    outbox.push(envelope.clone());
                    sync_pending(pending, outbox);
                    let _ = reply.send(Ok(()));
                    if sink.send(text(&ClientFrame::Send { envelope })).await.is_err() {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
                Some(Command::Lookup { user_id, reply }) => {
                    if let Err(e) = sink.send(text(&ClientFrame::Lookup { user_id })).await {
                        let _ = reply.send(Err(ClientError::Relay(e.to_string())));
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                    lookups.entry(user_id).or_default().push(reply);
                }
            },
            _ = keepalive.tick() => {
                if sink.send(text(&ClientFrame::Ping)).await.is_err() {
                    return Ok(Exit::Disconnected("keepalive failed".into()));
                }
            }
            frame = next_frame(&mut stream) => {
                let frame = match frame {
                    Ok(f) => f,
                    Err(e) => return Ok(Exit::Disconnected(e.to_string())),
                };
                match frame {
                    ServerFrame::Deliver { envelope } => {
                        let id = envelope.id.clone();
                        match open(identity, &envelope) {
                            Ok(message) => {
                                let _ = ev_tx.send(ClientEvent::Message(message)).await;
                            }
                            Err(e) => {
                                warn!("dropping undecryptable envelope {id}: {e}");
                                let _ = ev_tx
                                    .send(ClientEvent::Error(format!("could not open envelope {id}: {e}")))
                                    .await;
                            }
                        }
                        // Ack either way so a poison envelope cannot wedge the mailbox.
                        if sink.send(text(&ClientFrame::Ack { id })).await.is_err() {
                            return Ok(Exit::Disconnected("ack failed".into()));
                        }
                    }
                    ServerFrame::Sent { id } => {
                        outbox.remove(&id);
                        sync_pending(pending, outbox);
                        let _ = ev_tx.send(ClientEvent::Sent { id }).await;
                    }
                    ServerFrame::Rejected { id, code, message } => {
                        outbox.remove(&id);
                        sync_pending(pending, outbox);
                        let _ = ev_tx
                            .send(ClientEvent::Rejected {
                                id,
                                reason: format!("{message} ({code:?})"),
                            })
                            .await;
                    }
                    ServerFrame::LookupResult { user_id, bundle } => {
                        for reply in lookups.remove(&user_id).unwrap_or_default() {
                            let _ = reply.send(Ok(bundle.clone()));
                        }
                    }
                    ServerFrame::Error { code, message } => {
                        let _ = ev_tx
                            .send(ClientEvent::Error(format!("relay: {message} ({code:?})")))
                            .await;
                    }
                    ServerFrame::Published => {
                        if !published {
                            published = true;
                            info!("connected to {relay_url} as {}", identity.user_id());
                            *backoff = Duration::from_secs(1);
                            let _ = ev_tx
                                .send(ClientEvent::Connected {
                                    relay_url: relay_url.to_owned(),
                                })
                                .await;
                            // Resend everything the relay has not accepted
                            // yet; it ignores ids it already holds.
                            for envelope in outbox.iter() {
                                let frame = ClientFrame::Send {
                                    envelope: envelope.clone(),
                                };
                                if sink.send(text(&frame)).await.is_err() {
                                    return Ok(Exit::Disconnected("resend failed".into()));
                                }
                            }
                        }
                    }
                    ServerFrame::Pong => {}
                    ServerFrame::Challenge { .. } | ServerFrame::AuthOk { .. } => {
                        debug!("ignoring unexpected handshake frame mid-session");
                    }
                }
            }
        }
    }
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Open the WebSocket, directly or through a CONNECT proxy. TLS (for
/// `wss://`) is always negotiated end to end with the relay by us.
async fn open_websocket(
    url: &str,
    connector: Connector,
    proxy: Option<&Proxy>,
) -> anyhow::Result<Ws> {
    let Some(proxy) = proxy else {
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(describe_connect_error)?;
        return Ok(ws);
    };
    let request = url.into_client_request().map_err(describe_connect_error)?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("relay URL has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") => 443,
        _ => 80,
    });
    debug!(
        "tunnelling to {host}:{port} via proxy {}:{}",
        proxy.host, proxy.port
    );
    let stream = proxy.connect(&host, port).await?;
    let (ws, _) =
        tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
            .await
            .map_err(describe_connect_error)?;
    Ok(ws)
}

/// Turn a failed WebSocket connect into a message a person can act on. An
/// HTTP status instead of an upgrade usually means a proxy or firewall on the
/// path answered instead of the relay, so include what it said.
fn describe_connect_error(err: tokio_tungstenite::tungstenite::Error) -> anyhow::Error {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match err {
        WsError::Http(response) => {
            let status = response.status();
            let excerpt = response
                .body()
                .as_deref()
                .map(|body| text_excerpt(&String::from_utf8_lossy(body), 200))
                .unwrap_or_default();
            if excerpt.is_empty() {
                anyhow::anyhow!(
                    "HTTP {status} instead of a WebSocket upgrade (a proxy or firewall may be intercepting)"
                )
            } else {
                anyhow::anyhow!("HTTP {status} instead of a WebSocket upgrade: {excerpt}")
            }
        }
        other => anyhow::Error::new(other),
    }
}

/// The readable text of an HTML page: tags, scripts and styles removed,
/// whitespace collapsed, at most `max` characters.
fn text_excerpt(html: &str, max: usize) -> String {
    let lower = html.to_ascii_lowercase();
    let mut out = String::new();
    let mut count = 0;
    let mut last_space = true;
    let mut i = 0;
    while i < html.len() {
        if html[i..].starts_with('<') {
            let rest = &lower[i..];
            let block_end = if rest.starts_with("<script") {
                Some("</script>")
            } else if rest.starts_with("<style") {
                Some("</style>")
            } else {
                None
            };
            if let Some(close) = block_end {
                match rest.find(close) {
                    Some(end) => i += end + close.len(),
                    None => break,
                }
            } else {
                match html[i..].find('>') {
                    Some(end) => i += end + 1,
                    None => break,
                }
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            continue;
        }
        let ch = html[i..].chars().next().expect("in bounds");
        i += ch.len_utf8();
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
            count += 1;
            if count >= max {
                out.push('…');
                break;
            }
        }
    }
    out.trim().to_owned()
}

fn text(frame: &ClientFrame) -> WsMessage {
    WsMessage::Text(frame.encode().into())
}

type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Read the next server frame, skipping control frames. Errors on close.
async fn next_frame(stream: &mut WsStream) -> anyhow::Result<ServerFrame> {
    loop {
        let msg = match stream.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => anyhow::bail!("websocket error: {e}"),
            None => anyhow::bail!("connection closed"),
        };
        let text = match msg {
            WsMessage::Text(t) => t.as_str().to_owned(),
            WsMessage::Binary(b) => String::from_utf8(b.to_vec())?,
            WsMessage::Close(_) => anyhow::bail!("relay closed the connection"),
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        };
        return Ok(ServerFrame::decode(&text)?);
    }
}

#[cfg(test)]
mod tests {
    use super::text_excerpt;

    #[test]
    fn block_page_becomes_readable_text() {
        let html = "<html><head><title>Blocked</title><style>h1{color:red}</style>\
                    <script>var x = 1;</script></head><body><h1>Sorry,</h1> company \n\
                    policy   <b>prohibits</b> this action.</body></html>";
        assert_eq!(
            text_excerpt(html, 200),
            "Blocked Sorry, company policy prohibits this action."
        );
        assert_eq!(text_excerpt("abcdef", 3), "abc…");
        assert_eq!(text_excerpt("", 10), "");
    }
}
