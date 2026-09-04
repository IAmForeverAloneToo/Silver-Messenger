//! Background relay connection with reconnect, auth and envelope handling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_protocol::wire::{ClientFrame, ServerFrame, auth_signature};

use crate::tls::{ConnectOptions, connector};
use silver_protocol::{
    Content, Envelope, Identity, KeyBundle, Message, ProtocolError, UserId, now_ms, open, seal,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
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
    Connected {
        relay_url: String,
    },
    Disconnected {
        reason: String,
    },
    /// A decrypted, signature-verified incoming message.
    Message(Message),
    /// The relay accepted the envelope with this id.
    Sent {
        id: String,
    },
    /// A non-fatal problem worth surfacing (undecryptable envelope, relay error).
    Error(String),
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
}

impl Client {
    /// Start the connection task. Events arrive on the returned receiver.
    /// Fails only if the TLS options cannot be applied (e.g. an unreadable
    /// CA file); connection problems are reported as events.
    pub fn spawn(
        relay_url: String,
        identity: Arc<Identity>,
        options: ConnectOptions,
    ) -> anyhow::Result<(Self, mpsc::Receiver<ClientEvent>)> {
        let connector = connector(&options)?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(256);
        tokio::spawn(run(relay_url, identity.clone(), connector, cmd_rx, ev_tx));
        Ok((Self { identity, cmd_tx }, ev_rx))
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn user_id(&self) -> UserId {
        self.identity.user_id()
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

    /// Seal `text` for `to` and hand it to the relay. Resolves once the
    /// envelope is on the wire; [`ClientEvent::Sent`] follows when the relay
    /// accepts it.
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

async fn run(
    relay_url: String,
    identity: Arc<Identity>,
    connector: Connector,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev_tx: mpsc::Sender<ClientEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let outcome = session(
            &relay_url,
            &identity,
            connector.clone(),
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
            .send(ClientEvent::Disconnected { reason })
            .await
            .is_err()
        {
            return; // front end is gone
        }

        // Sleep before reconnecting, still answering commands with NotConnected.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::Shutdown) | None => return,
                    Some(cmd) => reject(cmd),
                },
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn reject(cmd: Command) {
    match cmd {
        Command::Send { reply, .. } => {
            let _ = reply.send(Err(ClientError::NotConnected));
        }
        Command::Lookup { reply, .. } => {
            let _ = reply.send(Err(ClientError::NotConnected));
        }
        Command::Shutdown => {}
    }
}

type Pending = HashMap<UserId, Vec<oneshot::Sender<Result<Option<KeyBundle>, ClientError>>>>;

async fn session(
    relay_url: &str,
    identity: &Identity,
    connector: Connector,
    cmd_rx: &mut mpsc::Receiver<Command>,
    ev_tx: &mpsc::Sender<ClientEvent>,
    backoff: &mut Duration,
) -> anyhow::Result<Exit> {
    debug!("connecting to {relay_url}");
    let (ws, _) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(relay_url, None, false, Some(connector)),
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
    let mut pending: Pending = HashMap::new();
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
                    let result = sink
                        .send(text(&ClientFrame::Send { envelope }))
                        .await
                        .map_err(|e| ClientError::Relay(e.to_string()));
                    let failed = result.is_err();
                    let _ = reply.send(result);
                    if failed {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
                Some(Command::Lookup { user_id, reply }) => {
                    if let Err(e) = sink.send(text(&ClientFrame::Lookup { user_id })).await {
                        let _ = reply.send(Err(ClientError::Relay(e.to_string())));
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                    pending.entry(user_id).or_default().push(reply);
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
                        let _ = ev_tx.send(ClientEvent::Sent { id }).await;
                    }
                    ServerFrame::LookupResult { user_id, bundle } => {
                        for reply in pending.remove(&user_id).unwrap_or_default() {
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
