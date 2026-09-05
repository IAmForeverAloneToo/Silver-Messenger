//! The anonymous submission connection.
//!
//! A relay that advertises anonymous submission accepts `Send` frames, and
//! file chunks, on a connection that never authenticates. Submitting on
//! such a connection instead of the authenticated one means the relay
//! cannot pair an envelope or a file with the identity that sent or fetched
//! it; it still sees the address the connection came from and when it was
//! used (see docs/THREAT_MODEL.md).
//!
//! The submitter is a background task with its own reconnect loop. The
//! main connection hands it frames and gets back the relay's answers, plus
//! `Ready`/`Down` so it knows when to hand more over.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_protocol::wire::{ClientFrame, ErrorCode, ServerFrame};
use tokio::sync::mpsc;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, warn};

use crate::connection::{open_websocket, read_frame};
use crate::proxy::Proxy;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub(crate) enum SubmitEvent {
    /// Connected; frames handed over now will be submitted.
    Ready,
    Sent {
        id: String,
    },
    Rejected {
        id: String,
        code: ErrorCode,
        message: String,
    },
    /// A file chunk answer: `BlobAck`, `BlobRejected` or `BlobChunk`.
    Blob(Box<ServerFrame>),
    /// The group sequencer's answer: `GroupState` or `GroupRejected`.
    Group(Box<ServerFrame>),
    /// The connection dropped; frames handed over since `Ready` and not
    /// answered must be resent after the next `Ready`.
    Down {
        reason: String,
    },
    /// The relay refused anonymous submission after all; the main
    /// connection should submit itself from now on.
    Refused,
}

pub(crate) struct Submitter {
    tx: mpsc::Sender<ClientFrame>,
    events: mpsc::Receiver<SubmitEvent>,
    pub(crate) ready: bool,
}

impl Submitter {
    pub(crate) fn spawn(relay_url: String, connector: Connector, proxy: Option<Proxy>) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(64);
        tokio::spawn(run(relay_url, connector, proxy, rx, ev_tx));
        Self {
            tx,
            events: ev_rx,
            ready: false,
        }
    }

    /// Hand a frame over. `false` if the task has stopped.
    pub(crate) async fn submit(&self, frame: ClientFrame) -> bool {
        self.tx.send(frame).await.is_ok()
    }

    pub(crate) async fn next_event(&mut self) -> Option<SubmitEvent> {
        self.events.recv().await
    }
}

async fn run(
    relay_url: String,
    connector: Connector,
    proxy: Option<Proxy>,
    mut rx: mpsc::Receiver<ClientFrame>,
    events: mpsc::Sender<SubmitEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let reason = match session(
            &relay_url,
            connector.clone(),
            proxy.as_ref(),
            &mut rx,
            &events,
        )
        .await
        {
            Ok(Exit::Closed) => return,
            Ok(Exit::Refused) => {
                let _ = events.send(SubmitEvent::Refused).await;
                return;
            }
            Ok(Exit::Dropped(reason)) => reason,
            Err(e) => e.to_string(),
        };
        debug!("anonymous submission connection down: {reason}; retrying in {backoff:?}");
        if events.send(SubmitEvent::Down { reason }).await.is_err() {
            return;
        }
        // Wait out the backoff, but stop at once if the owner is gone.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = closed(&mut rx) => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Resolves when the sender side of the channel is dropped. Frames that
/// arrive meanwhile are left in the channel for the next session.
async fn closed(rx: &mut mpsc::Receiver<ClientFrame>) {
    loop {
        if rx.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

enum Exit {
    Closed,
    Refused,
    Dropped(String),
}

async fn session(
    relay_url: &str,
    connector: Connector,
    proxy: Option<&Proxy>,
    rx: &mut mpsc::Receiver<ClientFrame>,
    events: &mpsc::Sender<SubmitEvent>,
) -> anyhow::Result<Exit> {
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        open_websocket(relay_url, connector, proxy),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timed out"))??;
    let (mut sink, mut stream) = ws.split();
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(ServerFrame::Challenge { .. })) => {}
        Ok(Ok(other)) => anyhow::bail!("expected challenge, got {other:?}"),
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!("handshake timed out"),
    }
    debug!("anonymous submission connection ready");
    if events.send(SubmitEvent::Ready).await.is_err() {
        return Ok(Exit::Closed);
    }
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await;

    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                None => {
                    let _ = sink.close().await;
                    return Ok(Exit::Closed);
                }
                Some(frame) => {
                    if sink.send(WsMessage::Text(frame.encode().into())).await.is_err() {
                        return Ok(Exit::Dropped("send failed".into()));
                    }
                }
            },
            _ = keepalive.tick() => {
                if sink.send(WsMessage::Text(ClientFrame::Ping.encode().into())).await.is_err() {
                    return Ok(Exit::Dropped("keepalive failed".into()));
                }
            }
            frame = read_frame(&mut stream) => {
                let event = match frame {
                    Ok(ServerFrame::Sent { id }) => SubmitEvent::Sent { id },
                    Ok(ServerFrame::Rejected { id, code, message }) => {
                        SubmitEvent::Rejected { id, code, message }
                    }
                    Ok(frame @ (ServerFrame::BlobAck { .. }
                        | ServerFrame::BlobRejected { .. }
                        | ServerFrame::BlobChunk { .. })) => SubmitEvent::Blob(Box::new(frame)),
                    Ok(frame @ (ServerFrame::GroupState { .. } | ServerFrame::GroupRejected { .. })) => {
                        SubmitEvent::Group(Box::new(frame))
                    }
                    Ok(ServerFrame::Error { code: ErrorCode::Unauthenticated, message }) => {
                        warn!("relay refused anonymous submission: {message}");
                        return Ok(Exit::Refused);
                    }
                    Ok(ServerFrame::Error { code, message }) => {
                        warn!("relay error on anonymous submission: {message} ({code:?})");
                        continue;
                    }
                    Ok(_) => continue,
                    Err(e) => return Ok(Exit::Dropped(e.to_string())),
                };
                if events.send(event).await.is_err() {
                    return Ok(Exit::Closed);
                }
            }
        }
    }
}
