//! The client's side of the login (`docs/PROTOCOL.md` section 7.1),
//! against a relay played by hand so the challenge can say what a real
//! relay would not.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_client::{Client, ClientEvent, ConnectOptions};
use silver_protocol::Identity;
use silver_protocol::wire::{ClientFrame, ServerFrame};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// A relay that answers every connection with a challenge saying whether
/// it understands the bound login, and then says what the client sent
/// back over `seen`.
async fn fake_relay(bound: bool) -> (String, mpsc::Receiver<Option<ClientFrame>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let challenge = ServerFrame::Challenge {
                    nonce: [7u8; 32],
                    bound,
                };
                if ws
                    .send(Message::Text(challenge.encode().into()))
                    .await
                    .is_err()
                {
                    return;
                }
                let first = match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => ClientFrame::decode(text.as_str()).ok(),
                    _ => None,
                };
                let _ = tx.send(first).await;
            });
        }
    });
    (format!("ws://{addr}/ws"), rx)
}

async fn wait_for(
    rx: &mut mpsc::Receiver<ClientEvent>,
    what: &str,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("client stopped while waiting for {what}"));
        if pred(&ev) {
            return ev;
        }
    }
}

/// The audit's SM-C-04: a relay that offers only the older login gets no
/// answer. Signing the challenge alone yields a login worth the same at
/// every relay, so a relay in the middle can forward the real relay's
/// challenge and use what comes back there.
#[tokio::test]
async fn a_relay_that_offers_only_the_unbound_login_is_refused() {
    let (url, mut seen) = fake_relay(false).await;
    let identity = Arc::new(Identity::generate());
    let (client, mut events) = Client::spawn(url, identity, ConnectOptions::default()).unwrap();
    let ev = wait_for(&mut events, "the refusal", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    let ClientEvent::Disconnected { reason, .. } = ev else {
        unreachable!()
    };
    assert!(reason.contains("0.6.0"), "{reason}");
    assert!(
        matches!(seen.recv().await, Some(None)),
        "nothing is signed for it"
    );
    client.shutdown().await;
}

/// With the flag the older login is answered, for a relay that predates
/// the bound one.
#[tokio::test]
async fn the_unbound_login_is_answered_when_it_is_allowed() {
    let (url, mut seen) = fake_relay(false).await;
    let identity = Arc::new(Identity::generate());
    let (client, mut events) = Client::spawn(
        url,
        identity.clone(),
        ConnectOptions {
            allow_unbound_login: true,
            ..Default::default()
        },
    )
    .unwrap();
    match seen.recv().await {
        Some(Some(ClientFrame::Auth { user_id, host, .. })) => {
            assert_eq!(user_id, identity.user_id());
            assert!(host.is_none(), "the older login carries no host");
        }
        other => panic!("{other:?}"),
    }
    // The fake relay says nothing further, so the client gives up on the
    // connection rather than hanging.
    wait_for(&mut events, "the disconnection", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    client.shutdown().await;
}

/// A relay that understands the bound login is answered with the host in
/// the signature.
#[tokio::test]
async fn a_bound_challenge_is_answered_with_the_host() {
    let (url, mut seen) = fake_relay(true).await;
    let identity = Arc::new(Identity::generate());
    let (client, _events) =
        Client::spawn(url, identity.clone(), ConnectOptions::default()).unwrap();
    match seen.recv().await {
        Some(Some(ClientFrame::Auth { host, .. })) => {
            assert_eq!(host.as_deref(), Some("127.0.0.1"));
        }
        other => panic!("{other:?}"),
    }
    client.shutdown().await;
}
