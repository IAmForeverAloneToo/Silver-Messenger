//! The relay's limits that go by address rather than by connection, and
//! its idle timeout, driven with raw WebSocket connections so each one can
//! be counted, named and timed.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_protocol::Identity;
use silver_protocol::blob::{CHUNK_BYTES, new_blob_id};
use silver_protocol::wire::{ClientFrame, ErrorCode, ServerFrame, auth_signature};
use silver_relay::{Limits, Policy, RelayState, Store};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start(policy: Policy) -> (String, Arc<RelayState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state =
        RelayState::with_store_and_policy(Store::in_memory().unwrap(), Limits::default(), policy);
    tokio::spawn(silver_relay::serve(
        listener,
        state.clone(),
        std::future::pending(),
    ));
    (format!("ws://{addr}/ws"), state)
}

/// A connection, claiming to come from `forwarded_for` when given (the
/// relay trusts the loopback peer to say so, as it would a TLS front).
async fn open(url: &str, forwarded_for: Option<&str>) -> Ws {
    let mut request = url.into_client_request().unwrap();
    if let Some(ip) = forwarded_for {
        request
            .headers_mut()
            .insert("x-forwarded-for", ip.parse().unwrap());
    }
    let (ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws
}

/// The next frame, or `None` once the relay has closed the connection.
async fn next(ws: &mut Ws) -> Option<ServerFrame> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                return Some(ServerFrame::decode(text.as_str()).unwrap());
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => continue,
            Ok(Some(Ok(Message::Binary(_)))) => continue,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return None,
            Err(_) => panic!("no frame within 5 s"),
        }
    }
}

async fn send(ws: &mut Ws, frame: &ClientFrame) {
    ws.send(Message::Text(frame.encode().into())).await.unwrap();
}

fn is_refusal(frame: &Option<ServerFrame>, code: ErrorCode) -> bool {
    matches!(frame, Some(ServerFrame::Error { code: c, .. }) if *c == code)
}

/// Answer the challenge as a fresh identity.
async fn authenticate(ws: &mut Ws) -> Identity {
    let identity = Identity::generate();
    let Some(ServerFrame::Challenge { nonce }) = next(ws).await else {
        panic!("no challenge");
    };
    send(
        ws,
        &ClientFrame::Auth {
            user_id: identity.user_id(),
            signature: auth_signature(&identity, &nonce),
        },
    )
    .await;
    let Some(ServerFrame::AuthOk { .. }) = next(ws).await else {
        panic!("not authenticated");
    };
    identity
}

async fn publish(ws: &mut Ws, identity: &Identity) -> Option<ServerFrame> {
    send(
        ws,
        &ClientFrame::Publish {
            bundle: identity.key_bundle(),
            invite: None,
        },
    )
    .await;
    next(ws).await
}

#[tokio::test]
async fn connections_per_address_are_capped_and_places_come_back() {
    let (url, state) = start(Policy {
        connections_per_address: 2,
        ..Policy::default()
    })
    .await;
    let mut first = open(&url, None).await;
    let mut second = open(&url, None).await;
    assert!(matches!(
        next(&mut first).await,
        Some(ServerFrame::Challenge { .. })
    ));
    assert!(matches!(
        next(&mut second).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let mut third = open(&url, None).await;
    let refusal = next(&mut third).await;
    assert!(is_refusal(&refusal, ErrorCode::RateLimited), "{refusal:?}");
    assert!(
        next(&mut third).await.is_none(),
        "refused connections are closed"
    );
    assert_eq!(state.counters().refused_connections, 1);
    assert_eq!(state.counters().open_connections, 2);
    // A closed connection gives its place back.
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut again = open(&url, None).await;
    assert!(matches!(
        next(&mut again).await,
        Some(ServerFrame::Challenge { .. })
    ));
}

#[tokio::test]
async fn a_trusted_front_names_the_client() {
    let (url, state) = start(Policy {
        connections_per_address: 1,
        ..Policy::default()
    })
    .await;
    let mut a = open(&url, Some("203.0.113.5")).await;
    assert!(matches!(
        next(&mut a).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let mut a2 = open(&url, Some("203.0.113.5")).await;
    assert!(is_refusal(&next(&mut a2).await, ErrorCode::RateLimited));
    // The front's list may carry earlier hops; the last entry is what it saw.
    let mut b = open(&url, Some("10.0.0.1, 203.0.113.6")).await;
    assert!(matches!(
        next(&mut b).await,
        Some(ServerFrame::Challenge { .. })
    ));
    // Without the header the loopback peer counts as itself.
    let mut c = open(&url, None).await;
    assert!(matches!(
        next(&mut c).await,
        Some(ServerFrame::Challenge { .. })
    ));
    assert_eq!(state.counters().addresses, 3);

    // With explicit trusted proxies, a loopback peer's header is not taken.
    let (url, _) = start(Policy {
        connections_per_address: 1,
        trusted_proxies: vec!["192.0.2.1".parse().unwrap()],
        ..Policy::default()
    })
    .await;
    let mut a = open(&url, Some("203.0.113.5")).await;
    assert!(matches!(
        next(&mut a).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let mut b = open(&url, Some("203.0.113.6")).await;
    assert!(
        is_refusal(&next(&mut b).await, ErrorCode::RateLimited),
        "both count as the loopback peer"
    );
}

#[tokio::test]
async fn total_connections_are_capped() {
    let (url, _) = start(Policy {
        max_connections: 1,
        ..Policy::default()
    })
    .await;
    let mut first = open(&url, Some("203.0.113.1")).await;
    assert!(matches!(
        next(&mut first).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let mut second = open(&url, Some("203.0.113.2")).await;
    assert!(is_refusal(&next(&mut second).await, ErrorCode::RateLimited));
}

#[tokio::test]
async fn idle_connections_are_closed_and_pings_keep_them() {
    let (url, state) = start(Policy {
        idle_timeout: Duration::from_millis(800),
        ..Policy::default()
    })
    .await;
    let mut quiet = open(&url, None).await;
    authenticate(&mut quiet).await;
    let mut talkative = open(&url, None).await;
    authenticate(&mut talkative).await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        send(&mut talkative, &ClientFrame::Ping).await;
        assert!(matches!(
            next(&mut talkative).await,
            Some(ServerFrame::Pong)
        ));
    }
    assert!(next(&mut quiet).await.is_none(), "the quiet one was closed");
    assert_eq!(state.counters().idle_closed, 1);
    // Hung up by the client, so not counted as idle.
    drop(talkative);
    // The anonymous submission connection (opened by a file or send frame
    // instead of an answer to the challenge) is held to the same clock.
    let mut anonymous = open(&url, None).await;
    let Some(ServerFrame::Challenge { .. }) = next(&mut anonymous).await else {
        panic!("no challenge");
    };
    send(
        &mut anonymous,
        &ClientFrame::BlobGet {
            blob: new_blob_id(),
        },
    )
    .await;
    assert!(matches!(
        next(&mut anonymous).await,
        Some(ServerFrame::BlobRejected { .. })
    ));
    send(&mut anonymous, &ClientFrame::Ping).await;
    assert!(matches!(
        next(&mut anonymous).await,
        Some(ServerFrame::Pong)
    ));
    assert!(next(&mut anonymous).await.is_none(), "closed once idle");
    assert_eq!(state.counters().idle_closed, 2);
}

#[tokio::test]
async fn registrations_per_address_and_identities_are_capped() {
    let (url, state) = start(Policy {
        registrations_per_hour: 1,
        ..Policy::default()
    })
    .await;
    let mut a = open(&url, None).await;
    let alice = authenticate(&mut a).await;
    assert!(matches!(
        publish(&mut a, &alice).await,
        Some(ServerFrame::Published)
    ));
    let mut b = open(&url, None).await;
    let bob = authenticate(&mut b).await;
    assert!(is_refusal(
        &publish(&mut b, &bob).await,
        ErrorCode::RateLimited
    ));
    // A known identity publishing again is not a registration.
    assert!(matches!(
        publish(&mut a, &alice).await,
        Some(ServerFrame::Published)
    ));
    // Another address is not held back by this one.
    let mut c = open(&url, Some("203.0.113.9")).await;
    let carol = authenticate(&mut c).await;
    assert!(matches!(
        publish(&mut c, &carol).await,
        Some(ServerFrame::Published)
    ));
    assert_eq!(state.counters().refused_registrations, 1);

    let (url, state) = start(Policy {
        max_identities: 1,
        ..Policy::default()
    })
    .await;
    let mut a = open(&url, None).await;
    let alice = authenticate(&mut a).await;
    assert!(matches!(
        publish(&mut a, &alice).await,
        Some(ServerFrame::Published)
    ));
    let mut b = open(&url, Some("203.0.113.9")).await;
    let bob = authenticate(&mut b).await;
    assert!(is_refusal(
        &publish(&mut b, &bob).await,
        ErrorCode::Forbidden
    ));
    assert_eq!(state.counters().refused_registrations, 1);
}

#[tokio::test]
async fn uploads_per_address_are_limited() {
    let (url, state) = start(Policy {
        blob_mib_per_address_per_hour: 1,
        ..Policy::default()
    })
    .await;
    let mut ws = open(&url, None).await;
    authenticate(&mut ws).await;
    let blob = new_blob_id();
    let chunk = vec![7u8; CHUNK_BYTES + 16];
    let mut refused_at = None;
    for index in 0..20u32 {
        send(
            &mut ws,
            &ClientFrame::BlobPut {
                blob: blob.clone(),
                index,
                total: 20,
                data: chunk.clone(),
            },
        )
        .await;
        match next(&mut ws).await {
            Some(ServerFrame::BlobAck { .. }) => {}
            Some(ServerFrame::BlobRejected { code, message, .. }) => {
                assert_eq!(code, ErrorCode::RateLimited);
                assert!(message.contains("share"), "{message}");
                refused_at = Some(index);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    // 1 MiB is sixteen chunks; the one that would pass it is refused.
    assert_eq!(refused_at, Some(15), "refused at the wrong chunk");
    assert_eq!(state.counters().refused_uploads, 1);
    // Another address has its own share.
    let mut other = open(&url, Some("203.0.113.7")).await;
    authenticate(&mut other).await;
    send(
        &mut other,
        &ClientFrame::BlobPut {
            blob: new_blob_id(),
            index: 0,
            total: 1,
            data: chunk,
        },
    )
    .await;
    assert!(matches!(
        next(&mut other).await,
        Some(ServerFrame::BlobAck { .. })
    ));
}
