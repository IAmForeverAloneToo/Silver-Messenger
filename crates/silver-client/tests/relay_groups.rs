//! The relay's key package deposit and group epoch sequencer
//! (`docs/PROTOCOL.md` section 13), driven with raw WebSocket connections
//! so each side of every rule can be exercised.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_protocol::group::{GroupId, token_hash};
use silver_protocol::wire::{
    ClientFrame, ErrorCode, KeyPackageDeposit, KeyPackageRef, ServerFrame, auth_signature_bound,
    feature,
};
use silver_protocol::{Identity, now_ms};
use silver_relay::{Limits, Policy, RelayState, Store};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

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

async fn open(url: &str) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

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

async fn ask(ws: &mut Ws, frame: &ClientFrame) -> ServerFrame {
    send(ws, frame).await;
    next(ws).await.expect("a reply")
}

/// Take the challenge and log in as `identity`; the relay's `auth_ok`.
async fn login(ws: &mut Ws, identity: &Identity) -> ServerFrame {
    let Some(ServerFrame::Challenge { nonce, .. }) = next(ws).await else {
        panic!("no challenge");
    };
    ask(
        ws,
        &ClientFrame::Auth {
            user_id: identity.user_id(),
            signature: auth_signature_bound(identity, "127.0.0.1", &nonce),
            host: Some("127.0.0.1".into()),
        },
    )
    .await
}

/// A fresh identity, logged in and with its bundle published.
async fn member(url: &str) -> (Ws, Identity) {
    let mut ws = open(url).await;
    let identity = Identity::generate();
    assert!(matches!(
        login(&mut ws, &identity).await,
        ServerFrame::AuthOk { .. }
    ));
    let reply = ask(
        &mut ws,
        &ClientFrame::Publish {
            bundle: identity.key_bundle(),
            invite: None,
        },
    )
    .await;
    assert_eq!(reply, ServerFrame::Published);
    (ws, identity)
}

/// Take the challenge and say nothing: the next frame makes the
/// connection anonymous.
async fn anonymous(url: &str) -> Ws {
    let mut ws = open(url).await;
    assert!(matches!(
        next(&mut ws).await,
        Some(ServerFrame::Challenge { .. })
    ));
    ws
}

fn package(n: u8) -> KeyPackageDeposit {
    KeyPackageDeposit {
        r#ref: [n; 32],
        expires_at_ms: now_ms() + 3_600_000,
        data: vec![n; 100],
    }
}

fn deposit(
    packages: Vec<KeyPackageDeposit>,
    last_resort: Option<KeyPackageDeposit>,
) -> ClientFrame {
    ClientFrame::KeyPackages {
        packages,
        last_resort,
    }
}

fn is_error(frame: &ServerFrame, code: ErrorCode) -> bool {
    matches!(frame, ServerFrame::Error { code: c, .. } if *c == code)
}

fn handed(frame: &ServerFrame) -> (Option<u8>, bool) {
    match frame {
        ServerFrame::KeyPackageResult {
            package,
            last_resort,
            ..
        } => (package.as_ref().map(|p| p.r#ref[0]), *last_resort),
        other => panic!("not a key package result: {other:?}"),
    }
}

#[tokio::test]
async fn the_relay_advertises_groups() {
    let (url, _state) = start(Policy::default()).await;
    let mut ws = open(&url).await;
    let ServerFrame::AuthOk { features, .. } = login(&mut ws, &Identity::generate()).await else {
        panic!("not logged in");
    };
    assert!(features.iter().any(|f| f == feature::GROUPS));
}

#[tokio::test]
async fn key_packages_go_on_deposit_and_come_out_oldest_first_then_the_last_resort() {
    let (url, _state) = start(Policy::default()).await;
    let (mut bob_ws, bob) = member(&url).await;
    let reply = ask(
        &mut bob_ws,
        &deposit(vec![package(1), package(2)], Some(package(9))),
    )
    .await;
    assert_eq!(
        reply,
        ServerFrame::KeyPackageStatus {
            remaining: 2,
            consumed: Vec::new()
        }
    );

    // Alice, who deposited nothing, may not ask.
    let (mut alice_ws, _alice) = member(&url).await;
    let refused = ask(
        &mut alice_ws,
        &ClientFrame::KeyPackage {
            user_id: bob.user_id(),
        },
    )
    .await;
    assert!(is_error(&refused, ErrorCode::Forbidden), "{refused:?}");

    // Once she has, she gets bob's oldest first, then the last resort as
    // often as she asks.
    ask(&mut alice_ws, &deposit(vec![package(3)], None)).await;
    let want = ClientFrame::KeyPackage {
        user_id: bob.user_id(),
    };
    assert_eq!(handed(&ask(&mut alice_ws, &want).await), (Some(1), false));
    assert_eq!(handed(&ask(&mut alice_ws, &want).await), (Some(2), false));
    assert_eq!(handed(&ask(&mut alice_ws, &want).await), (Some(9), true));
    assert_eq!(handed(&ask(&mut alice_ws, &want).await), (Some(9), true));
    // Nothing for an identity with no deposit.
    let nobody = ask(
        &mut alice_ws,
        &ClientFrame::KeyPackage {
            user_id: Identity::generate().user_id(),
        },
    )
    .await;
    assert_eq!(handed(&nobody), (None, false));

    // Bob's next deposit, a minute later, hears what was handed out: the
    // package he still lists is reported, the one he dropped is forgotten,
    // the new one queues.
    let (mut bob_again, _) = {
        let mut ws = open(&url).await;
        assert!(matches!(
            login(&mut ws, &bob).await,
            ServerFrame::AuthOk { .. }
        ));
        (ws, ())
    };
    let reply = ask(
        &mut bob_again,
        &deposit(vec![package(1), package(4)], Some(package(9))),
    )
    .await;
    assert_eq!(
        reply,
        ServerFrame::KeyPackageStatus {
            remaining: 1,
            consumed: vec![KeyPackageRef([1; 32])]
        }
    );
    // And not twice within a minute.
    let again = ask(&mut bob_again, &deposit(vec![package(5)], None)).await;
    assert!(is_error(&again, ErrorCode::RateLimited), "{again:?}");
}

#[tokio::test]
async fn a_deposit_is_checked_before_it_is_stored() {
    let (url, _state) = start(Policy::default()).await;
    // Each check on its own connection: a deposit spends the minute's one.
    let too_many: Vec<KeyPackageDeposit> = (0..31).map(|n| package(n as u8)).collect();
    let (mut ws, _) = member(&url).await;
    let reply = ask(&mut ws, &deposit(too_many, None)).await;
    assert!(is_error(&reply, ErrorCode::TooLarge), "{reply:?}");

    let (mut ws, _) = member(&url).await;
    let mut big = package(1);
    big.data = vec![1; 4097];
    let reply = ask(&mut ws, &deposit(vec![big], None)).await;
    assert!(is_error(&reply, ErrorCode::TooLarge), "{reply:?}");

    let (mut ws, _) = member(&url).await;
    let mut expired = package(1);
    expired.expires_at_ms = 1;
    let reply = ask(&mut ws, &deposit(vec![], Some(expired))).await;
    assert!(is_error(&reply, ErrorCode::Malformed), "{reply:?}");

    // No bundle, no deposit.
    let mut ws = open(&url).await;
    assert!(matches!(
        login(&mut ws, &Identity::generate()).await,
        ServerFrame::AuthOk { .. }
    ));
    let reply = ask(&mut ws, &deposit(vec![package(1)], None)).await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");

    // An anonymous connection can neither deposit nor ask.
    let mut ws = anonymous(&url).await;
    let reply = ask(&mut ws, &deposit(vec![package(1)], None)).await;
    assert!(is_error(&reply, ErrorCode::Unauthenticated), "{reply:?}");
}

#[tokio::test]
async fn the_sequencer_serves_any_connection_and_orders_commits() {
    let (url, _state) = start(Policy::default()).await;
    let group = GroupId([7; 32]);
    let (t0, t1, t2) = ([10u8; 32], [11u8; 32], [12u8; 32]);
    let state_at = |epoch| ServerFrame::GroupState { group, epoch };
    let rejected = |code, epoch| ServerFrame::GroupRejected { group, code, epoch };

    // Anonymous: create, idempotently; refuse other values.
    let mut ws = anonymous(&url).await;
    let create = ClientFrame::GroupCreate {
        group,
        epoch: 0,
        next: token_hash(&t0),
    };
    assert_eq!(ask(&mut ws, &create).await, state_at(0));
    assert_eq!(ask(&mut ws, &create).await, state_at(0));
    let other = ClientFrame::GroupCreate {
        group,
        epoch: 1,
        next: token_hash(&t0),
    };
    assert_eq!(
        ask(&mut ws, &other).await,
        rejected(ErrorCode::Exists, Some(0))
    );
    // Commits: the wrong epoch, the wrong token, the right one.
    let commit = |epoch, token, next: [u8; 32]| ClientFrame::GroupCommit {
        group,
        epoch,
        token,
        next: token_hash(&next),
    };
    assert_eq!(
        ask(&mut ws, &commit(1, t0, t1)).await,
        rejected(ErrorCode::Stale, Some(0))
    );
    assert_eq!(
        ask(&mut ws, &commit(0, t1, t1)).await,
        rejected(ErrorCode::Forbidden, None)
    );
    assert_eq!(ask(&mut ws, &commit(0, t0, t1)).await, state_at(1));
    // The loser of the race hears where the group stands.
    assert_eq!(
        ask(&mut ws, &commit(0, t0, t2)).await,
        rejected(ErrorCode::Stale, Some(1))
    );
    // An unknown group.
    let unknown = ClientFrame::GroupCommit {
        group: GroupId([8; 32]),
        epoch: 0,
        token: t0,
        next: token_hash(&t1),
    };
    assert_eq!(
        ask(&mut ws, &unknown).await,
        ServerFrame::GroupRejected {
            group: GroupId([8; 32]),
            code: ErrorCode::NotFound,
            epoch: None
        }
    );
    // An authenticated connection moves it on too.
    let (mut member_ws, _) = member(&url).await;
    assert_eq!(ask(&mut member_ws, &commit(1, t1, t2)).await, state_at(2));
    assert_eq!(_state.store().group_epoch(&group).unwrap(), Some(2));
}

#[tokio::test]
async fn the_number_of_groups_is_capped() {
    let (url, _state) = start(Policy {
        max_groups: 1,
        ..Policy::default()
    })
    .await;
    let mut ws = anonymous(&url).await;
    let create = |n: u8| ClientFrame::GroupCreate {
        group: GroupId([n; 32]),
        epoch: 0,
        next: [0; 32],
    };
    assert!(matches!(
        ask(&mut ws, &create(1)).await,
        ServerFrame::GroupState { .. }
    ));
    assert_eq!(
        ask(&mut ws, &create(2)).await,
        ServerFrame::GroupRejected {
            group: GroupId([2; 32]),
            code: ErrorCode::Forbidden,
            epoch: None
        }
    );
    // The one that exists is still answered.
    assert!(matches!(
        ask(&mut ws, &create(1)).await,
        ServerFrame::GroupState { .. }
    ));
}
