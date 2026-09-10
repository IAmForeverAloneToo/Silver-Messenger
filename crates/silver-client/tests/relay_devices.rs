//! The relay's side of devices (`docs/PROTOCOL.md` section 14): a linked
//! device's bundle kept and served with its account, the claim in it
//! checked, `revoke_device` storing, logging and cutting the device off;
//! driven with raw WebSocket connections so each side of every rule can be
//! exercised.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use silver_client::{Client, ClientEvent, ConnectOptions};
use silver_protocol::bundle::capability;
use silver_protocol::transparency::{EntryKind, subject};
use silver_protocol::wire::{ClientFrame, ErrorCode, ServerFrame, auth_signature_bound, feature};
use silver_protocol::{
    Body, Content, DeviceCertificate, Identity, KeyBundle, PrekeySecret, Prekeys, Sequence, seal,
    seal_bytes,
};
use silver_relay::{Limits, Policy, RelayState, Store};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start() -> (String, Arc<RelayState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = RelayState::with_store_and_policy(
        Store::in_memory().unwrap(),
        Limits::default(),
        Policy::default(),
    );
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

/// Take the challenge and log in as `identity`; the relay's answer.
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

/// A fresh connection logged in as `identity`.
async fn connect(url: &str, identity: &Identity) -> Ws {
    let mut ws = open(url).await;
    assert!(
        matches!(login(&mut ws, identity).await, ServerFrame::AuthOk { .. }),
        "login refused"
    );
    ws
}

/// Publish `bundle` on `ws`, reading the prekey report that follows a
/// bundle with prekeys; the relay's first answer.
async fn publish(ws: &mut Ws, bundle: KeyBundle) -> ServerFrame {
    let has_prekeys = bundle.prekeys.is_some();
    let reply = ask(
        ws,
        &ClientFrame::Publish {
            bundle,
            invite: None,
        },
    )
    .await;
    if has_prekeys && reply == ServerFrame::Published {
        assert!(matches!(
            next(ws).await,
            Some(ServerFrame::PrekeyStatus { .. })
        ));
    }
    reply
}

/// A bundle with a signed prekey, two one-time prekeys and `caps`.
fn bundle_of(identity: &Identity, caps: &[&str]) -> KeyBundle {
    let signed = PrekeySecret::generate(1, 0).signed_by(identity);
    let one_time = vec![
        PrekeySecret::generate(2, 0).one_time(),
        PrekeySecret::generate(3, 0).one_time(),
    ];
    identity
        .key_bundle_with(Prekeys::classical(signed, one_time))
        .with_caps(identity, caps.iter().map(|c| (*c).to_owned()).collect())
}

/// A connection logged in as a fresh identity whose bundle, with prekeys
/// and `caps`, is published.
async fn member(url: &str, caps: &[&str]) -> (Ws, Identity) {
    let identity = Identity::generate();
    let mut ws = connect(url, &identity).await;
    assert_eq!(
        publish(&mut ws, bundle_of(&identity, caps)).await,
        ServerFrame::Published
    );
    (ws, identity)
}

/// A primary with the `devices` capability, and a device linked to it:
/// registered on its own, then republished with the certificate, then
/// put on the primary's published list. Both connections stay open.
async fn linked(url: &str) -> (Ws, Identity, Ws, Identity, DeviceCertificate) {
    let (mut primary_ws, primary) = member(url, &[capability::DEVICES]).await;
    let (mut device_ws, device) = member(url, &[capability::DEVICES]).await;
    let certificate = primary
        .certify_device(&device.user_id(), "laptop", 1)
        .unwrap();
    // The device presents the certificate with its own signature added
    // (section 14.1); the primary's list keeps the account's copy.
    assert_eq!(
        publish(
            &mut device_ws,
            bundle_of(&device, &[capability::DEVICES])
                .as_device_of(device.countersign_device(&certificate).unwrap())
        )
        .await,
        ServerFrame::Published
    );
    assert_eq!(
        publish(
            &mut primary_ws,
            bundle_of(&primary, &[capability::DEVICES])
                .with_devices(&primary, vec![certificate.clone()])
                .unwrap()
        )
        .await,
        ServerFrame::Published
    );
    (primary_ws, primary, device_ws, device, certificate)
}

async fn lookup(ws: &mut Ws, who: &Identity) -> ServerFrame {
    ask(
        ws,
        &ClientFrame::Lookup {
            user_id: who.user_id(),
        },
    )
    .await
}

fn is_error(frame: &ServerFrame, code: ErrorCode) -> bool {
    matches!(frame, ServerFrame::Error { code: c, .. } if *c == code)
}

fn envelope_to(from: &Identity, to: &Identity, text: &str) -> ClientFrame {
    ClientFrame::Send {
        envelope: seal(from, &to.key_bundle(), Content::text(text), 0).unwrap(),
    }
}

#[tokio::test]
async fn the_relay_advertises_devices() {
    let (url, _state) = start().await;
    let mut ws = open(&url).await;
    let ServerFrame::AuthOk { features, .. } = login(&mut ws, &Identity::generate()).await else {
        panic!("not logged in");
    };
    assert!(features.iter().any(|f| f == feature::DEVICES));
}

#[tokio::test]
async fn a_linked_device_is_served_with_its_account() {
    let (url, state) = start().await;
    let (_primary_ws, primary, _device_ws, device, certificate) = linked(&url).await;
    assert_eq!(state.stats().devices, 1);

    // A client that seals per device gets the list in the bundle and the
    // device's bundle along with it, a one-time prekey popped from each.
    let (mut bob_ws, _bob) = member(&url, &[capability::DEVICES]).await;
    let ServerFrame::LookupResult {
        bundle,
        device_bundles,
        device_revocations,
        ..
    } = lookup(&mut bob_ws, &primary).await
    else {
        panic!("not a lookup result");
    };
    let bundle = bundle.expect("the primary's bundle");
    assert_eq!(bundle.devices, vec![certificate.clone()]);
    assert!(bundle.verify().is_ok(), "served as signed, list and all");
    assert_eq!(bundle.prekeys.unwrap().one_time.len(), 1);
    assert_eq!(device_bundles.len(), 1);
    assert_eq!(device_bundles[0].user_id, device.user_id());
    // The device's bundle carries the certificate as the device presents
    // it, signed by both; the list above keeps the account's copy.
    assert_eq!(
        device_bundles[0].device_of,
        Some(device.countersign_device(&certificate).unwrap())
    );
    assert_eq!(
        device_bundles[0].prekeys.as_ref().unwrap().one_time.len(),
        1
    );
    assert!(device_revocations.is_empty());
    assert_eq!(state.one_time_prekeys_left(&device.user_id()), 1);

    // A client that does not seal per device sees the list, since it is
    // part of the signed bundle, and no device bundles: it would not use
    // them and their prekeys would be wasted on it.
    let (mut carol_ws, _carol) = member(&url, &[]).await;
    let ServerFrame::LookupResult {
        bundle,
        device_bundles,
        ..
    } = lookup(&mut carol_ws, &primary).await
    else {
        panic!("not a lookup result");
    };
    assert_eq!(bundle.unwrap().devices.len(), 1);
    assert!(device_bundles.is_empty());
    assert_eq!(state.one_time_prekeys_left(&device.user_id()), 1);

    // The device looked up on its own says whose it is.
    let ServerFrame::LookupResult {
        bundle,
        device_bundles,
        ..
    } = lookup(&mut bob_ws, &device).await
    else {
        panic!("not a lookup result");
    };
    // As the device published it: with its own signature, which the
    // account's list copy (`certificate`) does not carry.
    assert_eq!(
        bundle.unwrap().device_of,
        Some(device.countersign_device(&certificate).unwrap())
    );
    assert!(device_bundles.is_empty());
}

#[tokio::test]
async fn a_device_claim_is_checked_on_publish() {
    let (url, _state) = start().await;
    let primary = Identity::generate();
    let (mut device_ws, device) = member(&url, &[capability::DEVICES]).await;
    let certificate = primary
        .certify_device(&device.user_id(), "laptop", 1)
        .unwrap();
    let presented = device.countersign_device(&certificate).unwrap();
    let claim = || bundle_of(&device, &[capability::DEVICES]).as_device_of(presented.clone());
    // The account is not on this relay.
    let reply = publish(&mut device_ws, claim()).await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    // A certificate that does not verify (the wrong name) is a bad
    // signature, as any bundle that does not verify is.
    let mut forged = claim();
    forged.device_of.as_mut().unwrap().name = "phone".into();
    let reply = publish(&mut device_ws, forged).await;
    assert!(is_error(&reply, ErrorCode::BadSignature), "{reply:?}");
    // So is the certificate as the account minted it, without the
    // device's own signature (section 14.1, required from 0.17.0): a
    // device from before 0.16.0 presents exactly this, and is refused
    // until it updates -- the one older client a relay stops taking.
    let bare = bundle_of(&device, &[capability::DEVICES]).as_device_of(certificate.clone());
    let reply = publish(&mut device_ws, bare).await;
    assert!(is_error(&reply, ErrorCode::BadSignature), "{reply:?}");
    // Registered: taken. Revoked: refused.
    let mut primary_ws = connect(&url, &primary).await;
    assert_eq!(
        publish(&mut primary_ws, bundle_of(&primary, &[capability::DEVICES])).await,
        ServerFrame::Published
    );
    assert_eq!(
        publish(&mut device_ws, claim()).await,
        ServerFrame::Published
    );
    assert_eq!(
        publish(
            &mut primary_ws,
            bundle_of(&primary, &[capability::DEVICES])
                .with_devices(&primary, vec![certificate.clone()])
                .unwrap()
        )
        .await,
        ServerFrame::Published
    );
    // The account is revoked, as from a backup: a one-shot on a fresh
    // connection, which needs no login.
    let mut one_shot = open(&url).await;
    assert!(matches!(
        next(&mut one_shot).await,
        Some(ServerFrame::Challenge { .. })
    ));
    assert_eq!(
        ask(
            &mut one_shot,
            &ClientFrame::Revoke {
                revocation: primary.revocation(2)
            }
        )
        .await,
        ServerFrame::Published
    );
    assert!(
        next(&mut primary_ws).await.is_none(),
        "the dead account's connection is closed"
    );
    // The device's connection is closed with a word, and its next login
    // refused: its account is dead.
    assert!(matches!(
        next(&mut device_ws).await,
        Some(ServerFrame::Error {
            code: ErrorCode::Forbidden,
            ..
        })
    ));
    assert!(next(&mut device_ws).await.is_none());
    let mut again = open(&url).await;
    let reply = login(&mut again, &device).await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
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

/// The recipient's half of the requirement (section 14.1): a body whose
/// device certificate lacks the device's own signature is dropped, and
/// the recipient says so. A body is opaque to the relay, so whatever the
/// relay let through, this is the one check on that path -- and the
/// account's bare copy is exactly what a device from before 0.16.0
/// puts in every body it sends.
#[tokio::test]
async fn a_body_carrying_the_accounts_bare_certificate_is_dropped() {
    let (url, _state) = start().await;
    let (_primary_ws, primary, mut device_ws, device, certificate) = linked(&url).await;
    let bob = Arc::new(Identity::generate());
    let (_bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let from_device = |certificate: DeviceCertificate, text: &str| {
        let body = Body::plain(Content::text(text), 1, Sequence::default())
            .with_device(Some(certificate))
            .encode()
            .unwrap();
        ClientFrame::Send {
            envelope: seal_bytes(&device, &bob.key_bundle(), &body).unwrap(),
        }
    };
    // The account's copy: the relay carries it, bob refuses it.
    assert!(matches!(
        ask(&mut device_ws, &from_device(certificate.clone(), "bare")).await,
        ServerFrame::Sent { .. }
    ));
    let ClientEvent::Error(said) = wait_for(&mut bob_ev, "bob's refusal", |e| {
        matches!(e, ClientEvent::Error(_))
    })
    .await
    else {
        unreachable!("matched above");
    };
    assert!(said.contains("does not verify; dropped"), "{said}");
    // Signed by the device as well, the same body is the account's
    // message, from that device.
    let presented = device.countersign_device(&certificate).unwrap();
    assert!(matches!(
        ask(&mut device_ws, &from_device(presented, "signed")).await,
        ServerFrame::Sent { .. }
    ));
    let ClientEvent::Message(message) = wait_for(&mut bob_ev, "the signed text", |e| {
        matches!(e, ClientEvent::Message(_))
    })
    .await
    else {
        unreachable!("matched above");
    };
    assert_eq!(message.from, primary.user_id());
    assert_eq!(
        message.device.as_ref().map(|c| c.device),
        Some(device.user_id())
    );
    assert!(matches!(&message.content, Content::Text { body, .. } if body == "signed"));
}

#[tokio::test]
async fn revoke_device_cuts_the_device_off() {
    let (url, state) = start().await;
    let (mut primary_ws, primary, mut device_ws, device, certificate) = linked(&url).await;
    let (mut bob_ws, bob) = member(&url, &[capability::DEVICES]).await;
    assert!(matches!(
        ask(&mut bob_ws, &envelope_to(&bob, &device, "one")).await,
        ServerFrame::Sent { .. }
    ));
    assert!(matches!(
        next(&mut device_ws).await,
        Some(ServerFrame::Deliver { .. })
    ));

    let revocation = primary.revoke_device(&device.user_id(), 2);
    assert_eq!(
        ask(
            &mut primary_ws,
            &ClientFrame::RevokeDevice {
                revocation: revocation.clone()
            }
        )
        .await,
        ServerFrame::Published
    );
    // The device hears why and is closed; it cannot log in again, nor
    // publish; nothing more is queued for it, and what was is gone.
    assert!(matches!(
        next(&mut device_ws).await,
        Some(ServerFrame::Error {
            code: ErrorCode::Forbidden,
            ..
        })
    ));
    assert!(next(&mut device_ws).await.is_none());
    let mut again = open(&url).await;
    let reply = login(&mut again, &device).await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    assert_eq!(state.queued_for(&device.user_id()), 0);
    assert!(matches!(
        ask(&mut bob_ws, &envelope_to(&bob, &device, "two")).await,
        ServerFrame::Rejected {
            code: ErrorCode::NotFound,
            ..
        }
    ));
    // Served on the account's lookup, without the device's bundle, and on
    // the device's own, with the bundle the log covers.
    let ServerFrame::LookupResult {
        device_bundles,
        device_revocations,
        ..
    } = lookup(&mut bob_ws, &primary).await
    else {
        panic!("not a lookup result");
    };
    assert!(device_bundles.is_empty());
    assert_eq!(device_revocations, vec![revocation.clone()]);
    let ServerFrame::LookupResult {
        bundle,
        device_revocations,
        ..
    } = lookup(&mut bob_ws, &device).await
    else {
        panic!("not a lookup result");
    };
    assert_eq!(
        bundle.unwrap().device_of,
        Some(device.countersign_device(&certificate).unwrap())
    );
    assert_eq!(device_revocations, vec![revocation.clone()]);
    // Logged as a revocation of the device.
    let entries = state.store().log_since(0, 100).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.kind, EntryKind::Revocation);
    assert_eq!(last.subject, subject(&device.user_id()));
    assert_eq!(last.leaf, revocation.transparency_leaf());
    assert_eq!(state.stats().device_revocations, 1);
    // The primary cannot list the device again; without it, all is well;
    // and saying it again is answered without a second entry.
    let reply = publish(
        &mut primary_ws,
        bundle_of(&primary, &[capability::DEVICES])
            .with_devices(&primary, vec![certificate])
            .unwrap(),
    )
    .await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    assert_eq!(
        publish(&mut primary_ws, bundle_of(&primary, &[capability::DEVICES])).await,
        ServerFrame::Published
    );
    let logged = state.store().log_len().unwrap();
    assert_eq!(
        ask(
            &mut primary_ws,
            &ClientFrame::RevokeDevice {
                revocation: primary.revoke_device(&device.user_id(), 3)
            }
        )
        .await,
        ServerFrame::Published
    );
    assert_eq!(state.store().log_len().unwrap(), logged);
}

#[tokio::test]
async fn a_device_revocation_is_the_accounts_own_to_make() {
    let (url, state) = start().await;
    let (_primary_ws, primary, _device_ws, device, _) = linked(&url).await;
    let (mut stranger_ws, stranger) = member(&url, &[capability::DEVICES]).await;
    // The account's statement on someone else's connection.
    let reply = ask(
        &mut stranger_ws,
        &ClientFrame::RevokeDevice {
            revocation: primary.revoke_device(&device.user_id(), 2),
        },
    )
    .await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    // Someone else's statement about a device that is not theirs, and
    // about an identity that is nobody's device.
    for target in [device.user_id(), primary.user_id()] {
        let reply = ask(
            &mut stranger_ws,
            &ClientFrame::RevokeDevice {
                revocation: stranger.revoke_device(&target, 2),
            },
        )
        .await;
        assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    }
    assert!(!state.store().is_device_revoked(&device.user_id()).unwrap());
    assert!(!state.store().is_device_revoked(&primary.user_id()).unwrap());
    // Not on a connection that never logged in.
    let mut anonymous = open(&url).await;
    assert!(matches!(
        next(&mut anonymous).await,
        Some(ServerFrame::Challenge { .. })
    ));
    let reply = ask(
        &mut anonymous,
        &ClientFrame::RevokeDevice {
            revocation: primary.revoke_device(&device.user_id(), 2),
        },
    )
    .await;
    assert!(is_error(&reply, ErrorCode::Unauthenticated), "{reply:?}");
}

/// The audit's SM-R-01: an account that names another registered identity
/// on its device list and revokes it must not cut that identity off. The
/// list is taken (a device is listed while it still has a bundle of its
/// own, between registering and claiming), the statement is refused, and
/// the victim keeps its login, its publish and its mail.
#[tokio::test]
async fn an_account_cannot_cut_off_a_registered_identity_by_listing_it() {
    let (url, state) = start().await;
    let (mut attacker_ws, attacker) = member(&url, &[capability::DEVICES]).await;
    let (mut victim_ws, victim) = member(&url, &[capability::DEVICES]).await;
    let (mut other_ws, other) = member(&url, &[capability::DEVICES]).await;

    let forged = attacker
        .certify_device(&victim.user_id(), "not mine", 1)
        .unwrap();
    assert_eq!(
        publish(
            &mut attacker_ws,
            bundle_of(&attacker, &[capability::DEVICES])
                .with_devices(&attacker, vec![forged])
                .unwrap()
        )
        .await,
        ServerFrame::Published,
        "a list is taken before the device claims the account"
    );
    let reply = ask(
        &mut attacker_ws,
        &ClientFrame::RevokeDevice {
            revocation: attacker.revoke_device(&victim.user_id(), 2),
        },
    )
    .await;
    assert!(is_error(&reply, ErrorCode::Forbidden), "{reply:?}");
    assert!(!state.store().is_device_revoked(&victim.user_id()).unwrap());
    assert_eq!(
        state.store().log_len().unwrap(),
        state.store().log_len().unwrap(),
        "nothing is logged under the victim"
    );

    // The victim publishes, is looked up, receives and logs in again.
    assert_eq!(
        publish(&mut victim_ws, bundle_of(&victim, &[capability::DEVICES])).await,
        ServerFrame::Published
    );
    let answer = lookup(&mut other_ws, &victim).await;
    match answer {
        ServerFrame::LookupResult {
            bundle,
            device_revocations,
            ..
        } => {
            assert!(bundle.is_some());
            assert!(device_revocations.is_empty());
        }
        other => panic!("{other:?}"),
    }
    drop(victim_ws);
    let mut again = connect(&url, &victim).await;
    assert_eq!(
        publish(&mut again, bundle_of(&victim, &[capability::DEVICES])).await,
        ServerFrame::Published
    );
    send(&mut other_ws, &envelope_to(&other, &victim, "still here")).await;
    assert!(matches!(
        next(&mut other_ws).await,
        Some(ServerFrame::Sent { .. })
    ));
    assert!(matches!(
        next(&mut again).await,
        Some(ServerFrame::Deliver { .. })
    ));
}
