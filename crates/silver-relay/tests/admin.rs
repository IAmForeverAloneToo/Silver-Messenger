//! Administration over the Unix socket: what an operator sees and can
//! do, through the same client `silver-relay admin` uses.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use serde_json::Value;
use silver_protocol::{Content, Identity, PrekeySecret, Prekeys, seal};
use silver_relay::admin::{self, Status};
use silver_relay::{BanRow, IdentityRow, Limits, Policy, RelayState, Store};

async fn start(
    store: Store,
    policy: Policy,
) -> (Arc<RelayState>, tempfile::TempDir, std::path::PathBuf) {
    let state = RelayState::with_store_and_policy(store, Limits::default(), policy);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    tokio::spawn(admin::serve_unix(socket.clone(), state.clone(), None));
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    (state, dir, socket)
}

#[tokio::test]
async fn the_socket_lists_evicts_bans_and_sets_the_invite_token() {
    let store = Store::in_memory().unwrap();
    let bob = Identity::generate();
    let signed = PrekeySecret::generate(1, 0);
    store
        .put_bundle(&bob.key_bundle_with(Prekeys::classical(signed.signed_by(&bob), Vec::new())))
        .unwrap();
    store
        .set_one_time_prekeys(&bob.user_id(), &[PrekeySecret::generate(2, 0).one_time()])
        .unwrap();
    let alice = Identity::generate();
    let envelope = seal(
        &alice,
        &bob.key_bundle(),
        Content::Text {
            body: "waiting".into(),
        },
        0,
    )
    .unwrap();
    store.enqueue(&envelope, 1, Limits::default()).unwrap();

    let (state, _dir, socket) = start(
        store,
        Policy {
            invite_token: Some("from-the-command-line".into()),
            ..Policy::default()
        },
    )
    .await;
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Status.
    let (code, body) = admin::request(&socket, "GET", "/status", "").await.unwrap();
    assert_eq!(code, 200);
    let status: Status = serde_json::from_value(body).unwrap();
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(status.stats.bundles, 1);
    assert_eq!(status.stats.messages, 1);
    assert!(status.invite_required);
    assert!(status.tls.is_none());

    // Identities, by pseudonym, with the mailbox and the deposit.
    let (code, body) = admin::request(&socket, "GET", "/identities", "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    let rows: Vec<IdentityRow> = serde_json::from_value(body).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.who, state.who(&bob.user_id()));
    assert_ne!(row.who, bob.user_id().to_string(), "pseudonyms, not ids");
    assert_eq!(
        (row.messages, row.one_time_prekeys, row.online, row.banned),
        (1, 1, false, false)
    );
    assert!(row.bytes > 0);
    assert_eq!(row.signed_prekey_at_ms, Some(0));
    assert!(!row.post_quantum);

    // Bans on an address and on an identity by pseudonym, and their lifting.
    let (code, _) = admin::request(&socket, "POST", "/bans/address/203.0.113.5", "flood")
        .await
        .unwrap();
    assert_eq!(code, 204);
    assert!(state.address_banned("203.0.113.5".parse().unwrap()));
    let (code, _) = admin::request(&socket, "POST", &format!("/bans/identity/{}", row.who), "")
        .await
        .unwrap();
    assert_eq!(code, 204);
    assert!(state.user_banned(&bob.user_id()));
    let (_, body) = admin::request(&socket, "GET", "/bans", "").await.unwrap();
    let bans: Vec<BanRow> = serde_json::from_value(body).unwrap();
    assert_eq!(bans.len(), 2);
    assert_eq!(bans[0].target, "address:203.0.113.5");
    assert_eq!(bans[0].note, "flood");
    assert_eq!(bans[1].target, format!("identity:{}", row.who));
    let (_, body) = admin::request(&socket, "GET", "/identities", "")
        .await
        .unwrap();
    let rows: Vec<IdentityRow> = serde_json::from_value(body).unwrap();
    assert!(rows[0].banned);
    let (code, _) = admin::request(&socket, "DELETE", "/bans/address/203.0.113.5", "")
        .await
        .unwrap();
    assert_eq!(code, 204);
    assert!(!state.address_banned("203.0.113.5".parse().unwrap()));
    let (code, body) = admin::request(&socket, "DELETE", "/bans/address/203.0.113.5", "")
        .await
        .unwrap();
    assert_eq!(code, 404);
    assert!(body.as_str().unwrap().contains("not banned"));
    let (code, body) = admin::request(&socket, "POST", "/bans/address/not-an-ip", "")
        .await
        .unwrap();
    assert_eq!(code, 400);
    assert!(body.as_str().unwrap().contains("not an IP address"));
    let (code, _) = admin::request(&socket, "POST", "/bans/identity/nobody", "")
        .await
        .unwrap();
    assert_eq!(code, 404);

    // The invite token: set to a given value, to a random one, off, reset.
    let (code, body) = admin::request(&socket, "POST", "/invite", "let-me-in")
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(body["token"], Value::from("let-me-in"));
    assert_eq!(state.invite_token().as_deref(), Some("let-me-in"));
    let (_, body) = admin::request(&socket, "POST", "/invite", "")
        .await
        .unwrap();
    let random = body["token"].as_str().unwrap().to_owned();
    assert_eq!(random.len(), 24);
    assert_eq!(state.invite_token().as_deref(), Some(random.as_str()));
    let (code, _) = admin::request(&socket, "DELETE", "/invite", "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(state.invite_token(), None);
    let (_, body) = admin::request(&socket, "POST", "/invite/reset", "")
        .await
        .unwrap();
    assert_eq!(body["token"], Value::from("from-the-command-line"));
    assert_eq!(
        state.invite_token().as_deref(),
        Some("from-the-command-line")
    );

    // Eviction removes everything; the ban on the identity stays.
    let (code, body) = admin::request(&socket, "POST", &format!("/evict/{}", row.who), "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(body["removed"]["messages"], Value::from(1));
    assert_eq!(body["removed"]["prekeys"], Value::from(1));
    assert_eq!(body["removed"]["had_bundle"], Value::from(true));
    let (_, body) = admin::request(&socket, "GET", "/identities", "")
        .await
        .unwrap();
    assert_eq!(body.as_array().unwrap().len(), 0);
    assert!(state.user_banned(&bob.user_id()));
    // A pseudonym of a banned, evicted identity still resolves, so the ban can be lifted.
    let (code, _) = admin::request(
        &socket,
        "DELETE",
        &format!("/bans/identity/{}", row.who),
        "",
    )
    .await
    .unwrap();
    assert_eq!(code, 204);
    assert!(!state.user_banned(&bob.user_id()));
    let (code, _) = admin::request(&socket, "POST", &format!("/evict/{}", row.who), "")
        .await
        .unwrap();
    assert_eq!(code, 404, "nothing left to name it by");
}

#[tokio::test]
async fn runtime_choices_are_read_back_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.redb");
    {
        let state = RelayState::open_with(&path, Limits::default(), Policy::default()).unwrap();
        state.set_invite_token(Some("kept".into())).unwrap();
        state
            .ban(
                &silver_relay::BanTarget::Address("198.51.100.1".parse().unwrap()),
                "",
            )
            .unwrap();
    }
    let state = RelayState::open_with(&path, Limits::default(), Policy::default()).unwrap();
    assert_eq!(state.invite_token().as_deref(), Some("kept"));
    assert!(state.address_banned("198.51.100.1".parse().unwrap()));
    // "No token" is a choice too, and wins over the command line.
    state.set_invite_token(None).unwrap();
    drop(state);
    let state = RelayState::open_with(
        &path,
        Limits::default(),
        Policy {
            invite_token: Some("configured".into()),
            ..Policy::default()
        },
    )
    .unwrap();
    assert_eq!(state.invite_token(), None);
    state.forget_invite_token().unwrap();
    assert_eq!(state.invite_token().as_deref(), Some("configured"));
}
