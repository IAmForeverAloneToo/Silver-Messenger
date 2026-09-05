//! Frames exchanged between a client and a relay over a WebSocket.
//!
//! Frames are JSON text messages tagged with a `type` field. The relay never
//! needs to understand [`Envelope`] contents; it only routes on `to`.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::bundle::KeyBundle;
use crate::encoding::{b64, b64_array};
use crate::envelope::Envelope;
use crate::identity::{Identity, UserId};
use crate::lifecycle::{Revocation, Succession};

/// Domain of the v1 relay login: a signature over the challenge nonce
/// alone, which a hostile relay could collect and present elsewhere.
pub const AUTH_DOMAIN: &[u8] = b"silver-messenger/v1/relay-auth";
/// Domain of the v2 relay login: the signature also covers the host the
/// client connected to, so an answer meant for one relay is useless at
/// another.
pub const AUTH_BOUND_DOMAIN: &[u8] = b"silver-messenger/v2/relay-auth";

/// Largest WebSocket frame either side will accept.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

/// Default WebSocket path served by the relay.
pub const WS_PATH: &str = "/ws";

use crate::transparency::{LogEntry, LogHead, LogPosition};

/// Relay feature names advertised in [`ServerFrame::AuthOk`].
pub mod feature {
    /// The relay stores prekeys, hands out one-time prekeys on lookup and
    /// reports their status.
    pub const PREKEYS: &str = "prekeys";
    /// The relay accepts `Send` frames on connections that never
    /// authenticated, so a sender need not reveal itself to submit.
    pub const ANONYMOUS_SEND: &str = "anonymous_send";
    /// The relay stores encrypted file chunks (`BlobPut`/`BlobGet`), on
    /// anonymous connections too.
    pub const BLOBS: &str = "blobs";
    /// The relay keeps the ML-KEM keys of the post-quantum handshake
    /// (protocol v3) and hands out one-time ones. A relay without this
    /// drops them from bundles, and sessions through it stay classical.
    pub const PQ_PREKEYS: &str = "pq_prekeys";
    /// The relay accepts and serves identity revocations and successions
    /// (`Revoke`/`Succeed`), so a lost or rotated key reaches contacts on
    /// their next lookup. A relay without this drops them; contacts still
    /// learn from statements pushed inside messages.
    pub const LIFECYCLE: &str = "lifecycle";
    /// The relay keeps a hash-chained log of every bundle and lifecycle
    /// statement it serves (`docs/PROTOCOL.md` section 11), tells its head
    /// on login and lookup, and hands out entries on `LogSince`, so clients
    /// can check what they were shown and gossip the head to each other.
    pub const TRANSPARENCY: &str = "transparency";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
// A bundle with ML-KEM keys is a few hundred bytes larger than any other
// frame; frames are few and short-lived, so boxing it would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum ClientFrame {
    /// Prove ownership of `user_id` by signing the server's challenge nonce.
    /// With `host` (the relay's host name as the client connected to it,
    /// normalised by [`normalize_host`]) the signature is the v2 kind and
    /// covers the host too; without it, the v1 kind over the nonce alone.
    Auth {
        user_id: UserId,
        #[serde(with = "b64_array")]
        signature: [u8; 64],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// Publish (or refresh) our signed key bundle. A relay may require an
    /// invite token the first time an identity registers.
    Publish {
        bundle: KeyBundle,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite: Option<String>,
    },
    /// Ask for someone's key bundle.
    Lookup {
        user_id: UserId,
    },
    /// Ask for the transparency log entries after `index` (section 11),
    /// answered with `LogEntries`; a page at a time, so the client asks
    /// again from the last index it got until it reaches the head.
    LogSince {
        index: u64,
    },
    /// Declare an identity dead. The revocation is self-signed, so the
    /// relay accepts it without the connection authenticating as that
    /// identity — the key may be lost. The relay stores it, serves it on
    /// lookups, and refuses to let the identity publish again.
    Revoke {
        revocation: Revocation,
    },
    /// Announce that an identity has moved to a new one. Cross-signed by
    /// both keys, so the relay accepts it without authentication and serves
    /// it on lookups of the old identity.
    Succeed {
        succession: Succession,
    },
    /// Hand an encrypted envelope to the relay for delivery. Accepted on an
    /// authenticated connection, or (on relays advertising
    /// [`feature::ANONYMOUS_SEND`]) as the first frame after the challenge
    /// on a connection that never authenticates.
    Send {
        envelope: Envelope,
    },
    /// Confirm an envelope was received and persisted; the relay may drop it.
    Ack {
        id: String,
    },
    /// Store chunk `index` of `total` of an encrypted file under `blob`
    /// (a client-chosen random id). Accepted on anonymous connections.
    BlobPut {
        blob: String,
        index: u32,
        total: u32,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    /// Ask for every chunk of `blob`, answered with `BlobChunk` frames.
    BlobGet {
        blob: String,
    },
    Ping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthenticated,
    BadSignature,
    Malformed,
    TooLarge,
    Forbidden,
    MailboxFull,
    /// Too many requests from this connection; try again shortly.
    RateLimited,
    /// This relay only registers identities that present an invite token.
    InviteRequired,
    /// No such blob, or it was never completed.
    NotFound,
    /// The relay has no room for more file chunks.
    StorageFull,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // as for ClientFrame
pub enum ServerFrame {
    Challenge {
        #[serde(with = "b64_array")]
        nonce: [u8; 32],
        /// The relay understands the v2 login; a client that sees this
        /// answers with `host` set. Older relays omit it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        bound: bool,
    },
    AuthOk {
        user_id: UserId,
        /// What this relay can do beyond v1; see [`feature`]. Older relays
        /// omit the field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
        /// The head of the relay's transparency log right now; absent on
        /// relays without [`feature::TRANSPARENCY`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head: Option<LogHead>,
    },
    Published,
    /// Sent after `Published` to clients that publish prekeys: how many
    /// one-time prekeys the relay still holds, and which ids it has handed
    /// out since they were published.
    PrekeyStatus {
        one_time_remaining: u32,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        consumed: Vec<u32>,
        /// The same for one-time ML-KEM keys; a relay from before 0.6.0
        /// says nothing about them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pq_one_time_remaining: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pq_consumed: Vec<u32>,
    },
    LookupResult {
        user_id: UserId,
        bundle: Option<KeyBundle>,
        /// A revocation the relay holds for this identity (it is dead).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revocation: Option<Revocation>,
        /// A succession the relay holds for this identity (it moved).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        succession: Option<Succession>,
        /// The head of the transparency log at the time of the answer, and
        /// where this identity last appears in it; both absent on relays
        /// without [`feature::TRANSPARENCY`], `logged` also when nothing
        /// has been logged for the identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head: Option<LogHead>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        logged: Option<LogPosition>,
    },
    /// Transparency log entries in answer to `LogSince`, in order, and the
    /// head the relay stands at; `entries` is empty when `index` was the
    /// head already.
    LogEntries {
        entries: Vec<LogEntry>,
        head: LogHead,
    },
    /// The relay accepted the envelope with this id for delivery.
    Sent {
        id: String,
    },
    /// The relay refused to queue the envelope with this id; the sender
    /// should not retry it.
    Rejected {
        id: String,
        code: ErrorCode,
        message: String,
    },
    Deliver {
        envelope: Envelope,
    },
    /// A chunk was stored; `complete` once the blob has all of them.
    BlobAck {
        blob: String,
        index: u32,
        complete: bool,
    },
    /// A `BlobPut` or `BlobGet` for this blob failed.
    BlobRejected {
        blob: String,
        code: ErrorCode,
        message: String,
    },
    /// One chunk in answer to `BlobGet`; `total` says how many to expect.
    BlobChunk {
        blob: String,
        index: u32,
        total: u32,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    Pong,
    Error {
        code: ErrorCode,
        message: String,
    },
}

impl ClientFrame {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("frames are always serializable")
    }

    pub fn decode(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

impl ServerFrame {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("frames are always serializable")
    }

    pub fn decode(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Sign a relay challenge nonce (the v1 login).
pub fn auth_signature(identity: &Identity, nonce: &[u8; 32]) -> [u8; 64] {
    identity.sign(AUTH_DOMAIN, nonce)
}

/// Verify a client's v1 answer to a challenge.
pub fn verify_auth(
    user_id: &UserId,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    user_id.verify(AUTH_DOMAIN, nonce, signature)
}

/// What a v2 login signs: the host, then the nonce. The nonce has a fixed
/// length, so the two cannot be confused for each other.
fn bound_message(host: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = normalize_host(host).into_bytes();
    message.extend_from_slice(nonce);
    message
}

/// Sign a relay challenge for the relay at `host` (the v2 login).
pub fn auth_signature_bound(identity: &Identity, host: &str, nonce: &[u8; 32]) -> [u8; 64] {
    identity.sign(AUTH_BOUND_DOMAIN, &bound_message(host, nonce))
}

/// Verify a client's v2 answer to a challenge, given the host the relay
/// was reached as.
pub fn verify_auth_bound(
    user_id: &UserId,
    host: &str,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    user_id.verify(AUTH_BOUND_DOMAIN, &bound_message(host, nonce), signature)
}

/// A host name as it goes into a v2 login: lower case, no port, no IPv6
/// brackets, no trailing dot. Both sides normalise, so `Relay.Example:443`
/// in a URL and `relay.example:443` in a `Host` header agree.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = match host.strip_prefix('[') {
        // [::1]:7777 or [::1]
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => match host.rsplit_once(':') {
            // one colon: a port; more: a bare IPv6 address
            Some((name, port))
                if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) =>
            {
                name
            }
            _ => host,
        },
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The host part of a relay URL (`wss://user@relay.example:443/ws` gives
/// `relay.example`), normalised; `None` when the URL has none.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = normalize_host(host);
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_as_tagged_json() {
        let id = Identity::generate();
        let frame = ClientFrame::Lookup {
            user_id: id.user_id(),
        };
        let json = frame.encode();
        assert!(json.contains("\"type\":\"lookup\""));
        assert_eq!(ClientFrame::decode(&json).unwrap(), frame);

        let pong = ServerFrame::Pong.encode();
        assert_eq!(pong, "{\"type\":\"pong\"}");
        assert_eq!(ServerFrame::decode(&pong).unwrap(), ServerFrame::Pong);
    }

    #[test]
    fn a_v1_client_still_reads_frames_with_new_fields() {
        // The shapes clients before protocol v2 deserialize.
        #[derive(Deserialize, Debug)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum OldServerFrame {
            AuthOk { user_id: UserId },
            Published,
            Pong,
        }
        let id = Identity::generate().user_id();
        let auth_ok = ServerFrame::AuthOk {
            user_id: id,
            features: vec![feature::PREKEYS.into(), feature::ANONYMOUS_SEND.into()],
            head: Some(LogHead {
                index: 3,
                hash: [7; 32],
            }),
        }
        .encode();
        assert!(auth_ok.contains("\"features\"") && auth_ok.contains("\"head\""));
        assert!(matches!(
            serde_json::from_str(&auth_ok).unwrap(),
            OldServerFrame::AuthOk { user_id } if user_id == id
        ));
        assert!(matches!(
            serde_json::from_str(&ServerFrame::Published.encode()).unwrap(),
            OldServerFrame::Published
        ));
        // And a relay without the new field is read by new clients.
        let bare = format!("{{\"type\":\"auth_ok\",\"user_id\":\"{id}\"}}");
        assert_eq!(
            ServerFrame::decode(&bare).unwrap(),
            ServerFrame::AuthOk {
                user_id: id,
                features: Vec::new(),
                head: None,
            }
        );
        let status = ServerFrame::PrekeyStatus {
            one_time_remaining: 3,
            consumed: vec![7, 9],
            pq_one_time_remaining: Some(1),
            pq_consumed: vec![11],
        };
        assert_eq!(ServerFrame::decode(&status.encode()).unwrap(), status);
        // A relay from before 0.6.0 says nothing about ML-KEM keys.
        let old = r#"{"type":"prekey_status","one_time_remaining":3,"consumed":[7,9]}"#;
        assert_eq!(
            ServerFrame::decode(old).unwrap(),
            ServerFrame::PrekeyStatus {
                one_time_remaining: 3,
                consumed: vec![7, 9],
                pq_one_time_remaining: None,
                pq_consumed: Vec::new(),
            }
        );
    }

    #[test]
    fn auth_challenge_signature_verifies() {
        let id = Identity::generate();
        let nonce = [7u8; 32];
        let sig = auth_signature(&id, &nonce);
        assert!(verify_auth(&id.user_id(), &nonce, &sig).is_ok());
        assert!(verify_auth(&id.user_id(), &[8u8; 32], &sig).is_err());
        assert!(verify_auth(&Identity::generate().user_id(), &nonce, &sig).is_err());
    }

    #[test]
    fn a_bound_login_holds_only_at_its_relay() {
        let id = Identity::generate();
        let nonce = [7u8; 32];
        let sig = auth_signature_bound(&id, "Relay.Example:443", &nonce);
        assert!(verify_auth_bound(&id.user_id(), "relay.example", &nonce, &sig).is_ok());
        assert!(verify_auth_bound(&id.user_id(), "relay.example:8443", &nonce, &sig).is_ok());
        assert!(verify_auth_bound(&id.user_id(), "other.example", &nonce, &sig).is_err());
        assert!(verify_auth_bound(&id.user_id(), "relay.example", &[8u8; 32], &sig).is_err());
        // Neither kind of signature passes as the other.
        assert!(verify_auth(&id.user_id(), &nonce, &sig).is_err());
        let v1 = auth_signature(&id, &nonce);
        assert!(verify_auth_bound(&id.user_id(), "relay.example", &nonce, &v1).is_err());
    }

    #[test]
    fn hosts_normalise_the_same_from_urls_and_headers() {
        assert_eq!(normalize_host("Relay.Example.ORG:443"), "relay.example.org");
        assert_eq!(normalize_host("relay.example.org."), "relay.example.org");
        assert_eq!(normalize_host("127.0.0.1:7777"), "127.0.0.1");
        assert_eq!(normalize_host("[::1]:7777"), "::1");
        assert_eq!(normalize_host("[fe80::1]"), "fe80::1");
        assert_eq!(normalize_host("fe80::1"), "fe80::1");
        assert_eq!(normalize_host(" relay "), "relay");
        assert_eq!(
            url_host("wss://Relay.Example.org:443/ws").as_deref(),
            Some("relay.example.org")
        );
        assert_eq!(
            url_host("ws://127.0.0.1:7777/ws").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(url_host("ws://[::1]:7777/ws?x=1").as_deref(), Some("::1"));
        assert_eq!(url_host("ws://me@relay/ws").as_deref(), Some("relay"));
        assert_eq!(url_host("relay/ws"), None);
        assert_eq!(url_host("ws:///ws"), None);
        // An old relay's challenge has no `bound`; a new one's says so.
        let old = r#"{"type":"challenge","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        assert!(matches!(
            ServerFrame::decode(old).unwrap(),
            ServerFrame::Challenge { bound: false, .. }
        ));
        let new = ServerFrame::Challenge {
            nonce: [0; 32],
            bound: true,
        }
        .encode();
        assert!(new.contains("\"bound\":true"));
        let auth = ClientFrame::Auth {
            user_id: Identity::generate().user_id(),
            signature: [0; 64],
            host: None,
        }
        .encode();
        assert!(!auth.contains("host"));
    }
}
