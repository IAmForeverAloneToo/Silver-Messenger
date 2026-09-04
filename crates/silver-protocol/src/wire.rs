//! Frames exchanged between a client and a relay over a WebSocket.
//!
//! Frames are JSON text messages tagged with a `type` field. The relay never
//! needs to understand [`Envelope`] contents; it only routes on `to`.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::bundle::KeyBundle;
use crate::encoding::b64_array;
use crate::envelope::Envelope;
use crate::identity::{Identity, UserId};

pub const AUTH_DOMAIN: &[u8] = b"silver-messenger/v1/relay-auth";

/// Largest WebSocket frame either side will accept.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

/// Default WebSocket path served by the relay.
pub const WS_PATH: &str = "/ws";

/// Relay feature names advertised in [`ServerFrame::AuthOk`].
pub mod feature {
    /// The relay stores prekeys, hands out one-time prekeys on lookup and
    /// reports their status.
    pub const PREKEYS: &str = "prekeys";
    /// The relay accepts `Send` frames on connections that never
    /// authenticated, so a sender need not reveal itself to submit.
    pub const ANONYMOUS_SEND: &str = "anonymous_send";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Prove ownership of `user_id` by signing the server's challenge nonce.
    Auth {
        user_id: UserId,
        #[serde(with = "b64_array")]
        signature: [u8; 64],
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
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Challenge {
        #[serde(with = "b64_array")]
        nonce: [u8; 32],
    },
    AuthOk {
        user_id: UserId,
        /// What this relay can do beyond v1; see [`feature`]. Older relays
        /// omit the field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
    },
    Published,
    /// Sent after `Published` to clients that publish prekeys: how many
    /// one-time prekeys the relay still holds, and which ids it has handed
    /// out since they were published.
    PrekeyStatus {
        one_time_remaining: u32,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        consumed: Vec<u32>,
    },
    LookupResult {
        user_id: UserId,
        bundle: Option<KeyBundle>,
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

/// Sign a relay challenge nonce.
pub fn auth_signature(identity: &Identity, nonce: &[u8; 32]) -> [u8; 64] {
    identity.sign(AUTH_DOMAIN, nonce)
}

/// Verify a client's answer to a challenge.
pub fn verify_auth(
    user_id: &UserId,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    user_id.verify(AUTH_DOMAIN, nonce, signature)
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
        }
        .encode();
        assert!(auth_ok.contains("\"features\""));
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
                features: Vec::new()
            }
        );
        let status = ServerFrame::PrekeyStatus {
            one_time_remaining: 3,
            consumed: vec![7, 9],
        };
        assert_eq!(ServerFrame::decode(&status.encode()).unwrap(), status);
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
}
