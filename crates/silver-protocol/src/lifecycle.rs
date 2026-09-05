//! Identity lifecycle: signed statements that retire or replace an identity
//! key, so a lost or rotated key no longer needs word of mouth.
//!
//! A [`Revocation`] is a self-signed statement that an identity is dead. It
//! is made when the identity is created and kept in the client's data and
//! its encrypted backup, so it can be published even after the private key
//! is gone — the way an OpenPGP revocation certificate is kept aside for
//! the day it is needed. Only the key holder could have produced a valid
//! one, so anyone may store and relay it.
//!
//! A [`Succession`] names a successor identity for a planned rotation, while
//! the old key still works. It is *cross-signed*: the old key authorises the
//! handover and the new key accepts it, the way Matrix cross-signing binds a
//! new device key, so nobody can name someone else's key as their successor.
//!
//! A contact verifies either statement against the key it has pinned for the
//! identity and then acts on it: a revocation retires the contact, a
//! succession re-pins it to the new key.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::encoding::b64_array;
use crate::identity::{Identity, UserId};

/// Domain for a revocation's self-signature.
pub const REVOCATION_DOMAIN: &[u8] = b"silver-messenger/v4/revocation";
/// Domain for the old key's signature over a succession.
pub const SUCCESSION_DOMAIN: &[u8] = b"silver-messenger/v4/succession";
/// Domain for the new key's acceptance of a succession.
pub const SUCCESSION_ACCEPT_DOMAIN: &[u8] = b"silver-messenger/v4/succession-accept";

/// A signed statement that an identity is revoked: dead, not to be trusted
/// or talked to any more. Self-signed by the identity it retires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub identity: UserId,
    pub created_at_ms: u64,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl Revocation {
    fn signed_bytes(identity: &UserId, created_at_ms: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(identity.as_bytes());
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v
    }

    /// Verify the self-signature.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.identity.verify(
            REVOCATION_DOMAIN,
            &Self::signed_bytes(&self.identity, self.created_at_ms),
            &self.signature,
        )
    }
}

/// A signed statement that `old` has handed over to `new`, cross-signed by
/// both keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Succession {
    pub old: UserId,
    pub new: UserId,
    pub created_at_ms: u64,
    /// The old key's signature: it authorises the handover.
    #[serde(with = "b64_array")]
    pub old_signature: [u8; 64],
    /// The new key's signature: it accepts the handover.
    #[serde(with = "b64_array")]
    pub new_signature: [u8; 64],
}

impl Succession {
    fn signed_bytes(old: &UserId, new: &UserId, created_at_ms: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(72);
        v.extend_from_slice(old.as_bytes());
        v.extend_from_slice(new.as_bytes());
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v
    }

    /// Verify both signatures and that the successor is a different key.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        if self.old == self.new {
            return Err(ProtocolError::Malformed(
                "a succession must name a different key".into(),
            ));
        }
        let message = Self::signed_bytes(&self.old, &self.new, self.created_at_ms);
        self.old
            .verify(SUCCESSION_DOMAIN, &message, &self.old_signature)?;
        self.new
            .verify(SUCCESSION_ACCEPT_DOMAIN, &message, &self.new_signature)
    }
}

impl Identity {
    /// A revocation certificate for this identity, to keep aside (in the
    /// backup) until the day the key must be declared dead.
    pub fn revocation(&self, created_at_ms: u64) -> Revocation {
        let identity = self.user_id();
        Revocation {
            signature: self.sign(
                REVOCATION_DOMAIN,
                &Revocation::signed_bytes(&identity, created_at_ms),
            ),
            identity,
            created_at_ms,
        }
    }

    /// A cross-signed succession from this (old) identity to `new`, for a
    /// planned rotation. `new` must be the identity being moved to.
    pub fn succeed_to(&self, new: &Identity, created_at_ms: u64) -> Succession {
        let (old_id, new_id) = (self.user_id(), new.user_id());
        let message = Succession::signed_bytes(&old_id, &new_id, created_at_ms);
        Succession {
            old_signature: self.sign(SUCCESSION_DOMAIN, &message),
            new_signature: new.sign(SUCCESSION_ACCEPT_DOMAIN, &message),
            old: old_id,
            new: new_id,
            created_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revocation_is_self_signed_and_tamper_evident() {
        let id = Identity::generate();
        let rev = id.revocation(1000);
        assert_eq!(rev.identity, id.user_id());
        assert!(rev.verify().is_ok());

        // A different identity's signature does not pass.
        let mut wrong_id = rev.clone();
        wrong_id.identity = Identity::generate().user_id();
        assert_eq!(wrong_id.verify(), Err(ProtocolError::InvalidSignature));
        // A changed timestamp breaks it.
        let mut moved = rev.clone();
        moved.created_at_ms = 1001;
        assert_eq!(moved.verify(), Err(ProtocolError::InvalidSignature));
        // Nobody but the key holder can forge one.
        let mut forged = rev.clone();
        forged.signature = Identity::generate().sign(
            REVOCATION_DOMAIN,
            &Revocation::signed_bytes(&rev.identity, rev.created_at_ms),
        );
        assert_eq!(forged.verify(), Err(ProtocolError::InvalidSignature));

        let json = serde_json::to_string(&rev).unwrap();
        assert_eq!(serde_json::from_str::<Revocation>(&json).unwrap(), rev);
    }

    #[test]
    fn a_succession_needs_both_keys() {
        let old = Identity::generate();
        let new = Identity::generate();
        let succ = old.succeed_to(&new, 2000);
        assert_eq!((succ.old, succ.new), (old.user_id(), new.user_id()));
        assert!(succ.verify().is_ok());

        // Missing or wrong new-key acceptance: refused. Nobody can name
        // another's key as their successor without that key's consent.
        let mut no_accept = succ.clone();
        no_accept.new = Identity::generate().user_id();
        assert_eq!(no_accept.verify(), Err(ProtocolError::InvalidSignature));
        // Missing old-key authorisation: refused. A key cannot claim to be
        // someone's successor on its own.
        let mut no_auth = succ.clone();
        no_auth.old = Identity::generate().user_id();
        assert_eq!(no_auth.verify(), Err(ProtocolError::InvalidSignature));
        // A tampered timestamp breaks both signatures.
        let mut moved = succ.clone();
        moved.created_at_ms = 2001;
        assert_eq!(moved.verify(), Err(ProtocolError::InvalidSignature));
        // Naming yourself is malformed.
        let self_succ = old.succeed_to(&old, 3000);
        assert!(matches!(
            self_succ.verify(),
            Err(ProtocolError::Malformed(_))
        ));

        let json = serde_json::to_string(&succ).unwrap();
        assert_eq!(serde_json::from_str::<Succession>(&json).unwrap(), succ);
    }
}
