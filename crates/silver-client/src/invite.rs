//! Invite links: `silver://add/<user id>[?relay=<url>]`.
//!
//! An id is 44 characters of base58, which is a lot to read out or type.
//! A link carries it in a form that survives copy and paste, chat apps and
//! QR codes, and can name the relay the person uses so the other side
//! knows where to find them.

use std::fmt;
use std::str::FromStr;

use silver_protocol::UserId;

pub const SCHEME: &str = "silver://add/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteLink {
    pub user_id: UserId,
    pub relay: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("not an invite link (expected silver://add/<user-id>)")]
    NotALink,
    #[error("the link does not contain a valid user id")]
    BadUserId,
}

impl InviteLink {
    pub fn new(user_id: UserId, relay: Option<String>) -> Self {
        Self { user_id, relay }
    }

    /// Whether `text` looks like a link at all (as opposed to a bare id).
    pub fn looks_like(text: &str) -> bool {
        text.trim().to_ascii_lowercase().starts_with("silver://")
    }
}

impl fmt::Display for InviteLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.user_id)?;
        if let Some(relay) = &self.relay {
            write!(f, "?relay={}", percent_encode(relay))?;
        }
        Ok(())
    }
}

impl FromStr for InviteLink {
    type Err = InviteError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let rest = text
            .get(..SCHEME.len())
            .filter(|head| head.eq_ignore_ascii_case(SCHEME))
            .map(|_| &text[SCHEME.len()..])
            .ok_or(InviteError::NotALink)?;
        let (id_part, query) = match rest.split_once('?') {
            Some((id, query)) => (id, Some(query)),
            None => (rest, None),
        };
        let user_id = id_part
            .trim_end_matches('/')
            .parse()
            .map_err(|_| InviteError::BadUserId)?;
        let relay = query
            .into_iter()
            .flat_map(|q| q.split('&'))
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == "relay")
            .map(|(_, value)| percent_decode(value))
            .filter(|relay| !relay.is_empty());
        Ok(Self { user_id, relay })
    }
}

pub(crate) fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub(crate) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(value) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;

    #[test]
    fn links_round_trip_with_and_without_a_relay() {
        let id = Identity::generate().user_id();
        let plain = InviteLink::new(id, None);
        let text = plain.to_string();
        assert_eq!(text, format!("silver://add/{id}"));
        assert_eq!(text.parse::<InviteLink>().unwrap(), plain);

        let with_relay = InviteLink::new(id, Some("wss://relay.example.org/ws".into()));
        let text = with_relay.to_string();
        assert_eq!(
            text,
            format!("silver://add/{id}?relay=wss%3A%2F%2Frelay.example.org%2Fws")
        );
        assert_eq!(text.parse::<InviteLink>().unwrap(), with_relay);
        // Case and whitespace around the scheme are forgiven, as is an
        // unencoded relay, which is what a person types by hand.
        let typed = format!("  SILVER://add/{id}?relay=wss://relay.example.org/ws ");
        assert_eq!(typed.parse::<InviteLink>().unwrap(), with_relay);
        assert!(InviteLink::looks_like(&typed));
        assert!(!InviteLink::looks_like(&id.to_string()));
    }

    #[test]
    fn bad_links_are_rejected() {
        assert_eq!(
            "https://example.org".parse::<InviteLink>(),
            Err(InviteError::NotALink)
        );
        assert_eq!(
            "silver://add/not-an-id".parse::<InviteLink>(),
            Err(InviteError::BadUserId)
        );
        assert_eq!(percent_decode("a%2Fb%zz%4"), "a/b%zz%4");
    }
}
