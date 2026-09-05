//! Group invite links:
//! `silver://group/<group id>?via=<admin id>&key=<link key>[&relay=<url>]`.
//!
//! The link names the group, one admin who will add whoever presents it,
//! and the link key derived from the group's invite key
//! (`silver_protocol::group::link_key`), so a rotated invite key voids
//! every link made before.

use std::fmt;
use std::str::FromStr;

use silver_protocol::UserId;
use silver_protocol::group::GroupId;

use crate::invite::InviteError;

pub const SCHEME: &str = "silver://group/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLink {
    pub group: GroupId,
    pub via: UserId,
    pub key: [u8; 16],
    pub relay: Option<String>,
}

impl GroupLink {
    /// Whether `text` is a group link rather than a contact link or an id.
    pub fn looks_like(text: &str) -> bool {
        text.trim()
            .get(..SCHEME.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
    }
}

impl fmt::Display for GroupLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}?via={}&key={}",
            self.group,
            self.via,
            bs58::encode(self.key).into_string()
        )?;
        if let Some(relay) = &self.relay {
            write!(f, "&relay={}", crate::invite::percent_encode(relay))?;
        }
        Ok(())
    }
}

impl FromStr for GroupLink {
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
        let group: GroupId = id_part
            .trim_end_matches('/')
            .parse()
            .map_err(|_| InviteError::BadUserId)?;
        let mut via = None;
        let mut key = None;
        let mut relay = None;
        for (name, value) in query
            .into_iter()
            .flat_map(|q| q.split('&'))
            .filter_map(|pair| pair.split_once('='))
        {
            match name {
                "via" => {
                    via = Some(
                        value
                            .parse::<UserId>()
                            .map_err(|_| InviteError::BadUserId)?,
                    )
                }
                "key" => {
                    let bytes = bs58::decode(value)
                        .into_vec()
                        .map_err(|_| InviteError::BadUserId)?;
                    key = Some(<[u8; 16]>::try_from(bytes).map_err(|_| InviteError::BadUserId)?);
                }
                "relay" => {
                    let decoded = crate::invite::percent_decode(value);
                    if !decoded.is_empty() {
                        relay = Some(decoded);
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            group,
            via: via.ok_or(InviteError::BadUserId)?,
            key: key.ok_or(InviteError::BadUserId)?,
            relay,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;

    #[test]
    fn group_links_round_trip() {
        let link = GroupLink {
            group: GroupId::generate(),
            via: Identity::generate().user_id(),
            key: [3; 16],
            relay: Some("wss://relay.example.org/ws".into()),
        };
        let text = link.to_string();
        assert!(text.starts_with("silver://group/"));
        assert!(GroupLink::looks_like(&text));
        assert!(!crate::invite::InviteLink::looks_like(&text) || text.contains("group"));
        assert_eq!(text.parse::<GroupLink>().unwrap(), link);
        let bare = GroupLink {
            relay: None,
            ..link.clone()
        };
        assert_eq!(bare.to_string().parse::<GroupLink>().unwrap(), bare);
        assert_eq!(
            format!("SILVER://group/{}", link.group).parse::<GroupLink>(),
            Err(InviteError::BadUserId),
            "a link without an admin or a key is no use"
        );
        assert_eq!(
            "silver://add/x".parse::<GroupLink>(),
            Err(InviteError::NotALink)
        );
    }
}
