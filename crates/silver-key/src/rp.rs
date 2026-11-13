//! The relying party id. It is read from `vault.json`, which anything
//! running as the user can rewrite, and goes to the key, into the
//! `clientDataJSON` Windows' API is handed, and onto the elevated helper's
//! command line; so every route checks it is a host name before it goes
//! anywhere ([`check`]), and the JSON escapes it all the same.

use crate::Error;

/// A relying party id as this program writes one: a host name, letters,
/// digits, dots and hyphens, no longer than DNS allows. Nothing in it
/// needs quoting on a command line or escaping in JSON.
pub fn valid(rp_id: &str) -> bool {
    !rp_id.is_empty()
        && rp_id.len() <= 253
        && rp_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// [`valid`], as an error to return.
pub fn check(rp_id: &str) -> Result<(), Error> {
    if valid(rp_id) {
        Ok(())
    } else {
        Err(Error::InvalidRpId)
    }
}

/// `clientDataJSON` for a ceremony through Windows' API: its type, the
/// challenge in hex, and the origin the relying party id makes. The id has
/// been through [`check`] on its way here, so the escaping changes nothing
/// today; it is there so that a looser check later cannot turn into a
/// different document.
#[cfg(any(windows, test))]
pub(crate) fn client_data_json(kind: &str, challenge: &[u8; 32], rp_id: &str) -> Vec<u8> {
    debug_assert!(valid(rp_id));
    let challenge: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":false}}"#,
        json_string(kind),
        json_string(&challenge),
        json_string(&format!("https://{rp_id}")),
    )
    .into_bytes()
}

/// `text` as a JSON string, quotes included (RFC 8259, section 7).
#[cfg(any(windows, test))]
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_host_name_is_a_relying_party_id() {
        for good in ["silver-messenger.local", "a", "example.com"] {
            assert!(valid(good), "{good}");
            assert!(check(good).is_ok());
        }
        let long = "a".repeat(254);
        for bad in [
            "",
            "a b",
            "a\"b",
            "a\\b",
            "a\",\"origin\":\"https://elsewhere",
            "a\0b",
            "é.example",
            long.as_str(),
        ] {
            assert!(!valid(bad), "{bad:?}");
            assert!(matches!(check(bad), Err(Error::InvalidRpId)));
        }
    }

    #[test]
    fn client_data_is_the_json_it_should_be() {
        let json = client_data_json("webauthn.get", &[0xab; 32], "silver-messenger.local");
        let want = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://silver-messenger.local","crossOrigin":false}}"#,
            "ab".repeat(32)
        );
        assert_eq!(String::from_utf8(json).unwrap(), want);
    }

    #[test]
    fn a_json_string_is_escaped() {
        assert_eq!(json_string("plain"), r#""plain""#);
        assert_eq!(json_string("a\"b\\c\n\u{1}"), r#""a\"b\\c\u000a\u0001""#);
    }
}
