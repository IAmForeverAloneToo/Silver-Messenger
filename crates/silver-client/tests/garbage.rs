//! What the client parses from links, senders and its own files, fed
//! bytes nobody meant. Nothing may panic and every name that comes out of
//! the sanitiser must be one a file system and a screen can take. The
//! libfuzzer targets in `fuzz/` do the same for much longer.

use silver_client::files::{printable, refuse_to_open, sanitize_name};
use silver_client::{
    Config, Contact, ContactRequest, FileInfo, HeldMessage, HistoryEntry, InviteLink,
};
use silver_protocol::KeyBundle;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() % (max as u64 + 1)) as usize;
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// Text drawn from the characters that give sanitisers trouble.
    fn nasty_text(&mut self) -> String {
        const POOL: &[char] = &[
            'a',
            'Z',
            '.',
            ' ',
            '/',
            '\\',
            ':',
            '*',
            '?',
            '"',
            '<',
            '>',
            '|',
            '\u{202e}',
            '\u{200b}',
            '\u{feff}',
            '\u{301}',
            'e',
            '\x1b',
            '\x07',
            '\r',
            '\n',
            '\t',
            '\u{2028}',
            'C',
            'O',
            'N',
            '1',
            '_',
            '~',
            '\u{e9}',
            '日',
            '\u{1f600}',
        ];
        let len = (self.next() % 160) as usize;
        (0..len)
            .map(|_| POOL[(self.next() as usize) % POOL.len()])
            .collect()
    }
}

#[test]
fn names_from_anywhere_come_out_safe() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for _ in 0..5000 {
        let text = if rng.next() % 2 == 0 {
            rng.nasty_text()
        } else {
            String::from_utf8_lossy(&rng.bytes(200)).into_owned()
        };
        let name = sanitize_name(&text);
        assert!(!name.is_empty(), "{text:?}");
        assert!(name.chars().count() <= 120, "{name:?}");
        assert!(
            !name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']),
            "{name:?}"
        );
        assert!(!name.chars().any(|c| c.is_control()), "{name:?}");
        assert!(!name.starts_with('.'), "{name:?}");
        assert!(!name.ends_with(['.', ' ']), "{name:?}");
        assert!(
            !name.contains(['\u{202e}', '\u{200b}', '\u{feff}']),
            "{name:?}"
        );
        assert_eq!(sanitize_name(&name), name, "not idempotent for {text:?}");
        let _ = refuse_to_open(std::path::Path::new(&name));
        let shown = printable(&text, 40);
        assert!(shown.chars().count() <= 40 && !shown.chars().any(|c| c.is_control()));
    }
}

#[test]
fn links_and_stored_records_never_panic() {
    let mut rng = Rng(0x0F1E_2D3C_4B5A_6978);
    for _ in 0..3000 {
        let data = rng.bytes(300);
        if let Ok(text) = std::str::from_utf8(&data) {
            if let Ok(link) = text.parse::<InviteLink>() {
                assert!(link.to_string().parse::<InviteLink>().is_ok());
            }
        }
        let _ = serde_json::from_slice::<HistoryEntry>(&data);
        let _ = serde_json::from_slice::<HeldMessage>(&data);
        let _ = serde_json::from_slice::<ContactRequest>(&data);
        let _ = serde_json::from_slice::<Contact>(&data);
        let _ = serde_json::from_slice::<Config>(&data).map(|c| c.downloads_quota());
        if let Ok(info) = serde_json::from_slice::<FileInfo>(&data) {
            let _ = info.check();
            let _ = info.label();
        }
        if let Ok(bundle) = serde_json::from_slice::<KeyBundle>(&data) {
            let _ = bundle.verify();
        }
    }
    // Near-valid records: a real one with a field set to something absurd.
    let absurd = r#"{"id":"x","direction":"received","timestamp_ms":18446744073709551615,"text":"hi","file":{"type":"file","name":"a","size":18446744073709551615,"blob":"b","key":"AAAA","chunks":4294967295,"sha256":"AAAA"}}"#;
    if let Ok(entry) = serde_json::from_str::<HistoryEntry>(absurd) {
        if let Some(info) = entry.file {
            assert!(info.check().is_err());
        }
    }
}
