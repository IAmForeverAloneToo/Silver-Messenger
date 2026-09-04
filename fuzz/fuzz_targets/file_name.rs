//! File names as a sender chose them, and what is made of them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::files::{printable, refuse_to_open, sanitize_name};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let name = sanitize_name(&text);
    assert!(!name.is_empty());
    assert!(name.chars().count() <= 120, "{name:?}");
    assert!(!name.contains(['/', '\\']), "{name:?}");
    assert!(!name.chars().any(|c| c.is_control()), "{name:?}");
    assert!(!name.starts_with('.'), "{name:?}");
    assert!(!name.ends_with(['.', ' ']), "{name:?}");
    assert_eq!(sanitize_name(&name), name, "sanitizing is not idempotent");
    let _ = refuse_to_open(std::path::Path::new(&name));
    let shown = printable(&text, 40);
    assert!(shown.chars().count() <= 40);
    assert!(!shown.chars().any(|c| c.is_control()));
});
