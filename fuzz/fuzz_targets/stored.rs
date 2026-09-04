//! Everything the client reads back from its own data directory, and the
//! key bundles it takes from a relay.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::{Config, Contact, ContactRequest, FileInfo, HeldMessage, HistoryEntry};
use silver_protocol::KeyBundle;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<HistoryEntry>(data);
    let _ = serde_json::from_slice::<HeldMessage>(data);
    let _ = serde_json::from_slice::<ContactRequest>(data);
    let _ = serde_json::from_slice::<Contact>(data);
    let _ = serde_json::from_slice::<Config>(data).map(|c| c.downloads_quota());
    if let Ok(info) = serde_json::from_slice::<FileInfo>(data) {
        let _ = info.check();
        let _ = info.label();
    }
    if let Ok(bundle) = serde_json::from_slice::<KeyBundle>(data) {
        let _ = bundle.verify();
    }
});
