//! WebSocket frames as the relay and the client parse them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::wire::{ClientFrame, ServerFrame};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(frame) = ClientFrame::decode(text) {
        let again = frame.encode();
        assert!(ClientFrame::decode(&again).is_ok());
    }
    if let Ok(frame) = ServerFrame::decode(text) {
        let again = frame.encode();
        assert!(ServerFrame::decode(&again).is_ok());
    }
});
