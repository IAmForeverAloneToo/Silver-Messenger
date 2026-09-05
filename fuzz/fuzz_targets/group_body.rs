//! Group bodies, the group extension and an application message's
//! plaintext as a member decodes them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::envelope::Body;
use silver_protocol::group::{GroupPlaintext, SilverGroup, decode_seal_key};

fuzz_target!(|data: &[u8]| {
    if let Ok(Body::Group(body)) = Body::decode(data) {
        // What decoded passes the shape rules, and encodes again.
        assert!(body.validate().is_ok());
        assert!(Body::Group(body).encode().is_ok());
    }
    if let Ok(group) = SilverGroup::decode(data) {
        assert_eq!(group.encode().unwrap(), data);
    }
    let _ = GroupPlaintext::decode(data);
    let _ = decode_seal_key(data);
});
