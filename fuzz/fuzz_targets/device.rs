//! Device certificates as a member decodes them from a group leaf, and the
//! device statements, sync content and provisioning messages as they
//! arrive in JSON.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::device::{DeviceCertificate, DeviceRevocation, Provision, Sync};

fuzz_target!(|data: &[u8]| {
    if let Ok(certificate) = DeviceCertificate::decode(data) {
        // What decoded encodes to the same bytes, and verifies or not
        // without panicking.
        assert_eq!(certificate.encode(), data);
        let _ = certificate.verify();
    }
    if let Ok(certificate) = serde_json::from_slice::<DeviceCertificate>(data) {
        let _ = certificate.verify();
        let _ = DeviceCertificate::decode(&certificate.encode());
    }
    if let Ok(revocation) = serde_json::from_slice::<DeviceRevocation>(data) {
        let _ = revocation.verify();
    }
    let _ = serde_json::from_slice::<Sync>(data);
    let _ = serde_json::from_slice::<Provision>(data);
});
