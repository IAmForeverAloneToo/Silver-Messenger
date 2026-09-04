//! Sealed envelopes as a recipient decodes and opens them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::Identity;
use silver_protocol::envelope::{Envelope, open};
use silver_protocol::identity::IdentitySecrets;

fuzz_target!(|data: &[u8]| {
    let me = Identity::from_secrets(&IdentitySecrets {
        signing_seed: [7; 32],
        dh_secret: [8; 32],
    });
    if let Ok(envelope) = serde_json::from_slice::<Envelope>(data) {
        let _ = open(&me, &envelope);
    }
});
