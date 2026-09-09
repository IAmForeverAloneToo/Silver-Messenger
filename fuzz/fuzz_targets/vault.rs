//! The encrypted-file format, read back from a directory somebody else
//! may have written to.
//!
//! The vault is what makes a copied data directory useless, so what it
//! must never do is hand back plaintext for a file it did not write.
//! Every file is bound to its own name, which is what stops one file
//! being swapped for another, and that binding is asserted here rather
//! than merely exercised: decrypting under the wrong name must fail, and
//! a round trip under the right one must come back byte for byte.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::FileCipher;
use silver_client::vault::{LINE_PREFIX, VaultFile};

fuzz_target!(|data: &[u8]| {
    // One key for the whole run: the fuzzer's job is the bytes, not the
    // key, and a key store key is a flat 32 bytes by construction.
    let (_vault, cipher) = FileCipher::create_with_kek(&[7u8; 32]);

    // Bytes off the disk, under the name they were found under. Nothing
    // here may panic, and nothing may come back as plaintext.
    let _ = cipher.decrypt("contacts.json", data);
    let _ = cipher.decrypt("", data);
    let _ = FileCipher::is_encrypted(data);

    if let Ok(text) = std::str::from_utf8(data) {
        // A history line, which is encrypted on its own so that appending
        // stays cheap -- and is therefore the piece an attacker with the
        // directory has the most copies of.
        let _ = cipher.decrypt_line("history/someone.jsonl", text);
        // A vault file: read before anything else, and the only thing
        // standing between a directory and the wrong key.
        if let Ok(vault) = serde_json::from_str::<VaultFile>(text) {
            let _ = FileCipher::unlock_with_kek(&vault, &[7u8; 32]);
            let _ = FileCipher::unlock_with_kek(&vault, &[0u8; 32]);
            let _ = vault.kdf.keystore_name();
            let _ = vault.kdf.is_keystore();
        }
    }

    // The binding: what this cipher wrote under one name must come back
    // under that name and nowhere else.
    let sealed = cipher.encrypt("sessions.json", data);
    assert!(
        FileCipher::is_encrypted(&sealed),
        "a file this cipher wrote was not recognised as encrypted"
    );
    let opened = cipher
        .decrypt("sessions.json", &sealed)
        .expect("a file this cipher wrote must open under its own name");
    assert_eq!(&opened[..], data, "a round trip changed the bytes");
    assert!(
        cipher.decrypt("contacts.json", &sealed).is_err(),
        "a file opened under a name it was not written under"
    );

    // The same, a line at a time. `encrypt_line` takes text, so this half
    // runs only when the input is text.
    if let Ok(text) = std::str::from_utf8(data) {
        let line = cipher.encrypt_line("history/a.jsonl", text);
        assert!(
            line.len() > LINE_PREFIX.len(),
            "an encrypted line came back with nothing in it"
        );
        let back = cipher
            .decrypt_line("history/a.jsonl", &line)
            .expect("a line this cipher wrote must open under its own name");
        assert_eq!(back, text, "a line round trip changed the text");
        assert!(
            cipher.decrypt_line("history/b.jsonl", &line).is_err(),
            "a line opened under a name it was not written under"
        );
    }

    // Not fuzzed here: `decrypt_with_passphrase`. What it adds over the
    // calls above is Argon2id, which costs a fuzzer sixteen milliseconds
    // an iteration -- a few thousand runs where these get a million --
    // and the bytes it then opens are opened by the same code. Its own
    // hazard, a `vault.json` demanding gigabytes of memory to unlock, is
    // a bounds check rather than something a fuzzer arrives at: `derive`
    // refuses parameters past MAX_M_COST_KIB, MAX_T_COST and MAX_P_COST
    // before Argon2 is built, and `vault.rs` tests that directly.
});
