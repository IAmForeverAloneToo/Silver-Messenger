//! Tries the client on a real security key, by hand, before a release
//! that touches it (docs/design/security-key.md, section 7): makes a
//! throwaway credential, asks for the secret twice with one input and once
//! with another, and prints a short fingerprint of each, never the secret.
//!
//!     cargo run -p silver-key --example try-key
//!
//! Linux only for now (`/dev/hidraw`, with the key's udev rule). The PIN is
//! read from the terminal; a key with no PIN is given the one typed.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use silver_key::{Key, hidraw};

    const RP: &str = "silver-messenger.test";
    let path = hidraw::list()?
        .into_iter()
        .next()
        .ok_or("no security key found")?;
    println!("key: {}", path.display());
    let mut key = Key::open(hidraw::Hidraw::open(&path)?)?;
    key.on_touch(|| println!("touch the key"));
    let info = key.info().clone();
    println!(
        "versions {:?}, extensions {:?}, PIN protocols {:?}",
        info.versions, info.extensions, info.pin_protocols
    );
    info.check()?;
    let pin = prompt("PIN: ")?;
    if info.client_pin == Some(false) {
        key.set_pin(&pin)?;
        println!("PIN set");
    } else {
        println!("{} PIN tries left", key.pin_retries()?);
    }
    let id = key.register(RP, &pin)?;
    println!("credential: {} bytes", id.len());
    let fingerprint = |s: &[u8; 32]| -> String {
        Sha256::digest(s)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let (_, a) = key.prf(RP, &[(&id[..], &b"one"[..])], &pin)?;
    let (_, b) = key.prf(RP, &[(&id[..], &b"one"[..])], &pin)?;
    let (_, c) = key.prf(RP, &[(&id[..], &b"two"[..])], &pin)?;
    println!("input one: {}", fingerprint(&a));
    println!("input one: {}", fingerprint(&b));
    println!("input two: {}", fingerprint(&c));
    if a != b || a == c {
        return Err("the key's secrets do not behave".into());
    }
    println!("ok: the same input gives the same secret, another input another");
    Ok(())
}

#[cfg(target_os = "linux")]
fn prompt(text: &str) -> std::io::Result<String> {
    use std::io::Write;
    print!("{text}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("try-key talks to /dev/hidraw, on Linux only for now");
}
