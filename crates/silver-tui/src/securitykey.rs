//! Unlocking with a security key at the terminal, before the interface
//! opens (docs/design/security-key.md): the PIN and the touch asked for
//! here, the recovery passphrase when no key can, and enrolling and
//! removing keys from the command line.

use std::io::{IsTerminal, Write};

use anyhow::{Context, bail};
use silver_client::{Missing, Protection, Store, VaultError};
use silver_key::Prompt;
use zeroize::Zeroizing;

use crate::{EnvSecrets, ask, new_passphrase};

/// The PIN, the touch and a missing key, asked about at the terminal.
struct TerminalPrompt {
    /// What an empty PIN or giving up on the key leads to.
    instead: &'static str,
}

impl Prompt for TerminalPrompt {
    fn pin(&mut self, retries: Option<u32>, wrong: bool) -> Option<Zeroizing<String>> {
        if wrong {
            eprintln!("Wrong PIN.");
        }
        let left = match retries {
            Some(1) => " (1 try left before the key locks itself)".to_owned(),
            Some(n) if n <= 3 => format!(" ({n} tries left before the key locks itself)"),
            _ => String::new(),
        };
        let pin = ask(&format!(
            "Security key PIN{left}, or Enter for {}: ",
            self.instead
        ))
        .ok()?;
        (!pin.is_empty()).then_some(pin)
    }

    fn new_pin(&mut self) -> Option<Zeroizing<String>> {
        eprintln!("This security key has no PIN yet; it gets one now. The key asks for it");
        eprintln!("from now on, and locks itself after eight wrong ones.");
        loop {
            let first = ask("New PIN for the key (4 to 63 characters): ").ok()?;
            if first.is_empty() {
                return None;
            }
            let second = ask("Repeat the PIN: ").ok()?;
            if first == second {
                return Some(first);
            }
            eprintln!("They do not match; try again.");
        }
    }

    fn insert(&mut self) -> bool {
        if !std::io::stdin().is_terminal() {
            eprintln!("No security key found.");
            return false;
        }
        eprint!(
            "No security key found. Plug one in and press Enter, or type r and Enter for {}: ",
            self.instead
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => false,
            Ok(_) => !line.trim().eq_ignore_ascii_case("r"),
        }
    }

    fn touch(&mut self) -> Box<dyn FnMut() + Send> {
        Box::new(|| eprintln!("Touch your security key."))
    }
}

fn authenticator(instead: &'static str) -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
    Ok(silver_key::platform(Box::new(TerminalPrompt { instead }))?)
}

/// Whether `e` is the person choosing something else, not a failure.
fn cancelled(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<silver_key::Error>(),
        Some(silver_key::Error::Cancelled)
    )
}

/// Unlock a directory a security key protects: the key, or the recovery
/// passphrase if no key can.
pub(crate) fn unlock(store: &mut Store, secrets: &mut EnvSecrets) -> anyhow::Result<()> {
    // SILVER_PASSPHRASE is the recovery passphrase here: a run nobody is
    // sitting at has nobody to touch the key.
    if let Some(passphrase) = secrets.spend() {
        return store.unlock(&passphrase).map_err(Into::into);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "a security key protects this data directory: run at a terminal, or give the \
             recovery passphrase in SILVER_PASSPHRASE"
        );
    }
    let keys = store.security_keys()?;
    eprintln!(
        "This data directory opens with its security key ({}), or the recovery passphrase.",
        keys.join(", ")
    );
    match authenticator("the recovery passphrase") {
        Ok(mut auth) => match store.unlock_with_security_key(auth.as_mut()) {
            Ok(()) => return Ok(()),
            Err(e) if cancelled(&e) => {}
            Err(e) => eprintln!("The security key did not open it: {e:#}."),
        },
        Err(e) => eprintln!("{e:#}."),
    }
    for attempt in 1..=3 {
        let passphrase = ask("Recovery passphrase: ")?;
        match store.unlock(&passphrase) {
            Ok(()) => return Ok(()),
            Err(VaultError::WrongPassphrase) if attempt < 3 => {
                eprintln!("Wrong recovery passphrase, try again.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!("too many failed attempts")
}

/// `--add-security-key [NAME]`.
pub(crate) fn add(
    store: &mut Store,
    secrets: &mut EnvSecrets,
    name: Option<&str>,
) -> anyhow::Result<()> {
    let first = store.protection() != Protection::SecurityKey;
    let recovery = if first {
        println!("A security key replaces what protects this data directory now. A recovery");
        println!("passphrase comes with it, to open the directory when no key can (one lost,");
        println!("broken or locked after too many wrong PINs): write it down and put it away.");
        Some(new_passphrase(secrets, "recovery passphrase")?)
    } else {
        None
    };
    let mut enrolled = enroll_one(store, name, recovery.as_deref().map(String::as_str))?;
    if first && std::io::stdin().is_terminal() {
        println!("A second key, kept somewhere else, opens the directory if this one is lost.");
        while crate::yes_no("Enroll another key now? [y/N]")? {
            println!("Unplug the first key and plug in the next.");
            match enroll_one(store, None, None) {
                Ok(name) => enrolled.push_str(&format!(", {name}")),
                Err(e) if cancelled(&e) => break,
                Err(e) => eprintln!("{e:#}"),
            }
        }
    }
    println!(
        "{} now opens with {enrolled}: its PIN and a touch at every start, or the recovery \
         passphrase.",
        store.root().display()
    );
    Ok(())
}

/// Enrolls the key plugged in, under `name` or the first free default.
fn enroll_one(
    store: &mut Store,
    name: Option<&str>,
    recovery: Option<&str>,
) -> anyhow::Result<String> {
    let taken = store.security_keys()?;
    let name = match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) => name.to_owned(),
        None => (1..)
            .map(|n| match n {
                1 => "security key".to_owned(),
                n => format!("security key {n}"),
            })
            .find(|n| !taken.contains(n))
            .expect("a free name"),
    };
    println!("Enrolling {name:?}: its PIN, then a touch, twice.");
    let mut auth = authenticator("cancelling")?;
    store
        .add_security_key(auth.as_mut(), &name, recovery)
        .context("enrolling the security key")?;
    Ok(name)
}

/// `--remove-security-key NAME`.
pub(crate) fn remove(
    store: &mut Store,
    secrets: &mut EnvSecrets,
    name: &str,
) -> anyhow::Result<()> {
    let keys = store.security_keys()?;
    if keys.is_empty() {
        bail!("no security key protects this data directory");
    }
    if !keys.iter().any(|k| k == name) {
        bail!(
            "no security key named {name:?} is enrolled (enrolled: {})",
            keys.join(", ")
        );
    }
    let recovery = recovery_passphrase(secrets)?;
    let others: Vec<&String> = keys.iter().filter(|k| *k != name).collect();
    if !others.is_empty() {
        let names: Vec<&str> = others.iter().map(|s| s.as_str()).collect();
        println!(
            "The directory moves to a fresh key, which each key that stays has to wrap: plug in \
             {} when asked.",
            names.join(", then ")
        );
    }
    let mut auth = authenticator("cancelling")?;
    let left = store.remove_security_key(name, auth.as_mut(), &recovery, &mut missing)?;
    match left {
        Protection::Passphrase => println!(
            "{name:?} removed. No security key is left: the recovery passphrase is now the \
             directory's passphrase, asked for at every start."
        ),
        _ => println!("{name:?} removed; it opens nothing written from now on."),
    }
    Ok(())
}

/// `--set-passphrase` on a directory a security key protects.
pub(crate) fn change_recovery(store: &mut Store, secrets: &mut EnvSecrets) -> anyhow::Result<()> {
    let old = recovery_passphrase(secrets)?;
    let new = new_passphrase(secrets, "recovery passphrase")?;
    println!("The directory moves to a fresh key, which each security key has to wrap.");
    let mut auth = authenticator("cancelling")?;
    store.change_recovery_passphrase(auth.as_mut(), &old, &new, &mut missing)?;
    println!("The recovery passphrase is changed; the old one opens nothing from now on.");
    Ok(())
}

fn recovery_passphrase(secrets: &mut EnvSecrets) -> anyhow::Result<Zeroizing<String>> {
    match secrets.spend() {
        Some(p) => Ok(p),
        None => ask("Recovery passphrase: "),
    }
}

/// A key that did not answer while the directory moves to a fresh data
/// key: try again, drop it, or give up.
fn missing(name: &str, e: &anyhow::Error) -> Missing {
    eprintln!("The key named {name:?} did not answer: {e:#}.");
    if !std::io::stdin().is_terminal() {
        return Missing::Cancel;
    }
    loop {
        eprint!(
            "Plug it in and type r to try again, d to drop it (it opens nothing from now on), \
             or c to change nothing: "
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            return Missing::Cancel;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "r" => return Missing::Retry,
            "d" => return Missing::Drop,
            "c" => return Missing::Cancel,
            _ => {}
        }
    }
}
