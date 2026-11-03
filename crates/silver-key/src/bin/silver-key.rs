//! `silver-key.exe`: the Windows 10 helper (docs/design/security-key.md,
//! section 5). Started elevated by the client, never by hand: it opens the
//! pipe named on its command line, asks for the security key's PIN in its
//! own window, talks to the key, writes one answer to the pipe and exits.
//! It reads nothing else: not the data directory, not the network, not
//! the client's settings.

#[cfg(windows)]
fn main() {
    use std::io::Write;

    use zeroize::Zeroizing;

    struct Console;

    impl silver_key::Prompt for Console {
        fn pin(&mut self, retries: Option<u32>, wrong: bool) -> Option<Zeroizing<String>> {
            if wrong {
                println!("Wrong PIN.");
            }
            let left = match retries {
                Some(n) if n <= 3 => format!(" ({n} tries left before the key locks itself)"),
                _ => String::new(),
            };
            let pin =
                rpassword::prompt_password(format!("Security key PIN{left}, or Enter to cancel: "))
                    .ok()?;
            (!pin.is_empty()).then(|| Zeroizing::new(pin))
        }

        fn new_pin(&mut self) -> Option<Zeroizing<String>> {
            println!("This security key has no PIN yet; it gets one now.");
            loop {
                let first = Zeroizing::new(
                    rpassword::prompt_password("New PIN for the key (4 to 63 characters): ")
                        .ok()?,
                );
                if first.is_empty() {
                    return None;
                }
                let second = Zeroizing::new(rpassword::prompt_password("Repeat the PIN: ").ok()?);
                if first == second {
                    return Some(first);
                }
                println!("They do not match; try again.");
            }
        }

        fn insert(&mut self) -> bool {
            print!("No security key found. Plug one in and press Enter, or type c to cancel: ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => false,
                Ok(_) => !line.trim().eq_ignore_ascii_case("c"),
            }
        }

        fn touch(&mut self) -> Box<dyn FnMut() + Send> {
            Box::new(|| println!("Touch your security key."))
        }
    }

    println!("Silver Messenger: unlocking with a security key.");
    let args: Vec<String> = std::env::args().skip(1).collect();
    match silver_key::windows::helper::serve(&args, Console) {
        Ok(()) => {}
        Err(silver_key::Error::Windows(text)) if text == "cancelled" => {}
        Err(e) => {
            println!("{e}");
            println!("This window closes in ten seconds.");
            std::thread::sleep(std::time::Duration::from_secs(10));
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "silver-key is the Windows 10 helper for security keys; elsewhere silver talks to the key itself."
    );
    std::process::exit(2);
}
