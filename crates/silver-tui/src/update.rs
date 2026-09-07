//! `silver update`: the newest release, in place of this binary.
//!
//! Runs without the interface. A client with an unlocked data directory
//! and live sessions is the wrong place to be swapping its own file, and
//! a running process keeps its inode anyway, so there is nothing to gain
//! by doing this from inside the TUI (docs/design/updates.md, section 6).

use std::path::Path;

use anyhow::{Context, bail};
use silver_client::update::{
    self, RELEASE_BY_TAG_API, RELEASES_API, Release, compare, install, parse_version,
};
use silver_client::{Store, tls::ConnectOptions};

use crate::{Args, EnvSecrets, release_options};

/// One run of the subcommand.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    args: &Args,
    data_dir: &Path,
    secrets: &mut EnvSecrets,
    check_only: bool,
    rollback: bool,
    to: Option<String>,
    yes: bool,
) -> anyhow::Result<()> {
    let exe = install::running_binary()?;

    if rollback {
        return go_back(&exe);
    }

    // Whose binary this is decides everything else, so it is asked before
    // a single request goes out.
    if let install::Owner::Managed { manager, command } = install::who_owns(&exe) {
        println!(
            "{} is {manager}'s, so replacing it here would break its own checks and be undone\n\
             by its next upgrade. Update it with:\n\n    {command}\n",
            exe.display()
        );
        return Ok(());
    }

    let options = release_options(args.proxy.clone(), args.ca_cert.clone(), data_dir, secrets)?;
    let current = env!("CARGO_PKG_VERSION");

    let release = match &to {
        Some(version) => {
            let tag = if version.starts_with('v') {
                version.clone()
            } else {
                format!("v{version}")
            };
            update::release_by_tag(RELEASE_BY_TAG_API, &tag, &options)
                .await
                .with_context(|| format!("asking the releases page for {tag}"))?
        }
        None => update::latest_release(RELEASES_API, &options)
            .await
            .context("asking the releases page")?,
    };

    let newer = compare(release.version(), current);
    if to.is_none() {
        match newer {
            Some(std::cmp::Ordering::Equal) => {
                println!("Silver Messenger {current} is the newest release.");
                return Ok(());
            }
            Some(std::cmp::Ordering::Less) => {
                println!(
                    "This is Silver Messenger {current}; the newest release is {}.",
                    release.version()
                );
                return Ok(());
            }
            _ => {}
        }
    }

    if check_only {
        println!(
            "Silver Messenger {} is available; this is {current}.\n{}\n\n\
             Run `silver update` to install it.",
            release.version(),
            release.url
        );
        return Ok(());
    }

    // Going backwards is a decision, not a default: an older client may
    // not read what a newer one has written in the data directory, and a
    // stale release re-served is how a fixed hole is reopened.
    if matches!(newer, Some(std::cmp::Ordering::Less)) {
        if !yes {
            bail!(
                "{} is older than this client ({current}). An older client may not read what \n\
                 this one has written in {}. Pass --yes to install it anyway.",
                release.version(),
                data_dir.display()
            );
        }
        println!(
            "Going back to {} from {current}, as asked.",
            release.version()
        );
    }

    if !yes && !confirm(&release, current)? {
        println!("Nothing was changed.");
        return Ok(());
    }

    install_release(&release, &options, &exe, current).await
}

/// Download, check, and put in place.
async fn install_release(
    release: &Release,
    options: &ConnectOptions,
    exe: &Path,
    current: &str,
) -> anyhow::Result<()> {
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no directory", exe.display()))?;

    println!("Downloading Silver Messenger {}…", release.version());
    let downloaded = update::download_client(release, options, dir).await?;

    // The real test: a file that cannot say its own name does not replace
    // one that can. Everything before this checked bytes; this checks
    // that the bytes are a working client of the version expected.
    let reported = install::reported_version(&downloaded.path).map_err(|e| {
        let _ = std::fs::remove_file(&downloaded.path);
        e.context("the download does not run on this computer, so it was not installed")
    })?;
    if parse_version(&reported) != parse_version(release.version()) {
        let _ = std::fs::remove_file(&downloaded.path);
        bail!(
            "the download reports version {reported}, but {} was expected; nothing was changed",
            release.version()
        );
    }

    let backup = install::swap(&downloaded.path, exe).inspect_err(|_| {
        let _ = std::fs::remove_file(&downloaded.path);
    })?;

    println!(
        "\nSilver Messenger {current} → {}\n  {}\n\n\
         Checked against the releases page, SHA256SUMS{}.\n\
         The previous binary is at {}; `silver update --rollback` puts it back.",
        release.version(),
        exe.display(),
        if downloaded.signature_checked {
            " and the project's signature"
        } else {
            " (this client was built without a signing key, so no signature was checked)"
        },
        backup.display()
    );
    Ok(())
}

fn go_back(exe: &Path) -> anyhow::Result<()> {
    let backup = install::backup_path(exe);
    let version = install::reported_version(&backup)
        .with_context(|| format!("{} is not a working client", backup.display()))?;
    let current = env!("CARGO_PKG_VERSION");
    if parse_version(&version) == parse_version(current) {
        bail!(
            "{} is also {current}; there is nothing to go back to",
            backup.display()
        );
    }
    install::rollback(exe)?;
    println!(
        "Silver Messenger {current} → {version}\n  {}",
        exe.display()
    );
    Ok(())
}

/// Ask, unless told not to.
fn confirm(release: &Release, current: &str) -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};
    print!(
        "Replace Silver Messenger {current} with {}? [y/N] ",
        release.version()
    );
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        // No one is there to answer, so nothing is assumed.
        return Ok(false);
    }
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// The releases page is asked at most once a day, and only when the
/// `update-check` setting is on. Returns a line to show, if any.
///
/// Nothing is downloaded here, ever: this prints, and `silver update`
/// installs.
pub async fn daily_check(store: &Store, options: &ConnectOptions, today: &str) -> Option<String> {
    let mut config = store.load_config().ok()?;
    if !config.update_check {
        return None;
    }
    if config.update_checked_on.as_deref() == Some(today) {
        return None;
    }
    // Remembered before the request, so a failing network does not mean
    // asking again on every start.
    config.update_checked_on = Some(today.to_owned());
    let _ = store.save_config(&config);

    let release = update::latest_release(RELEASES_API, options).await.ok()?;
    let current = env!("CARGO_PKG_VERSION");
    match compare(release.version(), current) {
        Some(std::cmp::Ordering::Greater) => Some(format!(
            "Silver Messenger {} is available; this is {current}. Quit and run `silver update`.",
            release.version()
        )),
        _ => None,
    }
}
