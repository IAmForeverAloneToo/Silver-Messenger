//! Updating: the newest release, in place of this binary.
//!
//! From inside the client, as other messengers do it: `/update` (or the
//! daily check, when it is on) downloads and checks the release in the
//! background while the client is in use, and once it is ready, `/update`
//! again puts it in place of this binary and starts it, asking for the
//! unlock as after `/lock` (docs/design/updates.md, section 6). The
//! download waits in the data directory; the previous version is kept
//! there too, for `silver update --rollback`; nothing is left beside the
//! program. `silver update` from a shell does the same without the
//! interface.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use silver_client::update::{
    self, RELEASE_BY_TAG_API, RELEASES_API, Release, compare, install, parse_version,
};
use silver_client::{Store, tls::ConnectOptions};

use crate::{Args, EnvSecrets, release_options};

/// A release downloaded and checked, waiting in the data directory to be
/// put in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    pub version: String,
    pub path: PathBuf,
}

/// Download the client in `release`, check it every way there is (the
/// releases page's digest, SHA256SUMS and its signature, and the file
/// itself reporting the version it should), and leave it in the data
/// directory.
pub async fn prepare(
    release: &Release,
    options: &ConnectOptions,
    data_dir: &Path,
) -> anyhow::Result<Staged> {
    let dir = install::staging_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("making {}", dir.display()))?;
    let downloaded = update::download_client(release, options, &dir).await?;
    // The real test: a file that cannot say its own name does not replace
    // one that can.
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
    Ok(Staged {
        version: release.version().to_owned(),
        path: downloaded.path,
    })
}

/// Whether this binary is ours to replace; the command that updates it
/// if a package manager owns it.
pub fn managed_by() -> Option<String> {
    let exe = install::running_binary().ok()?;
    match install::who_owns(&exe) {
        install::Owner::Managed { command, .. } => Some(command),
        install::Owner::Ours => None,
    }
}

/// Put `staged` in place of this binary, keeping the one it replaces in
/// the data directory.
pub fn apply(staged: &Staged, data_dir: &Path) -> anyhow::Result<()> {
    let exe = install::running_binary()?;
    if let Some(command) = managed_by() {
        let _ = std::fs::remove_file(&staged.path);
        bail!("this binary is managed by a package manager; update it with: {command}");
    }
    install::swap(&staged.path, &exe, &install::kept_path(data_dir, &exe)).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged.path);
    })
}

/// Start this program again, from the file now at its path, with the
/// arguments it was given. On Unix the process becomes the new one; on
/// Windows, which has no such call, the new one runs in this console and
/// this one waits for it and leaves with its exit code.
pub fn relaunch() -> anyhow::Result<std::convert::Infallible> {
    let exe = install::running_binary()?;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let e = std::process::Command::new(&exe).args(&args).exec();
        Err(e).with_context(|| format!("starting {}", exe.display()))
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(&exe)
            .args(&args)
            .status()
            .with_context(|| format!("starting {}", exe.display()))?;
        std::process::exit(status.code().unwrap_or(0));
    }
}

/// The settings' proxy and certificate for a request to the releases
/// page, as the relay connection goes: from inside the client, where the
/// directory is already open.
pub fn options_from(config: &silver_client::Config) -> ConnectOptions {
    ConnectOptions {
        extra_ca_certs: config.ca_cert.iter().cloned().collect(),
        proxy: config
            .proxy
            .clone()
            .or_else(silver_client::Proxy::url_from_env),
        ..Default::default()
    }
}

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
        return go_back(&exe, data_dir);
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

    install_release(&release, &options, data_dir, current).await
}

/// Download, check, and put in place.
async fn install_release(
    release: &Release,
    options: &ConnectOptions,
    data_dir: &Path,
    current: &str,
) -> anyhow::Result<()> {
    println!("Downloading Silver Messenger {}…", release.version());
    let staged = prepare(release, options, data_dir).await?;
    apply(&staged, data_dir)?;
    println!(
        "\nSilver Messenger {current} → {}\n  {}\n\n\
         Checked against the releases page, SHA256SUMS and the project's signature.\n\
         Start silver again to use it; `silver update --rollback` goes back to {current}.",
        release.version(),
        install::running_binary()?.display(),
    );
    Ok(())
}

fn go_back(exe: &Path, data_dir: &Path) -> anyhow::Result<()> {
    let kept = install::kept_path(data_dir, exe);
    let version = install::reported_version(&kept)
        .with_context(|| format!("{} is not a working client", kept.display()))?;
    let current = env!("CARGO_PKG_VERSION");
    if parse_version(&version) == parse_version(current) {
        bail!(
            "{} is also {current}; there is nothing to go back to",
            kept.display()
        );
    }
    install::rollback(exe, &kept)?;
    println!(
        "Silver Messenger {current} → {version}\n  {}",
        exe.display()
    );
    Ok(())
}

/// Ask, unless told not to. No one there to answer is a no.
fn confirm(release: &Release, current: &str) -> anyhow::Result<bool> {
    crate::yes_no(&format!(
        "Replace Silver Messenger {current} with {}? [y/N]",
        release.version()
    ))
}

/// The releases page is asked at most once a day, and only when the
/// `update-check` setting is on. Returns the newer release, if there is
/// one; the client then gets it ready in the background.
pub async fn daily_check(store: &Store, options: &ConnectOptions, today: &str) -> Option<Release> {
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
        Some(std::cmp::Ordering::Greater) => Some(release),
        _ => None,
    }
}
