//! Putting a checked download in place of the running binary.
//!
//! Two rules shape all of this. A running program must never be written
//! over — on Unix that would change the pages under it, on Windows the
//! operating system refuses — so the new file is written beside the old
//! one and *renamed* over it, which is one step and cannot half-happen.
//! And a binary a package manager owns is not ours to replace: doing so
//! breaks that manager's own verification and is undone by its next
//! upgrade, so it is refused with that manager's command instead.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Whose binary this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    /// Ours to replace.
    Ours,
    /// Someone else's, with what to run instead.
    Managed {
        /// What manages it, for the message.
        manager: &'static str,
        /// The command that updates it properly.
        command: String,
    },
}

/// Where this binary is, with symbolic links followed.
///
/// A link is followed because replacing the link would leave the real
/// binary behind and break every other name pointing at it.
pub fn running_binary() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("finding where this binary is")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

/// Decide whether `exe` is ours to replace.
///
/// This reads what is on disk rather than remembering how the client was
/// installed: someone who unpacked an archive over a packaged install
/// should be told what is true now.
pub fn who_owns(exe: &Path) -> Owner {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".cargo")));
    who_owns_with(exe, cargo_home.as_deref(), system_package)
}

/// [`who_owns`] with its two lookups passed in, so tests can decide what
/// the environment says without touching the real one.
fn who_owns_with(
    exe: &Path,
    cargo_home: Option<&Path>,
    ask_system: fn(&Path) -> Option<Owner>,
) -> Owner {
    let path = exe.to_string_lossy().replace('\\', "/");

    // Cargo first: `~/.cargo/bin/silver` is ours in the sense that we
    // could write it, but `cargo install` is the honest answer.
    if let Some(home) = cargo_home
        && exe.starts_with(home.join("bin"))
    {
        return Owner::Managed {
            manager: "cargo",
            command: "cargo install silver-messenger --force".into(),
        };
    }

    // Homebrew keeps everything under a Cellar and links into bin. On
    // Linux the prefix is `.linuxbrew` in a home directory or under
    // /home/linuxbrew, so the dot has to be allowed for.
    if path.contains("/Cellar/")
        || path.contains("/homebrew/")
        || path.contains("/linuxbrew/")
        || path.contains("/.linuxbrew/")
    {
        return Owner::Managed {
            manager: "Homebrew",
            command: "brew upgrade silver-messenger".into(),
        };
    }

    // winget unpacks into the user's Packages directory. This project
    // publishes no winget manifest, so a binary sitting there was
    // packaged by somebody else and is theirs to update -- which is all
    // the more reason not to replace it from here.
    if path.contains("/WinGet/Packages/") || path.contains("/Microsoft/WinGet/") {
        return Owner::Managed {
            manager: "winget",
            command: "winget upgrade silver-messenger".into(),
        };
    }

    // A system prefix means a system package manager, which is asked
    // directly: only it knows whether this path belongs to a package.
    if (path.starts_with("/usr/bin/") || path.starts_with("/usr/lib/"))
        && let Some(owner) = ask_system(exe)
    {
        return owner;
    }

    Owner::Ours
}

/// Ask dpkg, rpm or pacman whether they own `exe`, when they exist.
///
/// Nothing is asked speculatively: the path already looks like a system
/// prefix by the time this runs.
fn system_package(exe: &Path) -> Option<Owner> {
    let run = |program: &str, args: &[&str]| -> Option<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    let exe = exe.to_str()?;

    if run("dpkg-query", &["-S", exe]).is_some() {
        return Some(Owner::Managed {
            manager: "the Debian package",
            command: "sudo apt install --only-upgrade silver-messenger".into(),
        });
    }
    if run("rpm", &["-qf", exe]).is_some() {
        return Some(Owner::Managed {
            manager: "the RPM package",
            command: "sudo dnf upgrade silver-messenger".into(),
        });
    }
    if run("pacman", &["-Qo", exe]).is_some() {
        return Some(Owner::Managed {
            manager: "the Arch package",
            command: "pacman -Syu  # or however that package is kept up to date".into(),
        });
    }
    None
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Where the version an update replaced is kept, for [`rollback`]: one
/// copy, inside the data directory rather than beside the program, so
/// that nothing but the program sits where it was installed.
pub fn kept_path(data_dir: &Path, exe: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from("previous");
    if let Some(ext) = exe.extension() {
        name.push(".");
        name.push(ext);
    }
    data_dir.join(UPDATE_DIR).join(name)
}

/// Where downloads wait inside the data directory until they are put in
/// place.
pub fn staging_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(UPDATE_DIR)
}

/// [`staging_dir`], made owner-only, and the data directory with it if
/// this is the first thing ever to make it.
///
/// `silver update` can run before the client has ever started, and the
/// data directory it made then was at the umask's mercy, which the first
/// start then left as it found it.
pub fn make_staging_dir(data_dir: &Path) -> anyhow::Result<PathBuf> {
    crate::store::create_private_dir(data_dir, Some(UPDATE_DIR))?;
    let dir = staging_dir(data_dir);
    crate::store::create_private_dir(&dir, None)?;
    Ok(dir)
}

/// What an update wrote down about the version it kept for [`rollback`].
///
/// Beside the copy and in the clear, so it proves nothing by itself: what
/// it is for is to say which release to check the copy against. A
/// rollback hashes the copy, finds that hash listed for this platform in
/// that release's `SHA256SUMS`, and checks the project's signature over
/// the list, before the copy is run or put in place. A copy somebody put
/// in the data directory, or a record somebody edited to match it, then
/// fails at the signature unless what is there is a release the project
/// signed, and the version it is is shown before anything changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    /// The version the kept copy is, as the client that kept it knew
    /// itself.
    pub version: String,
    /// Its SHA-256, lower-case hex, taken as it was copied.
    pub sha256: String,
}

/// Where [`Kept`] is written for the copy at `keep`.
fn kept_record_path(keep: &Path) -> PathBuf {
    keep.with_file_name("previous.json")
}

/// The record of the copy at `keep`.
pub fn kept_record(keep: &Path) -> anyhow::Result<Kept> {
    let path = kept_record_path(keep);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "there is no record of which release {} is (it was kept by a client older than \
             0.25.0), so it cannot be checked against the project's signature and is not run \
             or put back. `silver update --to <version>` installs a release afresh, checked.",
            keep.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The SHA-256 of the file at `path`, lower-case hex.
pub fn sha256_of(path: &Path) -> anyhow::Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hash.update(&buf[..read]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

const UPDATE_DIR: &str = "update";

/// `exe`'s directory, with `name` in front of `exe`'s file name and a dot
/// before it: the files an update makes beside the program for a moment.
fn beside(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(exe.file_name().unwrap_or_default());
    name.push(suffix);
    exe.with_file_name(name)
}

/// The new binary on its way in, beside the program so that the last
/// step is a rename on one filesystem.
fn incoming_path(exe: &Path) -> PathBuf {
    beside(exe, ".incoming")
}

/// Windows: the old binary, renamed out of the way while it still runs,
/// and removed by the next start ([`tidy_after_update`]).
fn aside_path(exe: &Path) -> PathBuf {
    beside(exe, ".replaced")
}

/// What 0.12.0 to 0.22.0 left beside the program, and what the update
/// now keeps in the data directory instead.
fn legacy_backup_path(exe: &Path) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    exe.with_file_name(name)
}

/// Put `new` in place of `exe`, keeping a copy of the old one at `keep`
/// for [`rollback`], with a record that it is `version`. `new` is
/// consumed, and is installed only if it is still what hashed to `sha256`
/// when it was checked: it waits in the data directory, possibly for the
/// whole of a session, and somebody who can write there could have
/// replaced it since.
///
/// On failure the old binary is still in place: a rename is the only
/// moment `exe` changes.
pub fn swap_checked(
    new: &Path,
    sha256: &str,
    exe: &Path,
    keep: &Path,
    version: &str,
) -> anyhow::Result<()> {
    if !new.is_file() {
        bail!(
            "{} is not there to install; nothing has been changed",
            new.display()
        );
    }
    if let Some(dir) = keep.parent() {
        crate::store::create_private_dir(dir, None)?;
    }
    let record = kept_record_path(keep);
    let _ = std::fs::remove_file(&record);
    let _ = std::fs::remove_file(keep);
    std::fs::copy(exe, keep).with_context(|| format!("keeping a copy of {}", exe.display()))?;
    let kept = Kept {
        version: version.to_owned(),
        sha256: sha256_of(keep)?,
    };
    let mut out = crate::store::create_private(&record)?;
    std::io::Write::write_all(&mut out, serde_json::to_string(&kept)?.as_bytes())
        .with_context(|| format!("writing {}", record.display()))?;
    drop(out);
    place(new, exe, sha256)?;
    let _ = std::fs::remove_file(new);
    Ok(())
}

/// [`swap_checked`] for a file the caller has only just made and holds no
/// earlier hash of, so it is hashed here. Not for an update, whose
/// download has waited in the data directory since it was checked: that
/// goes through [`swap_checked`] with the hash taken when it was.
#[doc(hidden)]
pub fn swap(new: &Path, exe: &Path, keep: &Path) -> anyhow::Result<()> {
    let sha256 = sha256_of(new)?;
    swap_checked(new, &sha256, exe, keep, env!("CARGO_PKG_VERSION"))
}

/// Put back what the last update replaced, from `keep`, if it is still
/// what hashed to `sha256` when it was checked ([`kept_record`]).
pub fn rollback(exe: &Path, keep: &Path, sha256: &str) -> anyhow::Result<()> {
    if !keep.is_file() {
        bail!(
            "there is nothing to go back to: {} is not a file",
            keep.display()
        );
    }
    place(keep, exe, sha256)?;
    let _ = std::fs::remove_file(keep);
    let _ = std::fs::remove_file(kept_record_path(keep));
    Ok(())
}

/// Copy `from` in beside `exe` and rename it over `exe`, if the copy
/// hashes to `sha256`.
///
/// The copy is what is hashed, not `from`: it is outside the data
/// directory and nothing else writes it between the hash and the rename,
/// so what was checked is what is installed.
fn place(from: &Path, exe: &Path, sha256: &str) -> anyhow::Result<()> {
    let incoming = incoming_path(exe);
    let _ = std::fs::remove_file(&incoming);
    std::fs::copy(from, &incoming).with_context(|| {
        format!(
            "writing the new binary beside {} (is the directory writable?)",
            exe.display()
        )
    })?;
    match sha256_of(&incoming) {
        Ok(got) if got.eq_ignore_ascii_case(sha256) => {}
        Ok(got) => {
            let _ = std::fs::remove_file(&incoming);
            bail!(
                "{} is not the file that was checked (it hashes to {got}, where {sha256} was \
                 checked); it has been changed since, and nothing has been installed",
                from.display()
            );
        }
        Err(e) => {
            let _ = std::fs::remove_file(&incoming);
            return Err(e);
        }
    }
    // Keep whatever mode the old binary had: a file installed 0750 in a
    // shared directory should stay that way, so this is not a fixed 755.
    if let Err(e) = copy_permissions(exe, &incoming) {
        let _ = std::fs::remove_file(&incoming);
        return Err(e);
    }

    #[cfg(windows)]
    {
        // Windows cannot replace a running image in one step: it can only
        // be renamed out of the way and the replacement given the name it
        // left. Between those two renames the path holds nothing, so
        // everything that can fail has happened above, and the second
        // rename's failure puts the first back.
        let aside = aside_path(exe);
        let _ = std::fs::remove_file(&aside);
        if let Err(e) = std::fs::rename(exe, &aside) {
            let _ = std::fs::remove_file(&incoming);
            return Err(e).with_context(|| format!("moving {} aside", exe.display()));
        }
        hide(&aside);
        if let Err(e) = std::fs::rename(&incoming, exe) {
            let put_back = restore(&aside, exe);
            let _ = std::fs::remove_file(&incoming);
            let at = exe.display();
            return match put_back {
                Ok(()) => Err(e).with_context(|| format!("putting the new binary at {at}")),
                Err(recovery) => Err(e).with_context(|| {
                    format!(
                        "putting the new binary at {at}, and {at} could not be put back either ({recovery:#}); the previous version is at {}, so rename that back to {at} by hand",
                        aside.display()
                    )
                }),
            };
        }
    }
    #[cfg(not(windows))]
    {
        // One rename over the old name: a program running from the old
        // file keeps its inode, and the next start runs the new one.
        if let Err(e) = std::fs::rename(&incoming, exe) {
            let _ = std::fs::remove_file(&incoming);
            return Err(e).with_context(|| format!("putting the new binary at {}", exe.display()));
        }
        sync_dir(exe);
    }
    Ok(())
}

/// Windows: mark a file hidden, so that the old binary waiting to be
/// removed does not sit in the program's folder for all to see. Best
/// effort.
#[cfg(windows)]
fn hide(path: &Path) {
    let _ = std::process::Command::new("attrib")
        .arg("+h")
        .arg(path)
        .output();
}

/// Remove what an update left beside this binary: on Windows the old
/// binary, which could not be deleted while it ran. Called once at start;
/// a failure is not worth reporting, since the only cost is a stale file,
/// removed by a later start.
pub fn tidy_after_update() {
    if let Ok(exe) = running_binary() {
        for path in [aside_path(&exe), incoming_path(&exe)] {
            if path.is_file() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Move the `.old` copy that clients up to 0.22.0 kept beside the program
/// into the data directory, where the previous version is kept now, so
/// that `--rollback` still finds it and nothing is left beside the
/// program. A copy already in the data directory is newer and stays.
pub fn adopt_legacy_backup(data_dir: &Path) {
    let Ok(exe) = running_binary() else { return };
    adopt_legacy_backup_of(&exe, data_dir);
}

fn adopt_legacy_backup_of(exe: &Path, data_dir: &Path) {
    let legacy = legacy_backup_path(exe);
    if !legacy.is_file() {
        return;
    }
    let kept = kept_path(data_dir, exe);
    if !kept.exists() {
        if let Some(dir) = kept.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::rename(&legacy, &kept).is_ok() {
            return;
        }
        if std::fs::copy(&legacy, &kept).is_err() {
            // Keep it where it is rather than lose the only copy.
            return;
        }
    }
    let _ = std::fs::remove_file(&legacy);
}

/// Put `exe` back from `backup` after a failed replacement.
///
/// A rename if the filesystem will take one, a copy if it will not. The
/// distinction matters on Windows, where the path is empty at this point
/// and the program that would notice is the one that is missing: a
/// rollback lost is an inconvenience, a program lost is the user having
/// nothing to run. So the copy is worth the duplicated bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn restore(backup: &Path, exe: &Path) -> anyhow::Result<()> {
    // A file, not merely something at that path: the destination is free
    // by now, so a rename would happily move a *directory* onto it and
    // report success, leaving the name taken by something that cannot be
    // run.
    if !backup.is_file() {
        bail!("{} is not there to put back", backup.display());
    }
    if std::fs::rename(backup, exe).is_ok() {
        return Ok(());
    }
    std::fs::copy(backup, exe)
        .with_context(|| format!("copying {} back to {}", backup.display(), exe.display()))?;
    Ok(())
}

fn copy_permissions(from: &Path, to: &Path) -> anyhow::Result<()> {
    let mode = std::fs::metadata(from)
        .with_context(|| format!("reading {}", from.display()))?
        .permissions();
    std::fs::set_permissions(to, mode)
        .with_context(|| format!("setting the mode of {}", to.display()))
}

/// Make the rename durable, so a crash cannot leave the directory entry
/// pointing at neither binary.
#[cfg(not(windows))]
fn sync_dir(exe: &Path) {
    if let Some(dir) = exe.parent()
        && let Ok(handle) = std::fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
}

/// Run `exe --version` and return what it printed.
///
/// The real test that a download is a working client of the version it
/// claims: a file that cannot say its own name does not replace one that
/// can.
pub fn reported_version(exe: &Path) -> anyhow::Result<String> {
    let out = std::process::Command::new(exe)
        .arg("--version")
        .output()
        .with_context(|| format!("running {} --version", exe.display()))?;
    if !out.status.success() {
        bail!("{} --version failed", exe.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // "silver 0.12.0" -> "0.12.0"
    let version = text
        .split_whitespace()
        .find_map(|w| crate::update::parse_version(w).map(|_| w.to_owned()))
        .ok_or_else(|| anyhow::anyhow!("{} printed no version", exe.display()))?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A system that owns nothing, for the paths that should not ask.
    fn owns_nothing(_: &Path) -> Option<Owner> {
        None
    }

    /// A system that owns everything it is asked about.
    fn owns_everything(_: &Path) -> Option<Owner> {
        Some(Owner::Managed {
            manager: "the Debian package",
            command: "sudo apt install --only-upgrade silver-messenger".into(),
        })
    }

    #[test]
    fn a_managed_binary_is_not_ours_to_replace() {
        let cargo = Path::new("/home/x/.cargo");
        let manager = |exe: &str, ask: fn(&Path) -> Option<Owner>| match who_owns_with(
            Path::new(exe),
            Some(cargo),
            ask,
        ) {
            Owner::Managed { manager, .. } => Some(manager),
            Owner::Ours => None,
        };
        assert_eq!(
            manager("/home/x/.cargo/bin/silver", owns_nothing),
            Some("cargo")
        );
        assert_eq!(
            manager(
                "/opt/homebrew/Cellar/silver-messenger/0.11.0/bin/silver",
                owns_nothing
            ),
            Some("Homebrew")
        );
        assert_eq!(
            manager("/home/x/.linuxbrew/bin/silver", owns_nothing),
            Some("Homebrew")
        );
        assert_eq!(
            manager(
                "C:/Users/x/AppData/Local/Microsoft/WinGet/Packages/y/silver.exe",
                owns_nothing
            ),
            Some("winget")
        );
        // A system prefix asks the package manager, and believes it.
        assert_eq!(
            manager("/usr/bin/silver", owns_everything),
            Some("the Debian package")
        );
        assert_eq!(manager("/usr/bin/silver", owns_nothing), None);
        // Anything else is ours: an unpacked archive, /usr/local, a build.
        assert_eq!(manager("/usr/local/bin/silver", owns_everything), None);
        assert_eq!(manager("/home/x/bin/silver", owns_nothing), None);
        assert_eq!(
            manager("/home/x/silver/target/release/silver", owns_nothing),
            None
        );
    }

    #[test]
    fn a_swap_replaces_and_rolls_back_leaving_nothing_beside_the_binary() {
        let dir = tempdir();
        let bin = dir.join("bin");
        let data = dir.join("data");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("silver");
        let staged = dir.join("download");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let keep = kept_path(&data, &exe);

        swap_checked(&staged, &sha256_of(&staged).unwrap(), &exe, &keep, "0.1.0").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(&keep).unwrap(), b"old");
        let kept = kept_record(&keep).unwrap();
        assert_eq!(kept.version, "0.1.0");
        assert_eq!(kept.sha256, sha256_of(&keep).unwrap());
        assert!(!staged.exists(), "the download is consumed by the swap");
        if !cfg!(windows) {
            let beside: Vec<_> = std::fs::read_dir(&bin).unwrap().collect();
            assert_eq!(
                beside.len(),
                1,
                "only the program is left where it was installed"
            );
        }

        rollback(&exe, &keep, &kept.sha256).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert!(!keep.exists(), "the copy went back into place");
        assert!(kept_record(&keep).is_err(), "and its record with it");
    }

    /// The download waits in the data directory until `/update` puts it
    /// in place, and the version an update replaced waits there for
    /// `--rollback`. Either may have been replaced by then; neither is
    /// installed unless it is still what was checked, and nothing beside
    /// the program is left by the refusal.
    #[test]
    fn a_file_changed_since_it_was_checked_is_not_installed() {
        let dir = tempdir();
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("silver");
        let staged = dir.join("download");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let checked = sha256_of(&staged).unwrap();
        std::fs::write(&staged, b"somebody else's").unwrap();
        let keep = kept_path(&dir.join("data"), &exe);
        let err = swap_checked(&staged, &checked, &exe, &keep, "0.1.0").unwrap_err();
        assert!(
            format!("{err:#}").contains("not the file that was checked"),
            "{err:#}"
        );
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert!(!incoming_path(&exe).exists());

        std::fs::write(&staged, b"new").unwrap();
        swap_checked(&staged, &checked, &exe, &keep, "0.1.0").unwrap();
        let kept = kept_record(&keep).unwrap();
        std::fs::write(&keep, b"somebody else's").unwrap();
        assert!(rollback(&exe, &keep, &kept.sha256).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
    }

    #[test]
    fn rollback_without_a_kept_copy_says_so() {
        let dir = tempdir();
        let exe = dir.join("silver");
        std::fs::write(&exe, b"only").unwrap();
        let err = rollback(&exe, &kept_path(&dir.join("data"), &exe), "")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing to go back to"), "{err}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"only");
    }

    #[test]
    fn the_previous_version_is_kept_in_the_data_directory() {
        assert_eq!(
            kept_path(
                Path::new("/home/x/.local/share/silver-messenger"),
                Path::new("/usr/local/bin/silver")
            ),
            Path::new("/home/x/.local/share/silver-messenger/update/previous")
        );
        assert_eq!(
            kept_path(Path::new("C:/data"), Path::new("C:/tools/silver.exe")),
            Path::new("C:/data/update/previous.exe")
        );
    }

    #[test]
    fn the_old_copy_an_earlier_update_left_beside_the_program_moves_into_the_data_directory() {
        let dir = tempdir();
        let exe = dir.join("silver");
        let data = dir.join("data");
        std::fs::write(&exe, b"0.23.0").unwrap();
        std::fs::write(legacy_backup_path(&exe), b"0.22.0").unwrap();
        adopt_legacy_backup_of(&exe, &data);
        assert!(!legacy_backup_path(&exe).exists());
        let kept = kept_path(&data, &exe);
        assert_eq!(std::fs::read(&kept).unwrap(), b"0.22.0");
        // Kept by a client that wrote down nothing about it, so there is
        // no release to check it against, and it is not put back on its
        // own say-so.
        assert!(
            format!("{:#}", kept_record(&kept).unwrap_err()).contains("update --to"),
            "the way to a checked copy should be named"
        );
        rollback(&exe, &kept, &sha256_of(&kept).unwrap()).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"0.22.0");
    }

    #[test]
    fn a_missing_download_changes_nothing() {
        let dir = tempdir();
        let exe = dir.join("silver");
        std::fs::write(&exe, b"running").unwrap();
        assert!(swap(&dir.join("nothing"), &exe, &dir.join("keep")).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"running");
    }

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "silver-install-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// Putting the binary back must not depend on a rename working.
    ///
    /// Both `swap` on Windows and `rollback` everywhere move the running
    /// binary out of the way and then move the other one in. Between
    /// those two the path holds nothing, and the program that would
    /// notice is the one that is missing -- it cannot put itself back on
    /// a later start. So when the second move fails, the recovery has to
    /// try harder than the thing that just failed: a rename if that
    /// works, a copy if it does not. A rollback lost is an
    /// inconvenience; a program lost is the user with nothing to run.
    #[test]
    fn putting_a_binary_back_falls_back_to_copying() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("silver");
        let backup = dir.path().join("silver.backup");

        // The ordinary case: a rename, and the backup is consumed.
        std::fs::write(&backup, b"the previous version").unwrap();
        restore(&backup, &exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"the previous version");
        assert!(!backup.exists(), "a rename leaves nothing behind it");

        // A rename that cannot go: the destination's directory is not the
        // source's, which is the shape a cross-device rename has. The
        // copy takes over and the path is not left empty.
        let other = tempfile::tempdir().unwrap();
        let far = other.path().join("silver.backup");
        std::fs::write(&far, b"from somewhere else").unwrap();
        std::fs::remove_file(&exe).unwrap();
        restore(&far, &exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"from somewhere else");

        // Nothing to put back is an error rather than a silent success:
        // the caller reports it, and the message tells the user what to
        // do by hand, since a later start of this program cannot.
        std::fs::remove_file(&exe).unwrap();
        let missing = dir.path().join("not-here");
        assert!(restore(&missing, &exe).is_err());
        assert!(!exe.exists(), "nothing was invented to fill the gap");
    }

    /// Something that is not a file is not a binary to go back to, and
    /// is refused before anything is moved.
    #[test]
    fn a_kept_copy_that_is_not_a_file_is_refused_before_anything_moves() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("silver");
        std::fs::write(&exe, b"running").unwrap();
        let keep = kept_path(&dir.path().join("data"), &exe);
        std::fs::create_dir_all(&keep).unwrap();

        let err = rollback(&exe, &keep, "").unwrap_err();
        assert!(
            format!("{err:#}").contains("is not a file"),
            "a directory was taken for a binary: {err:#}"
        );
        assert_eq!(std::fs::read(&exe).unwrap(), b"running");
    }
}
