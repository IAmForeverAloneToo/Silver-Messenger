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

/// Where the binary replaced by an update is kept.
pub fn backup_path(exe: &Path) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    exe.with_file_name(name)
}

/// Put `new` in place of `exe`, keeping the old one for [`rollback`].
///
/// Returns where the old binary went. On failure the old one is still in
/// place: the rename is the only moment `exe` changes.
pub fn swap(new: &Path, exe: &Path) -> anyhow::Result<PathBuf> {
    let backup = backup_path(exe);
    let _ = std::fs::remove_file(&backup);

    // Keep whatever mode the old binary had: a file installed 0750 in a
    // shared directory should stay that way, so this is not a fixed 755.
    copy_permissions(exe, new)?;

    #[cfg(windows)]
    {
        // Windows cannot replace a running image in one step: it can only
        // be renamed out of the way and the replacement given the name it
        // left. Between those two renames the path holds nothing, and the
        // program that has just vanished from it is the one running this
        // code, so it cannot put itself back on a later start.
        //
        // The window cannot be closed -- the operating system offers no
        // atomic replace for a running file -- so make it as small and as
        // survivable as it can be. Everything that can fail happens
        // first: the new file is checked here rather than discovered
        // missing between the renames, and the mode was copied above.
        if !new.is_file() {
            bail!(
                "{} is not there to install; nothing has been changed",
                new.display()
            );
        }
        std::fs::rename(exe, &backup).with_context(|| format!("moving {} aside", exe.display()))?;
        if let Err(e) = std::fs::rename(new, exe) {
            // Put it back rather than leave the name empty, and if the
            // rename back will not go either, copy: leaving the user with
            // no program is worse than leaving them without a rollback.
            let put_back = restore(&backup, exe);
            let at = exe.display();
            return match put_back {
                Ok(()) => {
                    Err(e).with_context(|| format!("putting the new binary at {at}"))
                }
                // Both the install and the recovery failed, so the path
                // may be empty and this process may not run again. Say
                // exactly what to do by hand, since a later start cannot.
                Err(recovery) => Err(e).with_context(|| {
                    format!(
                        "putting the new binary at {at}, and {} could not be put back either                          ({recovery:#}); the previous version is at {}, so rename that back to                          {at} by hand",
                        at,
                        backup.display()
                    )
                }),
            };
        }
    }
    #[cfg(not(windows))]
    {
        // A hard link keeps the old inode reachable without copying it;
        // a copy when the filesystem will not link.
        if std::fs::hard_link(exe, &backup).is_err() {
            std::fs::copy(exe, &backup)
                .with_context(|| format!("keeping a copy of {}", exe.display()))?;
        }
        std::fs::rename(new, exe).with_context(|| {
            format!(
                "putting the new binary at {} (is the directory writable?)",
                exe.display()
            )
        })?;
        sync_dir(exe);
    }
    Ok(backup)
}

/// Put back what the last update replaced.
pub fn rollback(exe: &Path) -> anyhow::Result<PathBuf> {
    let backup = backup_path(exe);
    if !backup.is_file() {
        bail!(
            "there is nothing to go back to: {} is not a file",
            backup.display()
        );
    }
    // Straight back the way it came, keeping the current one in case the
    // one being restored turns out to be the broken one.
    let aside = exe.with_extension("rolling-back");
    let _ = std::fs::remove_file(&aside);
    std::fs::rename(exe, &aside).with_context(|| format!("moving {} aside", exe.display()))?;
    // The same two-rename window as the Windows half of `swap`, on every
    // platform: between these the path holds nothing. If the second will
    // not go, put the current binary back by whatever means -- see
    // `restore`.
    if let Err(e) = std::fs::rename(&backup, exe) {
        let at = exe.display();
        return match restore(&aside, exe) {
            Ok(()) => Err(e).with_context(|| format!("restoring {at}")),
            Err(recovery) => Err(e).with_context(|| {
                format!(
                    "restoring {at}, and the binary that was running could not be put back                      either ({recovery:#}); it is at {}, so rename that back to {at} by hand",
                    aside.display()
                )
            }),
        };
    }
    let _ = std::fs::remove_file(&aside);
    #[cfg(not(windows))]
    sync_dir(exe);
    Ok(backup)
}

/// Remove a `*.old` left beside this binary by an update on Windows,
/// where the running image could not be deleted at the time.
///
/// Called once at start; a failure is not worth reporting, since the
/// only cost is a stale file.
pub fn tidy_after_update() {
    if !cfg!(windows) {
        return;
    }
    if let Ok(exe) = running_binary() {
        let _ = std::fs::remove_file(backup_path(&exe));
    }
}

/// Put `exe` back from `backup` after a failed replacement.
///
/// A rename if the filesystem will take one, a copy if it will not. The
/// distinction matters on Windows, where the path is empty at this point
/// and the program that would notice is the one that is missing: a
/// rollback lost is an inconvenience, a program lost is the user having
/// nothing to run. So the copy is worth the duplicated bytes.
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
    fn a_swap_replaces_and_rolls_back() {
        let dir = tempdir();
        let exe = dir.join("silver");
        let new = dir.join("silver.new");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(&new, b"new").unwrap();

        let backup = swap(&new, &exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old");
        assert!(!new.exists(), "the download is consumed by the swap");

        rollback(&exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
    }

    #[test]
    fn rollback_without_a_backup_says_so() {
        let dir = tempdir();
        let exe = dir.join("silver");
        std::fs::write(&exe, b"only").unwrap();
        let err = rollback(&exe).unwrap_err().to_string();
        assert!(err.contains("nothing to go back to"), "{err}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"only");
    }

    #[test]
    fn the_backup_sits_beside_the_binary() {
        assert_eq!(
            backup_path(Path::new("/usr/local/bin/silver")),
            Path::new("/usr/local/bin/silver.old")
        );
        assert_eq!(
            backup_path(Path::new("C:/tools/silver.exe")),
            Path::new("C:/tools/silver.exe.old")
        );
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
    ///
    /// The check used to be `exists()`. By the time the backup is moved
    /// into place the path is free, so a rename puts whatever it is
    /// there and reports success -- leaving the name taken by something
    /// that cannot be run, which is the failure this whole area exists to
    /// avoid.
    #[test]
    fn a_backup_that_is_not_a_file_is_refused_before_anything_moves() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("silver");
        std::fs::write(&exe, b"running").unwrap();
        std::fs::create_dir(backup_path(&exe)).unwrap();

        let err = rollback(&exe).unwrap_err();
        assert!(
            format!("{err:#}").contains("is not a file"),
            "a directory was taken for a binary: {err:#}"
        );
        assert_eq!(
            std::fs::read(&exe).unwrap(),
            b"running",
            "the running binary was moved for a rollback that could never work"
        );
    }
}
