//! The log file `SILVER_LOG` turns on, kept to a bounded size.
//!
//! It was opened for appending and never looked at again, so a client
//! left running with `SILVER_LOG=debug` wrote until the disk filled. That
//! is worse than an ordinary runaway file: at `debug` the log names
//! envelope ids, contact ids and the relay, so it is also a growing
//! record of who this person talks to, sitting next to a data directory
//! whose whole purpose is that such a record does not exist. `/wipe`
//! removes it for that reason.
//!
//! So the writer counts what it writes. Past [`MAX_BYTES`] the file is
//! renamed to `silver.log.1`, replacing whatever was there, and a fresh
//! one is started: the log keeps the most recent activity, which is what
//! a log is read for, and takes at most twice the cap on disk for ever.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Bytes one log file may reach before it is rolled over. Two of these is
/// the most the pair ever occupies.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// The open log file and how much has gone into it.
struct Inner {
    file: File,
    written: u64,
    path: PathBuf,
}

/// A `MakeWriter` for `tracing_subscriber` that rolls the file over.
#[derive(Clone)]
pub struct CappedLog(Arc<Mutex<Inner>>);

impl CappedLog {
    /// Open `path` for appending, continuing an existing file and
    /// counting what it already holds.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = private_append(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self(Arc::new(Mutex::new(Inner {
            file,
            written,
            path: path.to_path_buf(),
        }))))
    }
}

impl Inner {
    /// Start a new file, keeping the one just filled as `.1`.
    ///
    /// A failure anywhere here leaves the current file in place and keeps
    /// writing to it: a log that cannot roll over is worth more than no
    /// log, and the cap is a courtesy to the disk rather than a promise
    /// to anybody.
    fn roll(&mut self) {
        let previous = self.path.with_extension("log.1");
        let _ = self.file.flush();
        if std::fs::rename(&self.path, &previous).is_err() {
            return;
        }
        match private_append(&self.path) {
            Ok(file) => {
                self.file = file;
                self.written = 0;
            }
            // The rename succeeded and the reopen did not, so this process
            // has no file to write to any more. Nothing can be done about
            // it here; writes below will fail and tracing drops them.
            Err(_) => self.written = 0,
        }
    }
}

impl Write for CappedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Rolled before the write rather than after, so a single line
        // cannot take the file past the cap.
        if inner.written + buf.len() as u64 > MAX_BYTES {
            inner.roll();
        }
        let written = inner.file.write(buf)?;
        inner.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CappedLog {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Open for appending, readable by its owner alone.
fn private_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair of files stays bounded however much is written, and the
    /// newest activity is the part that is kept.
    #[test]
    fn the_log_rolls_over_instead_of_growing_without_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silver.log");
        let mut log = CappedLog::open(&path).unwrap();

        // Comfortably more than two capfuls, a line at a time.
        let line = vec![b'x'; 64 * 1024];
        let mut wrote = 0u64;
        while wrote < MAX_BYTES * 3 {
            log.write_all(&line).unwrap();
            wrote += line.len() as u64;
        }
        log.flush().unwrap();

        let live = std::fs::metadata(&path).unwrap().len();
        let rolled = std::fs::metadata(path.with_extension("log.1"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(live <= MAX_BYTES, "the live file passed the cap: {live}");
        assert!(
            rolled <= MAX_BYTES,
            "the rolled file passed the cap: {rolled}"
        );
        assert!(
            live + rolled <= MAX_BYTES * 2,
            "{wrote} bytes written left {} on disk",
            live + rolled
        );

        // Nothing else was left lying about: two files, no more.
        let logs = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().starts_with("silver.log"))
            })
            .count();
        assert_eq!(logs, 2, "a log file was left behind");
    }

    /// Reopening continues the file it finds rather than starting the
    /// count from zero, which would let restarts push it past the cap.
    #[test]
    fn reopening_counts_what_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silver.log");
        {
            let mut log = CappedLog::open(&path).unwrap();
            log.write_all(&vec![b'x'; (MAX_BYTES - 1024) as usize])
                .unwrap();
            log.flush().unwrap();
        }
        let mut log = CappedLog::open(&path).unwrap();
        log.write_all(&vec![b'y'; 4096]).unwrap();
        log.flush().unwrap();
        assert!(
            std::fs::metadata(&path).unwrap().len() <= MAX_BYTES,
            "a restart wrote past the cap"
        );
        assert!(
            path.with_extension("log.1").exists(),
            "the full file should have been rolled, not appended to"
        );
    }
}
