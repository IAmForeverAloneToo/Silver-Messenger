//! Files as attachments: turning a file into encrypted chunks and a
//! [`Content::File`] message, and back.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use silver_protocol::Content;
use silver_protocol::blob::{
    BlobKey, CHUNK_BYTES, MAX_FILE_BYTES, chunk_count, new_blob_id, open_chunk, seal_chunk,
};
use unicode_normalization::UnicodeNormalization;

/// Longest file name saved, in characters.
const MAX_NAME_CHARS: usize = 120;

/// Extensions the operating system runs as a program or script when a
/// file is "opened", rather than showing it in a viewer.
const RUNNABLE: &[&str] = &[
    // Windows programs, installers and shell objects
    "exe",
    "com",
    "msi",
    "msix",
    "msixbundle",
    "appx",
    "appxbundle",
    "bat",
    "cmd",
    "scr",
    "pif",
    "cpl",
    "hta",
    "reg",
    "lnk",
    "url",
    "inf",
    "dll",
    "sys",
    "drv",
    "ocx",
    "msc",
    "msp",
    "mst",
    "gadget",
    "application",
    "xbap",
    "diagcab",
    "settingcontent-ms",
    "library-ms",
    "website",
    // Windows scripts
    "vb",
    "vbs",
    "vbe",
    "vbscript",
    "js",
    "jse",
    "wsf",
    "wsh",
    "ws",
    "sct",
    "shb",
    "shs",
    "ps1",
    "psm1",
    "psd1",
    "ps1xml",
    "psc1",
    // interpreters that register themselves as openers
    "py",
    "pyw",
    "pyc",
    "pl",
    "rb",
    "php",
    "jar",
    "jnlp",
    // Unix and macOS
    "sh",
    "bash",
    "zsh",
    "ksh",
    "csh",
    "fish",
    "command",
    "tool",
    "action",
    "workflow",
    "app",
    "desktop",
    "run",
    "appimage",
    "elf",
    "deb",
    "rpm",
    "pkg",
    "mpkg",
    "dmg",
    "apk",
    "ipa",
    "terminal",
    "scpt",
    "applescript",
    "webloc",
    // certificates: opening one offers to install it
    "cer",
    "crt",
    "der",
    "p12",
    "pfx",
];

/// What a [`Content::File`] message says about a file. Serialized as the
/// message content itself, so a file waiting to be fetched can sit in the
/// history until the user asks for it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "Content", try_from = "Content")]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub blob: String,
    pub key: BlobKey,
    pub chunks: u32,
    pub sha256: [u8; 32],
}

impl FileInfo {
    pub fn from_content(content: &Content) -> Option<Self> {
        match content {
            Content::File {
                name,
                size,
                blob,
                key,
                chunks,
                sha256,
            } => Some(Self {
                name: name.clone(),
                size: *size,
                blob: blob.clone(),
                key: key.clone(),
                chunks: *chunks,
                sha256: *sha256,
            }),
            _ => None,
        }
    }

    pub fn into_content(self) -> Content {
        Content::File {
            name: self.name,
            size: self.size,
            blob: self.blob,
            key: self.key,
            chunks: self.chunks,
            sha256: self.sha256,
        }
    }

    /// `name (1.2 MiB)`, with the name as it would be saved: the sender's
    /// spelling is never shown raw.
    pub fn label(&self) -> String {
        format!("{} ({})", sanitize_name(&self.name), human_size(self.size))
    }

    /// What a sender could have lied about, checked before a single chunk
    /// is asked for: the size against the cap and the chunk count against
    /// the size. The hash is checked once the bytes are here.
    pub fn check(&self) -> anyhow::Result<()> {
        if self.size > MAX_FILE_BYTES {
            bail!(
                "{} is larger than the {} cap",
                human_size(self.size),
                human_size(MAX_FILE_BYTES)
            );
        }
        if self.chunks != chunk_count(self.size) {
            bail!(
                "chunk count {} does not match a size of {}",
                self.chunks,
                human_size(self.size)
            );
        }
        Ok(())
    }
}

impl From<FileInfo> for Content {
    fn from(info: FileInfo) -> Self {
        info.into_content()
    }
}

impl TryFrom<Content> for FileInfo {
    type Error = anyhow::Error;

    fn try_from(content: Content) -> Result<Self, Self::Error> {
        Self::from_content(&content).ok_or_else(|| anyhow::anyhow!("not a file message"))
    }
}

/// Read `path`, encrypt it chunk by chunk under a fresh key, and describe
/// it. With `pad`, the last chunk is filled up to a whole chunk with zeros
/// (the description carries the real size), so the relay learns the size
/// to the nearest 64 KiB only; only for recipients that cut files to size.
pub fn prepare(path: &Path, pad: bool) -> anyhow::Result<(FileInfo, Vec<Vec<u8>>)> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a file", path.display());
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!(
            "{} is {}; files up to {} can be sent",
            path.display(),
            human_size(metadata.len()),
            human_size(MAX_FILE_BYTES)
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .map(|n| sanitize_name(&n.to_string_lossy()))
        .unwrap_or_else(|| "file".to_owned());
    let key = BlobKey::generate();
    let blob = new_blob_id();
    let size = bytes.len() as u64;
    let total = chunk_count(size);
    let sha256 = Sha256::digest(&bytes).into();
    let mut bytes = bytes;
    if pad {
        bytes.resize(total as usize * CHUNK_BYTES, 0);
    }
    let mut chunks = Vec::with_capacity(total as usize);
    // An empty file is one empty chunk.
    let pieces: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(CHUNK_BYTES).collect()
    };
    for (index, piece) in pieces.iter().enumerate() {
        chunks.push(seal_chunk(&key, &blob, index as u32, total, piece)?);
    }
    let info = FileInfo {
        name,
        size,
        blob,
        key,
        chunks: total,
        sha256,
    };
    Ok((info, chunks))
}

/// Decrypt fetched chunks and check the result against what the sender
/// promised.
pub fn assemble(info: &FileInfo, chunks: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    info.check()?;
    if chunks.len() != info.chunks as usize {
        bail!("expected {} chunks, got {}", info.chunks, chunks.len());
    }
    let mut bytes = Vec::with_capacity(info.size as usize);
    for (index, chunk) in chunks.iter().enumerate() {
        let plain = open_chunk(&info.key, &info.blob, index as u32, info.chunks, chunk)
            .with_context(|| format!("chunk {index} does not decrypt"))?;
        bytes.extend_from_slice(&plain);
    }
    // A sender that pads fills the last chunk up; the promised size says
    // where the file ends.
    if (bytes.len() as u64) < info.size {
        bail!("file is {} bytes, expected {}", bytes.len(), info.size);
    }
    bytes.truncate(info.size as usize);
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != info.sha256 {
        bail!("file hash does not match what the sender promised");
    }
    Ok(bytes)
}

/// Write `bytes` into `dir` under `name`, never overwriting: a taken name
/// gets ` (2)`, ` (3)` and so on before its extension. With a `quota`, the
/// directory's files plus this one must stay under it.
pub fn save(dir: &Path, name: &str, bytes: &[u8], quota: Option<u64>) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    check_quota(dir, bytes.len() as u64, quota)?;
    let name = sanitize_name(name);
    let (stem, ext) = split_extension(&name);
    let (stem, ext) = (stem.to_owned(), ext.to_owned());
    // The name is claimed by creating the file exclusively, so two fetches
    // finishing at the same moment cannot pick the same one.
    let mut candidate = dir.join(&name);
    let mut n = 2;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(e) = std::io::Write::write_all(&mut file, bytes) {
                    drop(file);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(e).with_context(|| format!("writing {}", candidate.display()));
                }
                drop(file);
                mark_of_the_web(&candidate);
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                candidate = dir.join(format!("{stem} ({n}){ext}"));
                n += 1;
            }
            Err(e) => return Err(e).with_context(|| format!("creating {}", candidate.display())),
        }
    }
}

/// Bytes of the regular files directly in `dir` (the downloads folder is
/// flat); a directory that does not exist holds nothing.
pub fn dir_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Refuse `incoming` bytes when `dir` plus them would pass `quota`.
pub fn check_quota(dir: &Path, incoming: u64, quota: Option<u64>) -> anyhow::Result<()> {
    let Some(quota) = quota else {
        return Ok(());
    };
    let used = dir_size(dir);
    if used.saturating_add(incoming) > quota {
        bail!(
            "{} holds {} and this file is {}; the downloads quota is {} (downloads_quota_mib in config.json)",
            dir.display(),
            human_size(used),
            human_size(incoming),
            human_size(quota)
        );
    }
    Ok(())
}

/// On Windows, tag a saved file as a download (the "mark of the web") so
/// Explorer, SmartScreen and Defender treat it like one from a browser.
#[cfg(windows)]
fn mark_of_the_web(path: &Path) {
    let stream = format!("{}:Zone.Identifier", path.display());
    let _ = std::fs::write(stream, "[ZoneTransfer]\r\nZoneId=3\r\n");
}

#[cfg(not(windows))]
fn mark_of_the_web(_path: &Path) {}

/// Why `path` should not be handed to the system's opener, if it should
/// not: it would run rather than be shown.
pub fn refuse_to_open(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let (_, ext) = split_extension(&name);
    let ext = ext.trim_start_matches('.').to_ascii_lowercase();
    RUNNABLE.contains(&ext.as_str()).then(|| {
        format!(
            ".{ext} files run as programs when opened; if you trust it, open it from the downloads folder yourself"
        )
    })
}

/// `photo.jpg` → (`photo`, `.jpg`); a name without a short extension
/// after a non-empty stem is all stem.
fn split_extension(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.chars().count() <= 16 => {
            (stem, &name[stem.len()..])
        }
        _ => (name, ""),
    }
}

/// Characters that show nothing but change how a name reads or sorts:
/// Unicode format characters (bidi overrides and embeddings, zero-width
/// joiners and spaces, soft hyphens, byte-order marks, tag characters)
/// and the line and paragraph separators.
fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x08E2
            | 0x180E
            | 0xFEFF
            | 0x0600..=0x0605
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// `text` without control or invisible characters, at most `max_chars`
/// long: what a peer chose (an alias, a message shown in a notification)
/// reduced to what a person can see.
pub fn printable(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Names Windows keeps for devices, judged on the part before the first
/// dot: `CON`, `con.txt` and `COM1.tar.gz` all are.
fn is_reserved_device_name(name: &str) -> bool {
    let head = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    match head.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            head.len() == 4
                && (head.starts_with("COM") || head.starts_with("LPT"))
                && matches!(head.as_bytes()[3], b'1'..=b'9')
        }
    }
}

/// A file name safe to create locally and honest on screen: no
/// directories, no control or invisible characters, composed the one way
/// (NFC), nothing hidden, nothing Windows would refuse or trim, at most
/// 120 characters with the extension kept. Sanitizing the result again
/// gives the result: the passes run until nothing changes, since cutting a
/// long name can change which part counts as its extension.
pub fn sanitize_name(name: &str) -> String {
    let mut name = sanitize_pass(name);
    for _ in 0..4 {
        let again = sanitize_pass(&name);
        if again == name {
            break;
        }
        name = again;
    }
    name
}

fn sanitize_pass(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // Invisible characters go before composition: one sitting between a
    // letter and its accent would otherwise keep them apart.
    let cleaned: String = base
        .chars()
        .filter(|c| {
            !c.is_control()
                && !is_invisible(*c)
                && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect::<String>()
        .nfc()
        .collect();
    let edge = |c: char| c == '.' || c.is_whitespace();
    let trimmed = cleaned.trim_start_matches(edge).trim_end_matches(edge);
    if trimmed.is_empty() {
        return "file".to_owned();
    }
    let (stem, ext) = split_extension(trimmed);
    // One character is kept back for the device-name mark below, so the
    // result never needs a second cut.
    let room = (MAX_NAME_CHARS - 1)
        .saturating_sub(ext.chars().count())
        .max(1);
    let stem: String = stem.chars().take(room).collect();
    let stem = stem.trim_end_matches(edge);
    let stem = if stem.is_empty() { "file" } else { stem };
    let name = format!("{stem}{ext}");
    // Windows device names get a mark so the file is a file; judged on the
    // finished name, since trimming the stem can be what makes it one.
    if is_reserved_device_name(&name) {
        format!("_{name}")
    } else {
        name
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_round_trip_through_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("photo.jpg");
        let data: Vec<u8> = (0..(CHUNK_BYTES * 2 + 123))
            .map(|i| (i * 7 % 251) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        let (info, chunks) = prepare(&path, false).unwrap();
        assert_eq!(info.name, "photo.jpg");
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.chunks, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(info.label(), "photo.jpg (128.1 KiB)");
        let content = info.clone().into_content();
        assert_eq!(FileInfo::from_content(&content), Some(info.clone()));
        assert_eq!(assemble(&info, &chunks).unwrap(), data);
        // Padded, the last chunk is a whole one and the file still comes
        // back exactly; the relay sees three full chunks either way.
        let (padded, padded_chunks) = prepare(&path, true).unwrap();
        assert_eq!(
            (padded.size, padded.chunks, padded.sha256),
            (info.size, 3, info.sha256)
        );
        assert!(padded_chunks.iter().all(|c| c.len() == CHUNK_BYTES + 16));
        assert_eq!(assemble(&padded, &padded_chunks).unwrap(), data);

        // A damaged chunk, a missing chunk or the wrong count are refused.
        let mut damaged = chunks.clone();
        damaged[1][0] ^= 1;
        assert!(assemble(&info, &damaged).is_err());
        assert!(assemble(&info, &chunks[..2]).is_err());
        let mut lying = info.clone();
        lying.size += 1;
        assert!(assemble(&lying, &chunks).is_err());

        let saved = save(dir.path(), "photo.jpg", &data, None).unwrap();
        assert_eq!(saved, dir.path().join("photo (2).jpg"));
        let again = save(dir.path(), "../../etc/passwd", b"x", None).unwrap();
        assert_eq!(again, dir.path().join("passwd"));

        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        let (info, chunks) = prepare(&empty, false).unwrap();
        assert_eq!((info.chunks, chunks.len()), (1, 1));
        assert!(assemble(&info, &chunks).unwrap().is_empty());
        let (info, chunks) = prepare(&empty, true).unwrap();
        assert_eq!((info.chunks, chunks.len()), (1, 1));
        assert!(assemble(&info, &chunks).unwrap().is_empty());
    }

    #[test]
    fn what_a_sender_claims_is_checked_before_fetching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.bin");
        std::fs::write(&path, vec![7u8; CHUNK_BYTES + 1]).unwrap();
        let (info, chunks) = prepare(&path, false).unwrap();
        assert!(info.check().is_ok());
        let mut huge = info.clone();
        huge.size = MAX_FILE_BYTES + 1;
        assert!(huge.check().unwrap_err().to_string().contains("cap"));
        let mut odd = info.clone();
        odd.chunks = 1;
        assert!(odd.check().unwrap_err().to_string().contains("chunk"));
        // assemble never trusts the claim either, so it cannot be asked to
        // allocate what a sender made up.
        assert!(assemble(&huge, &chunks).is_err());
        // The description survives the history file as the message it came in.
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(serde_json::from_str::<FileInfo>(&json).unwrap(), info);
    }

    #[test]
    fn saves_at_the_same_moment_never_share_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let dir = dir.path().to_path_buf();
                std::thread::spawn(move || save(&dir, "same.txt", &[i; 64], None).unwrap())
            })
            .collect();
        let mut paths: Vec<PathBuf> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), 8, "{paths:?}");
        for path in &paths {
            let bytes = std::fs::read(path).unwrap();
            assert!(bytes.iter().all(|b| *b == bytes[0]) && bytes.len() == 64);
        }
    }

    #[test]
    fn the_downloads_quota_holds() {
        let dir = tempfile::tempdir().unwrap();
        let downloads = dir.path().join("downloads");
        assert_eq!(dir_size(&downloads), 0);
        save(&downloads, "one.bin", &[0u8; 600], Some(1000)).unwrap();
        assert_eq!(dir_size(&downloads), 600);
        let err = save(&downloads, "two.bin", &[0u8; 500], Some(1000)).unwrap_err();
        assert!(err.to_string().contains("quota"), "{err}");
        assert!(!downloads.join("two.bin").exists());
        save(&downloads, "two.bin", &[0u8; 400], Some(1000)).unwrap();
        save(&downloads, "three.bin", &[0u8; 5000], None).unwrap();
        assert_eq!(dir_size(&downloads), 6000);
    }

    #[test]
    fn names_that_mislead_are_straightened() {
        // A right-to-left override would show "photoexe.png" for a program.
        assert_eq!(sanitize_name("photo\u{202e}gnp.exe"), "photognp.exe");
        assert_eq!(sanitize_name("in\u{200b}voice\u{feff}.pdf"), "invoice.pdf");
        assert_eq!(sanitize_name("caf\u{65}\u{301}.txt"), "caf\u{e9}.txt");
        assert_eq!(sanitize_name("CON"), "_CON");
        assert_eq!(sanitize_name("con.txt"), "_con.txt");
        assert_eq!(sanitize_name("Com1.tar.gz"), "_Com1.tar.gz");
        assert_eq!(sanitize_name("lpt10.txt"), "lpt10.txt");
        assert_eq!(sanitize_name("console.log"), "console.log");
        assert_eq!(sanitize_name("name. . ."), "name");
        assert_eq!(sanitize_name("name.txt "), "name.txt");
        assert_eq!(sanitize_name("..."), "file");
        // Found by the fuzzer: the trailing space hid the device name once.
        assert_eq!(sanitize_name("CON . `"), "_CON. `");
        assert_eq!(sanitize_name("_CON. `"), "_CON. `");
        let long = format!("{}.jpeg", "a".repeat(300));
        let got = sanitize_name(&long);
        assert!(
            got.ends_with(".jpeg") && got.chars().count() == MAX_NAME_CHARS - 1,
            "{got}"
        );
        let long_device = format!("CON{}.txt", "x".repeat(300));
        assert!(sanitize_name(&long_device).chars().count() <= MAX_NAME_CHARS);
        // Found by the fuzzer: cutting the name turned its tail into an
        // extension, which a second pass then trimmed differently.
        let shifting = format!("a{} ..{}", "b".repeat(110), "c".repeat(20));
        let once = sanitize_name(&shifting);
        assert_eq!(sanitize_name(&once), once, "{once}");
        let info = FileInfo {
            name: "re\u{202e}fdp.exe".into(),
            size: 10,
            blob: String::new(),
            key: BlobKey::generate(),
            chunks: 1,
            sha256: [0; 32],
        };
        assert_eq!(info.label(), "refdp.exe (10 B)");
        assert_eq!(printable(" bob\u{202e}\x1b]2;x\x07 ", 40), "bob]2;x");
        assert_eq!(printable(&"x".repeat(100), 8), "xxxxxxxx");
    }

    #[test]
    fn programs_are_not_handed_to_the_opener() {
        for name in [
            "a.exe",
            "b.EXE",
            "invoice.pdf.exe",
            "run.sh",
            "x.py",
            "y.lnk",
            "z.msi",
            "w.jar",
            "v.bat",
            "u.desktop",
            "t.Ps1",
        ] {
            assert!(refuse_to_open(Path::new(name)).is_some(), "{name}");
        }
        for name in [
            "a.pdf",
            "b.png",
            "c.tar.gz",
            "noext",
            "d.docx",
            "e.txt",
            "photo.bin",
        ] {
            assert!(refuse_to_open(Path::new(name)).is_none(), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn saved_files_carry_the_mark_of_the_web() {
        let dir = tempfile::tempdir().unwrap();
        let saved = save(dir.path(), "from-the-net.txt", b"hello", None).unwrap();
        let zone = std::fs::read_to_string(format!("{}:Zone.Identifier", saved.display())).unwrap();
        assert!(zone.contains("ZoneId=3"), "{zone}");
    }

    #[test]
    fn names_and_sizes_are_tidy() {
        assert_eq!(
            sanitize_name("C:\\Users\\me\\..\\report:final?.pdf"),
            "report_final_.pdf".replace('_', "")
        );
        assert_eq!(sanitize_name("...hidden"), "hidden");
        assert_eq!(sanitize_name("   "), "file");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(16 * 1024 * 1024), "16.0 MiB");
    }
}
