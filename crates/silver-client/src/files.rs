//! Files as attachments: turning a file into encrypted chunks and a
//! [`Content::File`] message, and back.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use silver_protocol::Content;
use silver_protocol::blob::{
    BlobKey, CHUNK_BYTES, MAX_FILE_BYTES, chunk_count, new_blob_id, open_chunk, seal_chunk,
};

/// What a [`Content::File`] message says about a file.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// `name (1.2 MiB)`.
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, human_size(self.size))
    }
}

/// Read `path`, encrypt it chunk by chunk under a fresh key, and describe it.
pub fn prepare(path: &Path) -> anyhow::Result<(FileInfo, Vec<Vec<u8>>)> {
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
    let total = chunk_count(bytes.len() as u64);
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
        size: bytes.len() as u64,
        blob,
        key,
        chunks: total,
        sha256: Sha256::digest(&bytes).into(),
    };
    Ok((info, chunks))
}

/// Decrypt fetched chunks and check the result against what the sender
/// promised.
pub fn assemble(info: &FileInfo, chunks: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    if chunks.len() != info.chunks as usize {
        bail!("expected {} chunks, got {}", info.chunks, chunks.len());
    }
    let mut bytes = Vec::with_capacity(info.size as usize);
    for (index, chunk) in chunks.iter().enumerate() {
        let plain = open_chunk(&info.key, &info.blob, index as u32, info.chunks, chunk)
            .with_context(|| format!("chunk {index} does not decrypt"))?;
        bytes.extend_from_slice(&plain);
    }
    if bytes.len() as u64 != info.size {
        bail!("file is {} bytes, expected {}", bytes.len(), info.size);
    }
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != info.sha256 {
        bail!("file hash does not match what the sender promised");
    }
    Ok(bytes)
}

/// Write `bytes` into `dir` under `name`, never overwriting: a taken name
/// gets ` (2)`, ` (3)` and so on before its extension.
pub fn save(dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = sanitize_name(name);
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_owned(), format!(".{ext}")),
        _ => (name.clone(), String::new()),
    };
    let mut candidate = dir.join(&name);
    let mut n = 2;
    while candidate.exists() {
        candidate = dir.join(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    std::fs::write(&candidate, bytes)
        .with_context(|| format!("writing {}", candidate.display()))?;
    Ok(candidate)
}

/// A file name safe to create locally: no directories, no control
/// characters, nothing hidden, at most 120 characters.
pub fn sanitize_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .take(120)
        .collect::<String>();
    let trimmed = base.trim().trim_start_matches('.').to_owned();
    if trimmed.is_empty() {
        "file".to_owned()
    } else {
        trimmed
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
        let (info, chunks) = prepare(&path).unwrap();
        assert_eq!(info.name, "photo.jpg");
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.chunks, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(info.label(), "photo.jpg (128.1 KiB)");
        let content = info.clone().into_content();
        assert_eq!(FileInfo::from_content(&content), Some(info.clone()));
        assert_eq!(assemble(&info, &chunks).unwrap(), data);

        // A damaged chunk, a missing chunk or the wrong count are refused.
        let mut damaged = chunks.clone();
        damaged[1][0] ^= 1;
        assert!(assemble(&info, &damaged).is_err());
        assert!(assemble(&info, &chunks[..2]).is_err());
        let mut lying = info.clone();
        lying.size += 1;
        assert!(assemble(&lying, &chunks).is_err());

        let saved = save(dir.path(), "photo.jpg", &data).unwrap();
        assert_eq!(saved, dir.path().join("photo (2).jpg"));
        let again = save(dir.path(), "../../etc/passwd", b"x").unwrap();
        assert_eq!(again, dir.path().join("passwd"));

        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        let (info, chunks) = prepare(&empty).unwrap();
        assert_eq!((info.chunks, chunks.len()), (1, 1));
        assert!(assemble(&info, &chunks).unwrap().is_empty());
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
