//! Backups of the whole store, in a format of the relay's own.
//!
//! A backup is a consistent snapshot: one read transaction walks every
//! table, so a backup taken while the relay runs is one moment's picture
//! and not a mix of moments. The format belongs to the relay rather than
//! to the database engine, so a backup taken today stays readable by a
//! later relay whatever the engine does with its file format, and it is
//! checked before it is trusted: the file ends in a record count and a
//! SHA-256 over everything before it, and [`load`] commits nothing unless
//! that trailer checks out.
//!
//! The layout is the line `silver-relay-backup`, a JSON header line
//! (`format`, `schema`, `relay`, `taken_at_ms`), then one record per table
//! entry (a tag byte, then fields that are length-prefixed bytes or
//! fixed-width big-endian integers) and the trailer (tag 0, the count, the
//! digest). A backup holds what the database holds: ciphertext, public
//! keys, bans, counters. Keep it as private as the database, and encrypt
//! it before it leaves the host.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use redb::{ReadableDatabase, ReadableTable, Table, WriteTransaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::store::{self, SCHEMA, SCHEMA_VERSION, Store};

/// The backup format this relay writes and reads.
pub const FORMAT: u32 = 2;
const MAGIC: &[u8] = b"silver-relay-backup\n";
/// The longest field a record may carry. A blob chunk is 64 KiB and a
/// mailbox entry well under a megabyte, so this bounds what a corrupt
/// length can ask for.
const MAX_FIELD: u32 = 16 * 1024 * 1024;
const MAX_HEADER: usize = 4096;
const END: u8 = 0;
const TRUNCATED: &str = "the backup ends before its trailer: it is incomplete";

/// The first line after the magic: what wrote the backup and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub schema: u64,
    pub relay: String,
    pub taken_at_ms: u64,
}

/// What a backup holds, counted while it is written or read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub records: u64,
    pub bytes: u64,
    pub identities: u64,
    pub messages: u64,
    pub blobs: u64,
}

impl Summary {
    fn count(&mut self, record: &Record) {
        self.records += 1;
        match record {
            Record::Bundle { .. } => self.identities += 1,
            Record::Mailbox { .. } => self.messages += 1,
            Record::Blob { .. } => self.blobs += 1,
            _ => {}
        }
    }
}

/// One table entry, owned. The tag is the table's number in the format;
/// the tables are listed in `store.rs`, and every one of them is here.
#[derive(Debug, PartialEq, Eq)]
enum Record {
    Bundle {
        user: Vec<u8>,
        json: Vec<u8>,
    },
    OneTime {
        user: Vec<u8>,
        id: u32,
        key: Vec<u8>,
    },
    OneTimeUsed {
        user: Vec<u8>,
        id: u32,
    },
    PqOneTime {
        user: Vec<u8>,
        id: u32,
        key: Vec<u8>,
    },
    PqOneTimeUsed {
        user: Vec<u8>,
        id: u32,
    },
    Mailbox {
        user: Vec<u8>,
        seq: u64,
        entry: Vec<u8>,
    },
    ById {
        id: String,
        user: Vec<u8>,
        seq: u64,
    },
    Usage {
        user: Vec<u8>,
        messages: u64,
        bytes: u64,
    },
    Meta {
        key: String,
        value: u64,
    },
    Blob {
        id: String,
        meta: Vec<u8>,
    },
    BlobChunk {
        id: String,
        index: u32,
        data: Vec<u8>,
    },
    Ban {
        key: String,
        json: Vec<u8>,
    },
    Admin {
        key: String,
        value: String,
    },
    Revocation {
        user: Vec<u8>,
        json: Vec<u8>,
    },
    Succession {
        user: Vec<u8>,
        json: Vec<u8>,
    },
    LogEntry {
        index: u64,
        json: Vec<u8>,
    },
    LogLatest {
        subject: Vec<u8>,
        json: Vec<u8>,
    },
    /// Format 2: key packages on deposit, the group sequencer and device
    /// revocations.
    KeyPackage {
        user: Vec<u8>,
        seq: u64,
        json: Vec<u8>,
    },
    KeyPackageUsed {
        user: Vec<u8>,
        r#ref: Vec<u8>,
    },
    KeyPackageLastResort {
        user: Vec<u8>,
        json: Vec<u8>,
    },
    Group {
        id: Vec<u8>,
        json: Vec<u8>,
    },
    DeviceRevocation {
        device: Vec<u8>,
        json: Vec<u8>,
    },
    DeviceRevocationByAccount {
        account: Vec<u8>,
        device: Vec<u8>,
    },
}

impl Record {
    fn tag(&self) -> u8 {
        match self {
            Self::Bundle { .. } => 1,
            Self::OneTime { .. } => 2,
            Self::OneTimeUsed { .. } => 3,
            Self::PqOneTime { .. } => 4,
            Self::PqOneTimeUsed { .. } => 5,
            Self::Mailbox { .. } => 6,
            Self::ById { .. } => 7,
            Self::Usage { .. } => 8,
            Self::Meta { .. } => 9,
            Self::Blob { .. } => 10,
            Self::BlobChunk { .. } => 11,
            Self::Ban { .. } => 12,
            Self::Admin { .. } => 13,
            Self::Revocation { .. } => 14,
            Self::Succession { .. } => 15,
            Self::LogEntry { .. } => 16,
            Self::LogLatest { .. } => 17,
            Self::KeyPackage { .. } => 18,
            Self::KeyPackageUsed { .. } => 19,
            Self::KeyPackageLastResort { .. } => 20,
            Self::Group { .. } => 21,
            Self::DeviceRevocation { .. } => 22,
            Self::DeviceRevocationByAccount { .. } => 23,
        }
    }

    fn put<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[self.tag()])?;
        match self {
            Self::Bundle { user, json } => {
                put_bytes(w, user)?;
                put_bytes(w, json)
            }
            Self::OneTime { user, id, key } | Self::PqOneTime { user, id, key } => {
                put_bytes(w, user)?;
                put_u32(w, *id)?;
                put_bytes(w, key)
            }
            Self::OneTimeUsed { user, id } | Self::PqOneTimeUsed { user, id } => {
                put_bytes(w, user)?;
                put_u32(w, *id)
            }
            Self::Mailbox { user, seq, entry } => {
                put_bytes(w, user)?;
                put_u64(w, *seq)?;
                put_bytes(w, entry)
            }
            Self::ById { id, user, seq } => {
                put_bytes(w, id.as_bytes())?;
                put_bytes(w, user)?;
                put_u64(w, *seq)
            }
            Self::Usage {
                user,
                messages,
                bytes,
            } => {
                put_bytes(w, user)?;
                put_u64(w, *messages)?;
                put_u64(w, *bytes)
            }
            Self::Meta { key, value } => {
                put_bytes(w, key.as_bytes())?;
                put_u64(w, *value)
            }
            Self::Blob { id, meta } => {
                put_bytes(w, id.as_bytes())?;
                put_bytes(w, meta)
            }
            Self::BlobChunk { id, index, data } => {
                put_bytes(w, id.as_bytes())?;
                put_u32(w, *index)?;
                put_bytes(w, data)
            }
            Self::Ban { key, json } => {
                put_bytes(w, key.as_bytes())?;
                put_bytes(w, json)
            }
            Self::Admin { key, value } => {
                put_bytes(w, key.as_bytes())?;
                put_bytes(w, value.as_bytes())
            }
            Self::Revocation { user, json } | Self::Succession { user, json } => {
                put_bytes(w, user)?;
                put_bytes(w, json)
            }
            Self::LogEntry { index, json } => {
                put_u64(w, *index)?;
                put_bytes(w, json)
            }
            Self::LogLatest { subject, json } => {
                put_bytes(w, subject)?;
                put_bytes(w, json)
            }
            Self::KeyPackage { user, seq, json } => {
                put_bytes(w, user)?;
                put_u64(w, *seq)?;
                put_bytes(w, json)
            }
            Self::KeyPackageUsed { user, r#ref } => {
                put_bytes(w, user)?;
                put_bytes(w, r#ref)
            }
            Self::KeyPackageLastResort { user, json } => {
                put_bytes(w, user)?;
                put_bytes(w, json)
            }
            Self::Group { id, json } => {
                put_bytes(w, id)?;
                put_bytes(w, json)
            }
            Self::DeviceRevocation { device, json } => {
                put_bytes(w, device)?;
                put_bytes(w, json)
            }
            Self::DeviceRevocationByAccount { account, device } => {
                put_bytes(w, account)?;
                put_bytes(w, device)
            }
        }
    }

    /// The record with `tag`, whose fields follow in `r`.
    fn get<R: Read>(tag: u8, r: &mut R) -> anyhow::Result<Self> {
        Ok(match tag {
            1 => Self::Bundle {
                user: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            2 => Self::OneTime {
                user: get_bytes(r)?,
                id: get_u32(r)?,
                key: get_bytes(r)?,
            },
            3 => Self::OneTimeUsed {
                user: get_bytes(r)?,
                id: get_u32(r)?,
            },
            4 => Self::PqOneTime {
                user: get_bytes(r)?,
                id: get_u32(r)?,
                key: get_bytes(r)?,
            },
            5 => Self::PqOneTimeUsed {
                user: get_bytes(r)?,
                id: get_u32(r)?,
            },
            6 => Self::Mailbox {
                user: get_bytes(r)?,
                seq: get_u64(r)?,
                entry: get_bytes(r)?,
            },
            7 => Self::ById {
                id: get_string(r)?,
                user: get_bytes(r)?,
                seq: get_u64(r)?,
            },
            8 => Self::Usage {
                user: get_bytes(r)?,
                messages: get_u64(r)?,
                bytes: get_u64(r)?,
            },
            9 => Self::Meta {
                key: get_string(r)?,
                value: get_u64(r)?,
            },
            10 => Self::Blob {
                id: get_string(r)?,
                meta: get_bytes(r)?,
            },
            11 => Self::BlobChunk {
                id: get_string(r)?,
                index: get_u32(r)?,
                data: get_bytes(r)?,
            },
            12 => Self::Ban {
                key: get_string(r)?,
                json: get_bytes(r)?,
            },
            13 => Self::Admin {
                key: get_string(r)?,
                value: get_string(r)?,
            },
            14 => Self::Revocation {
                user: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            15 => Self::Succession {
                user: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            16 => Self::LogEntry {
                index: get_u64(r)?,
                json: get_bytes(r)?,
            },
            17 => Self::LogLatest {
                subject: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            18 => Self::KeyPackage {
                user: get_bytes(r)?,
                seq: get_u64(r)?,
                json: get_bytes(r)?,
            },
            19 => Self::KeyPackageUsed {
                user: get_bytes(r)?,
                r#ref: get_bytes(r)?,
            },
            20 => Self::KeyPackageLastResort {
                user: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            21 => Self::Group {
                id: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            22 => Self::DeviceRevocation {
                device: get_bytes(r)?,
                json: get_bytes(r)?,
            },
            23 => Self::DeviceRevocationByAccount {
                account: get_bytes(r)?,
                device: get_bytes(r)?,
            },
            other => bail!("record type {other} is not in backup format {FORMAT}"),
        })
    }
}

/// Every entry of every table, in table order.
fn each_record(
    txn: &redb::ReadTransaction,
    mut emit: impl FnMut(Record) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for item in txn.open_table(store::BUNDLES)?.iter()? {
        let (k, v) = item?;
        emit(Record::Bundle {
            user: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::ONE_TIME)?.iter()? {
        let (k, v) = item?;
        let (user, id) = k.value();
        emit(Record::OneTime {
            user: user.to_vec(),
            id,
            key: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::ONE_TIME_USED)?.iter()? {
        let (k, _) = item?;
        let (user, id) = k.value();
        emit(Record::OneTimeUsed {
            user: user.to_vec(),
            id,
        })?;
    }
    for item in txn.open_table(store::PQ_ONE_TIME)?.iter()? {
        let (k, v) = item?;
        let (user, id) = k.value();
        emit(Record::PqOneTime {
            user: user.to_vec(),
            id,
            key: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::PQ_ONE_TIME_USED)?.iter()? {
        let (k, _) = item?;
        let (user, id) = k.value();
        emit(Record::PqOneTimeUsed {
            user: user.to_vec(),
            id,
        })?;
    }
    for item in txn.open_table(store::MAILBOX)?.iter()? {
        let (k, v) = item?;
        let (user, seq) = k.value();
        emit(Record::Mailbox {
            user: user.to_vec(),
            seq,
            entry: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::BY_ID)?.iter()? {
        let (k, v) = item?;
        let (user, seq) = v.value();
        emit(Record::ById {
            id: k.value().to_owned(),
            user: user.to_vec(),
            seq,
        })?;
    }
    for item in txn.open_table(store::USAGE)?.iter()? {
        let (k, v) = item?;
        let (messages, bytes) = v.value();
        emit(Record::Usage {
            user: k.value().to_vec(),
            messages,
            bytes,
        })?;
    }
    for item in txn.open_table(store::META)?.iter()? {
        let (k, v) = item?;
        emit(Record::Meta {
            key: k.value().to_owned(),
            value: v.value(),
        })?;
    }
    for item in txn.open_table(store::BLOBS)?.iter()? {
        let (k, v) = item?;
        emit(Record::Blob {
            id: k.value().to_owned(),
            meta: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::BLOB_CHUNKS)?.iter()? {
        let (k, v) = item?;
        let (id, index) = k.value();
        emit(Record::BlobChunk {
            id: id.to_owned(),
            index,
            data: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::BANS)?.iter()? {
        let (k, v) = item?;
        emit(Record::Ban {
            key: k.value().to_owned(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::ADMIN)?.iter()? {
        let (k, v) = item?;
        emit(Record::Admin {
            key: k.value().to_owned(),
            value: v.value().to_owned(),
        })?;
    }
    for item in txn.open_table(store::REVOCATIONS)?.iter()? {
        let (k, v) = item?;
        emit(Record::Revocation {
            user: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::SUCCESSIONS)?.iter()? {
        let (k, v) = item?;
        emit(Record::Succession {
            user: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::LOG)?.iter()? {
        let (k, v) = item?;
        emit(Record::LogEntry {
            index: k.value(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::LOG_LATEST)?.iter()? {
        let (k, v) = item?;
        emit(Record::LogLatest {
            subject: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::KEY_PACKAGES)?.iter()? {
        let (k, v) = item?;
        let (user, seq) = k.value();
        emit(Record::KeyPackage {
            user: user.to_vec(),
            seq,
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::KEY_PACKAGES_USED)?.iter()? {
        let (k, _) = item?;
        let (user, r) = k.value();
        emit(Record::KeyPackageUsed {
            user: user.to_vec(),
            r#ref: r.to_vec(),
        })?;
    }
    for item in txn.open_table(store::KEY_PACKAGE_LAST_RESORT)?.iter()? {
        let (k, v) = item?;
        emit(Record::KeyPackageLastResort {
            user: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::GROUPS)?.iter()? {
        let (k, v) = item?;
        emit(Record::Group {
            id: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn.open_table(store::DEVICE_REVOCATIONS)?.iter()? {
        let (k, v) = item?;
        emit(Record::DeviceRevocation {
            device: k.value().to_vec(),
            json: v.value().to_vec(),
        })?;
    }
    for item in txn
        .open_table(store::DEVICE_REVOCATIONS_BY_ACCOUNT)?
        .iter()?
    {
        let (k, _) = item?;
        let (account, device) = k.value();
        emit(Record::DeviceRevocationByAccount {
            account: account.to_vec(),
            device: device.to_vec(),
        })?;
    }
    Ok(())
}

/// Every table of one write transaction, open for restoring into.
struct Tables<'t> {
    bundles: Table<'t, &'static [u8], &'static [u8]>,
    one_time: Table<'t, (&'static [u8], u32), &'static [u8]>,
    one_time_used: Table<'t, (&'static [u8], u32), ()>,
    pq_one_time: Table<'t, (&'static [u8], u32), &'static [u8]>,
    pq_one_time_used: Table<'t, (&'static [u8], u32), ()>,
    mailbox: Table<'t, (&'static [u8], u64), &'static [u8]>,
    by_id: Table<'t, &'static str, (&'static [u8], u64)>,
    usage: Table<'t, &'static [u8], (u64, u64)>,
    meta: Table<'t, &'static str, u64>,
    blobs: Table<'t, &'static str, &'static [u8]>,
    blob_chunks: Table<'t, (&'static str, u32), &'static [u8]>,
    bans: Table<'t, &'static str, &'static [u8]>,
    admin: Table<'t, &'static str, &'static str>,
    revocations: Table<'t, &'static [u8], &'static [u8]>,
    successions: Table<'t, &'static [u8], &'static [u8]>,
    log: Table<'t, u64, &'static [u8]>,
    log_latest: Table<'t, &'static [u8], &'static [u8]>,
    key_packages: Table<'t, (&'static [u8], u64), &'static [u8]>,
    key_packages_used: Table<'t, (&'static [u8], &'static [u8]), ()>,
    key_package_last_resort: Table<'t, &'static [u8], &'static [u8]>,
    groups: Table<'t, &'static [u8], &'static [u8]>,
    device_revocations: Table<'t, &'static [u8], &'static [u8]>,
    device_revocations_by_account: Table<'t, (&'static [u8], &'static [u8]), ()>,
}

impl<'t> Tables<'t> {
    /// Every table, emptied: deleted and created again.
    fn emptied(txn: &'t WriteTransaction) -> anyhow::Result<Self> {
        txn.delete_table(store::BUNDLES)?;
        txn.delete_table(store::ONE_TIME)?;
        txn.delete_table(store::ONE_TIME_USED)?;
        txn.delete_table(store::PQ_ONE_TIME)?;
        txn.delete_table(store::PQ_ONE_TIME_USED)?;
        txn.delete_table(store::MAILBOX)?;
        txn.delete_table(store::BY_ID)?;
        txn.delete_table(store::USAGE)?;
        txn.delete_table(store::META)?;
        txn.delete_table(store::BLOBS)?;
        txn.delete_table(store::BLOB_CHUNKS)?;
        txn.delete_table(store::BANS)?;
        txn.delete_table(store::ADMIN)?;
        txn.delete_table(store::REVOCATIONS)?;
        txn.delete_table(store::SUCCESSIONS)?;
        txn.delete_table(store::LOG)?;
        txn.delete_table(store::LOG_LATEST)?;
        txn.delete_table(store::KEY_PACKAGES)?;
        txn.delete_table(store::KEY_PACKAGES_USED)?;
        txn.delete_table(store::KEY_PACKAGE_LAST_RESORT)?;
        txn.delete_table(store::GROUPS)?;
        txn.delete_table(store::DEVICE_REVOCATIONS)?;
        txn.delete_table(store::DEVICE_REVOCATIONS_BY_ACCOUNT)?;
        Ok(Self {
            bundles: txn.open_table(store::BUNDLES)?,
            one_time: txn.open_table(store::ONE_TIME)?,
            one_time_used: txn.open_table(store::ONE_TIME_USED)?,
            pq_one_time: txn.open_table(store::PQ_ONE_TIME)?,
            pq_one_time_used: txn.open_table(store::PQ_ONE_TIME_USED)?,
            mailbox: txn.open_table(store::MAILBOX)?,
            by_id: txn.open_table(store::BY_ID)?,
            usage: txn.open_table(store::USAGE)?,
            meta: txn.open_table(store::META)?,
            blobs: txn.open_table(store::BLOBS)?,
            blob_chunks: txn.open_table(store::BLOB_CHUNKS)?,
            bans: txn.open_table(store::BANS)?,
            admin: txn.open_table(store::ADMIN)?,
            revocations: txn.open_table(store::REVOCATIONS)?,
            successions: txn.open_table(store::SUCCESSIONS)?,
            log: txn.open_table(store::LOG)?,
            log_latest: txn.open_table(store::LOG_LATEST)?,
            key_packages: txn.open_table(store::KEY_PACKAGES)?,
            key_packages_used: txn.open_table(store::KEY_PACKAGES_USED)?,
            key_package_last_resort: txn.open_table(store::KEY_PACKAGE_LAST_RESORT)?,
            groups: txn.open_table(store::GROUPS)?,
            device_revocations: txn.open_table(store::DEVICE_REVOCATIONS)?,
            device_revocations_by_account: txn.open_table(store::DEVICE_REVOCATIONS_BY_ACCOUNT)?,
        })
    }

    fn insert(&mut self, record: &Record) -> anyhow::Result<()> {
        match record {
            Record::Bundle { user, json } => {
                self.bundles.insert(user.as_slice(), json.as_slice())?;
            }
            Record::OneTime { user, id, key } => {
                self.one_time
                    .insert((user.as_slice(), *id), key.as_slice())?;
            }
            Record::OneTimeUsed { user, id } => {
                self.one_time_used.insert((user.as_slice(), *id), ())?;
            }
            Record::PqOneTime { user, id, key } => {
                self.pq_one_time
                    .insert((user.as_slice(), *id), key.as_slice())?;
            }
            Record::PqOneTimeUsed { user, id } => {
                self.pq_one_time_used.insert((user.as_slice(), *id), ())?;
            }
            Record::Mailbox { user, seq, entry } => {
                self.mailbox
                    .insert((user.as_slice(), *seq), entry.as_slice())?;
            }
            Record::ById { id, user, seq } => {
                self.by_id.insert(id.as_str(), (user.as_slice(), *seq))?;
            }
            Record::Usage {
                user,
                messages,
                bytes,
            } => {
                self.usage.insert(user.as_slice(), (*messages, *bytes))?;
            }
            Record::Meta { key, value } => {
                self.meta.insert(key.as_str(), *value)?;
            }
            Record::Blob { id, meta } => {
                self.blobs.insert(id.as_str(), meta.as_slice())?;
            }
            Record::BlobChunk { id, index, data } => {
                self.blob_chunks
                    .insert((id.as_str(), *index), data.as_slice())?;
            }
            Record::Ban { key, json } => {
                self.bans.insert(key.as_str(), json.as_slice())?;
            }
            Record::Admin { key, value } => {
                self.admin.insert(key.as_str(), value.as_str())?;
            }
            Record::Revocation { user, json } => {
                self.revocations.insert(user.as_slice(), json.as_slice())?;
            }
            Record::Succession { user, json } => {
                self.successions.insert(user.as_slice(), json.as_slice())?;
            }
            Record::LogEntry { index, json } => {
                self.log.insert(*index, json.as_slice())?;
            }
            Record::LogLatest { subject, json } => {
                self.log_latest
                    .insert(subject.as_slice(), json.as_slice())?;
            }
            Record::KeyPackage { user, seq, json } => {
                self.key_packages
                    .insert((user.as_slice(), *seq), json.as_slice())?;
            }
            Record::KeyPackageUsed { user, r#ref } => {
                self.key_packages_used
                    .insert((user.as_slice(), r#ref.as_slice()), ())?;
            }
            Record::KeyPackageLastResort { user, json } => {
                self.key_package_last_resort
                    .insert(user.as_slice(), json.as_slice())?;
            }
            Record::Group { id, json } => {
                self.groups.insert(id.as_slice(), json.as_slice())?;
            }
            Record::DeviceRevocation { device, json } => {
                self.device_revocations
                    .insert(device.as_slice(), json.as_slice())?;
            }
            Record::DeviceRevocationByAccount { account, device } => {
                self.device_revocations_by_account
                    .insert((account.as_slice(), device.as_slice()), ())?;
            }
        }
        Ok(())
    }
}

// --- the bytes -----------------------------------------------------------------

struct HashWriter<W: Write> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hash.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct HashReader<R: Read> {
    inner: R,
    hash: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

fn put_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .ok()
        .filter(|len| *len <= MAX_FIELD)
        .ok_or_else(|| io::Error::other("a field too long for the backup format"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(bytes)
}

fn put_u32<W: Write>(w: &mut W, value: u32) -> io::Result<()> {
    w.write_all(&value.to_be_bytes())
}

fn put_u64<W: Write>(w: &mut W, value: u64) -> io::Result<()> {
    w.write_all(&value.to_be_bytes())
}

fn get_u8<R: Read>(r: &mut R) -> anyhow::Result<u8> {
    let mut byte = [0u8; 1];
    r.read_exact(&mut byte).context(TRUNCATED)?;
    Ok(byte[0])
}

fn get_u32<R: Read>(r: &mut R) -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    r.read_exact(&mut bytes).context(TRUNCATED)?;
    Ok(u32::from_be_bytes(bytes))
}

fn get_u64<R: Read>(r: &mut R) -> anyhow::Result<u64> {
    let mut bytes = [0u8; 8];
    r.read_exact(&mut bytes).context(TRUNCATED)?;
    Ok(u64::from_be_bytes(bytes))
}

fn get_bytes<R: Read>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let len = get_u32(r)?;
    ensure!(
        len <= MAX_FIELD,
        "a field of {len} bytes is longer than the backup format allows: the backup is corrupt"
    );
    let mut bytes = vec![0u8; len as usize];
    r.read_exact(&mut bytes).context(TRUNCATED)?;
    Ok(bytes)
}

fn get_string<R: Read>(r: &mut R) -> anyhow::Result<String> {
    String::from_utf8(get_bytes(r)?).context("a text field of the backup is not UTF-8")
}

fn put_header<W: Write>(w: &mut W, header: &Header) -> anyhow::Result<()> {
    w.write_all(MAGIC)?;
    serde_json::to_writer(&mut *w, header)?;
    w.write_all(b"\n")?;
    Ok(())
}

fn get_header<R: Read>(r: &mut R) -> anyhow::Result<Header> {
    let mut magic = vec![0u8; MAGIC.len()];
    r.read_exact(&mut magic)
        .ok()
        .filter(|()| magic == MAGIC)
        .context("this is not a silver-relay backup")?;
    let mut line = Vec::new();
    loop {
        let byte = get_u8(r).context("the backup's header is cut off")?;
        if byte == b'\n' {
            break;
        }
        line.push(byte);
        ensure!(
            line.len() <= MAX_HEADER,
            "the backup's header is longer than a header can be"
        );
    }
    let header: Header =
        serde_json::from_slice(&line).context("the backup's header is unreadable")?;
    // Format 1 (0.7.0 and 0.8.0) is format 2 without the records 0.9.0
    // added, so it still loads; a later format is refused.
    ensure!(
        header.format <= FORMAT,
        "the backup is in format {}; this silver-relay {} reads formats up to {FORMAT}",
        header.format,
        env!("CARGO_PKG_VERSION")
    );
    ensure!(
        header.schema <= SCHEMA_VERSION,
        "the backup was taken by a newer relay (schema version {}); this silver-relay {} knows version {SCHEMA_VERSION}",
        header.schema,
        env!("CARGO_PKG_VERSION")
    );
    Ok(header)
}

// --- whole backups --------------------------------------------------------------

/// Write a backup of `store` to `out`, taken in one read transaction.
pub fn write<W: Write>(store: &Store, out: W, taken_at_ms: u64) -> anyhow::Result<Summary> {
    let txn = store.db.begin_read()?;
    let schema = txn
        .open_table(store::META)?
        .get(SCHEMA)?
        .map(|g| g.value())
        .unwrap_or(0);
    let mut w = HashWriter {
        inner: BufWriter::new(out),
        hash: Sha256::new(),
        bytes: 0,
    };
    put_header(
        &mut w,
        &Header {
            format: FORMAT,
            schema,
            relay: env!("CARGO_PKG_VERSION").to_owned(),
            taken_at_ms,
        },
    )?;
    let mut summary = Summary::default();
    each_record(&txn, |record| {
        record.put(&mut w)?;
        summary.count(&record);
        Ok(())
    })?;
    w.write_all(&[END])?;
    put_u64(&mut w, summary.records)?;
    let digest = w.hash.clone().finalize();
    w.write_all(&digest)?;
    w.flush()?;
    summary.bytes = w.bytes;
    Ok(summary)
}

/// Read a backup to its end, handing every record to `sink`, and check the
/// trailer: the count and the digest must match what was read, and nothing
/// may follow.
fn read_all<R: Read>(
    input: R,
    mut sink: impl FnMut(&Record) -> anyhow::Result<()>,
) -> anyhow::Result<(Header, Summary)> {
    let mut r = HashReader {
        inner: BufReader::new(input),
        hash: Sha256::new(),
        bytes: 0,
    };
    let header = get_header(&mut r)?;
    let mut summary = Summary::default();
    loop {
        let tag = get_u8(&mut r)?;
        if tag == END {
            let count = get_u64(&mut r)?;
            let expected = r.hash.clone().finalize();
            let mut found = [0u8; 32];
            r.read_exact(&mut found).context(TRUNCATED)?;
            ensure!(
                count == summary.records,
                "the backup says it holds {count} records but {} were read",
                summary.records
            );
            ensure!(
                found[..] == expected[..],
                "the backup's checksum does not match its content: it was altered"
            );
            let mut extra = [0u8; 1];
            ensure!(
                r.read(&mut extra)? == 0,
                "the backup has data after its trailer"
            );
            break;
        }
        let record = Record::get(tag, &mut r)?;
        sink(&record)?;
        summary.count(&record);
    }
    summary.bytes = r.bytes;
    Ok((header, summary))
}

/// Check a backup from start to trailer without loading it.
pub fn verify<R: Read>(input: R) -> anyhow::Result<(Header, Summary)> {
    read_all(input, |_| Ok(()))
}

/// Replace everything in `store` with the backup in `input`. Nothing is
/// committed unless the whole backup reads and its trailer checks out; a
/// backup from an older layout is brought up to [`SCHEMA_VERSION`] on the
/// way in.
pub fn load<R: Read>(store: &Store, input: R) -> anyhow::Result<(Header, Summary)> {
    let txn = store.db.begin_write()?;
    let read = {
        let mut tables = Tables::emptied(&txn)?;
        read_all(input, |record| tables.insert(record))
    };
    let (header, summary) = read?;
    for version in header.schema..SCHEMA_VERSION {
        store::migrate(&txn, version)?;
    }
    txn.open_table(store::META)?
        .insert(SCHEMA, SCHEMA_VERSION)?;
    txn.commit()?;
    Ok((header, summary))
}

// --- files ----------------------------------------------------------------------

/// Where a data directory keeps the database.
pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join("relay.redb")
}

/// A backup on disk at `dest`, produced by `produce` into a `.part` file
/// next to it that only its owner can read, checked from start to trailer,
/// and only then given its name: a file called a backup is a whole one.
pub fn to_file(
    dest: &Path,
    produce: impl FnOnce(&mut dyn Write) -> anyhow::Result<()>,
) -> anyhow::Result<(Header, Summary)> {
    let part = part_of(dest);
    let mut file = private_file(&part).with_context(|| format!("creating {}", part.display()))?;
    let written = produce(&mut file).and_then(|()| {
        file.sync_all()
            .with_context(|| format!("flushing {} to disk", part.display()))
    });
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    let checked = File::open(&part)
        .with_context(|| format!("reading {} back", part.display()))
        .and_then(verify);
    match checked {
        Ok(checked) => {
            fs::rename(&part, dest)
                .with_context(|| format!("moving {} to {}", part.display(), dest.display()))?;
            Ok(checked)
        }
        Err(e) => {
            let _ = fs::remove_file(&part);
            Err(e.context("the backup did not check out after it was written"))
        }
    }
}

fn part_of(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

fn private_file(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Open the database of a relay that is not running. A running relay holds
/// the file; the error then says to go through its socket instead.
fn open_stopped(path: &Path) -> anyhow::Result<Store> {
    Store::open(path).map_err(|e| match e.downcast_ref::<redb::DatabaseError>() {
        Some(redb::DatabaseError::DatabaseAlreadyOpen) => anyhow::anyhow!(
            "the relay is running and holds {}; stop it first (a backup can also be taken through its admin socket)",
            path.display()
        ),
        _ => e,
    })
}

/// Back up the database in `data_dir` to `dest`, with the relay stopped.
pub fn offline(
    data_dir: &Path,
    dest: &Path,
    taken_at_ms: u64,
) -> anyhow::Result<(Header, Summary)> {
    let path = database_path(data_dir);
    ensure!(path.exists(), "there is no database at {}", path.display());
    let store = open_stopped(&path)?;
    to_file(dest, |out| write(&store, out, taken_at_ms).map(drop))
}

/// What [`restore`] did.
#[derive(Debug)]
pub struct Restored {
    pub header: Header,
    pub summary: Summary,
    /// Where the database that was there before went.
    pub replaced: Option<PathBuf>,
}

/// Load the backup in `file` into a fresh database in `data_dir`, with the
/// relay stopped. A database already there is refused unless `replace` is
/// set, in which case it is moved aside (and moved back if the restore
/// fails). The file is checked before anything is touched.
pub fn restore(
    data_dir: &Path,
    file: &Path,
    replace: bool,
    now_secs: u64,
) -> anyhow::Result<Restored> {
    File::open(file)
        .with_context(|| format!("opening {}", file.display()))
        .and_then(verify)
        .with_context(|| format!("checking {}", file.display()))?;
    let path = database_path(data_dir);
    let mut replaced = None;
    if path.exists() {
        ensure!(
            replace,
            "{} exists; stop the relay and pass --replace to move it aside and restore over it",
            path.display()
        );
        // Whoever holds the file would keep writing to it under its new name.
        drop(open_stopped(&path)?);
        let aside = data_dir.join(format!("relay.redb.before-restore-{now_secs}"));
        fs::rename(&path, &aside)
            .with_context(|| format!("moving {} to {}", path.display(), aside.display()))?;
        replaced = Some(aside);
    }
    let store = Store::open(&path)?;
    let loaded = File::open(file)
        .with_context(|| format!("opening {}", file.display()))
        .and_then(|input| load(&store, input));
    drop(store);
    match loaded {
        Ok((header, summary)) => Ok(Restored {
            header,
            summary,
            replaced,
        }),
        Err(e) => {
            let _ = fs::remove_file(&path);
            if let Some(aside) = &replaced {
                let _ = fs::rename(aside, &path);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{BlobLimits, Limits};
    use silver_protocol::{Content, Identity, PqPrekeySecret, PrekeySecret, Prekeys, seal};

    /// A store with something in every table.
    fn populated() -> (Store, Identity, Identity) {
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate();
        let carol = Identity::generate();
        for who in [&bob, &carol] {
            let signed = PrekeySecret::generate(1, 0);
            store
                .put_bundle(
                    &who.key_bundle_with(Prekeys::classical(signed.signed_by(who), Vec::new())),
                )
                .unwrap();
            store
                .set_one_time_prekeys(
                    &who.user_id(),
                    &[
                        PrekeySecret::generate(2, 0).one_time(),
                        PrekeySecret::generate(3, 0).one_time(),
                    ],
                )
                .unwrap();
            store
                .set_pq_one_time_prekeys(
                    &who.user_id(),
                    &[
                        PqPrekeySecret::generate(4, 0).signed_by(who),
                        PqPrekeySecret::generate(5, 0).signed_by(who),
                    ],
                )
                .unwrap();
        }
        // Handed-out keys populate the "used" tables.
        store.take_one_time_prekey(&bob.user_id()).unwrap();
        store.take_pq_one_time_prekey(&bob.user_id()).unwrap();
        let alice = Identity::generate();
        for (to, texts) in [(&bob, vec!["one", "two", "three"]), (&carol, vec!["four"])] {
            for text in texts {
                let envelope = seal(&alice, &to.key_bundle(), Content::text(text), 0).unwrap();
                store.enqueue(&envelope, 10, Limits::default()).unwrap();
            }
        }
        for index in 0..2 {
            store
                .put_blob_chunk(
                    "a-blob",
                    index,
                    2,
                    &[index as u8; 300],
                    20,
                    BlobLimits::default(),
                )
                .unwrap();
        }
        // Key packages: two on deposit and a last resort for bob, one handed
        // out so the "used" table has an entry; and one group's sequencer.
        let package = |n: u8| silver_protocol::wire::KeyPackageDeposit {
            r#ref: [n; 32],
            expires_at_ms: u64::MAX,
            data: vec![n; 40],
        };
        store
            .set_key_packages(&bob.user_id(), &[package(1), package(2)], Some(&package(9)))
            .unwrap();
        store.take_key_package(&bob.user_id(), 0).unwrap();
        store
            .group_create(&silver_protocol::GroupId([5; 32]), 3, [6; 32], 60)
            .unwrap();
        store
            .set_ban(
                "address:203.0.113.9",
                &crate::store::Ban {
                    since_ms: 30,
                    note: "flood".into(),
                },
            )
            .unwrap();
        store
            .set_admin_setting("invite_token", Some("kept"))
            .unwrap();
        // Lifecycle statements: bob revoked, carol handed over to a successor,
        // and a device of carol's revoked.
        store.set_revocation(&bob.revocation(40)).unwrap();
        let dave = Identity::generate();
        store.set_succession(&carol.succeed_to(&dave, 50)).unwrap();
        let laptop = Identity::generate();
        store
            .set_device_revocation(&carol.revoke_device(&laptop.user_id(), 55))
            .unwrap();
        (store, bob, carol)
    }

    fn dump(store: &Store) -> (Vec<u8>, Summary) {
        let mut bytes = Vec::new();
        let summary = write(store, &mut bytes, 7).unwrap();
        (bytes, summary)
    }

    #[test]
    fn a_backup_round_trips_every_table_byte_for_byte() {
        let (store, bob, carol) = populated();
        let (bytes, summary) = dump(&store);
        assert_eq!(
            (summary.identities, summary.messages, summary.blobs),
            (2, 4, 1)
        );
        assert_eq!(summary.bytes, bytes.len() as u64);
        assert!(bytes.starts_with(MAGIC));

        let restored = Store::in_memory().unwrap();
        let (header, loaded) = load(&restored, bytes.as_slice()).unwrap();
        assert_eq!(
            header,
            Header {
                format: FORMAT,
                schema: SCHEMA_VERSION,
                relay: env!("CARGO_PKG_VERSION").to_owned(),
                taken_at_ms: 7
            }
        );
        assert_eq!(loaded, summary);
        let (again, _) = dump(&restored);
        assert_eq!(again, bytes, "the restored store dumps to the same bytes");

        // And it behaves the same.
        assert_eq!(restored.stats().unwrap(), store.stats().unwrap());
        assert_eq!(restored.queued(&bob.user_id()).unwrap().len(), 3);
        assert_eq!(restored.queued(&carol.user_id()).unwrap().len(), 1);
        assert_eq!(
            restored.one_time_status(&bob.user_id()).unwrap(),
            store.one_time_status(&bob.user_id()).unwrap()
        );
        assert_eq!(
            restored.pq_one_time_status(&bob.user_id()).unwrap(),
            (1, vec![4])
        );
        assert_eq!(
            restored.key_package_status(&bob.user_id()).unwrap(),
            (1, vec![[1; 32]])
        );
        assert_eq!(
            restored
                .last_resort_key_package(&bob.user_id(), 0)
                .unwrap()
                .map(|p| p.r#ref),
            Some([9; 32])
        );
        assert_eq!(
            restored
                .group_epoch(&silver_protocol::GroupId([5; 32]))
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            restored.blob_chunk("a-blob", 1).unwrap(),
            Some(vec![1u8; 300])
        );
        assert_eq!(restored.bans().unwrap(), store.bans().unwrap());
        assert_eq!(
            restored.admin_setting("invite_token").unwrap().as_deref(),
            Some("kept")
        );
        assert!(restored.is_revoked(&bob.user_id()).unwrap());
        assert_eq!(
            restored.revocation(&bob.user_id()).unwrap(),
            store.revocation(&bob.user_id()).unwrap()
        );
        assert_eq!(
            restored.succession(&carol.user_id()).unwrap(),
            store.succession(&carol.user_id()).unwrap()
        );
        assert!(restored.succession(&carol.user_id()).unwrap().is_some());
        let revoked_devices = restored.device_revocations_by(&carol.user_id()).unwrap();
        assert_eq!(revoked_devices.len(), 1);
        assert!(
            restored
                .is_device_revoked(&revoked_devices[0].device)
                .unwrap()
        );
        assert_eq!(restored.schema_version().unwrap(), SCHEMA_VERSION);
        // An acknowledgement finds the restored index.
        let first = restored.queued(&bob.user_id()).unwrap().remove(0);
        assert!(restored.ack(&bob.user_id(), &first.id).unwrap());
    }

    #[test]
    fn loading_replaces_what_the_store_held() {
        let (store, _, _) = populated();
        let (bytes, _) = dump(&store);
        let target = Store::in_memory().unwrap();
        let dave = Identity::generate();
        target.put_bundle(&dave.key_bundle()).unwrap();
        load(&target, bytes.as_slice()).unwrap();
        assert!(target.bundle(&dave.user_id()).unwrap().is_none());
        assert_eq!(target.stats().unwrap().bundles, 2);
    }

    #[test]
    fn a_damaged_backup_is_refused_and_nothing_is_loaded() {
        let (store, _, _) = populated();
        let (bytes, _) = dump(&store);
        let dave = Identity::generate();
        let refuse = |bytes: &[u8], expected: &str| {
            let target = Store::in_memory().unwrap();
            target.put_bundle(&dave.key_bundle()).unwrap();
            let err = load(&target, bytes).unwrap_err();
            assert!(
                format!("{err:#}").contains(expected),
                "expected {expected:?} in {err:#}"
            );
            assert!(
                target.bundle(&dave.user_id()).unwrap().is_some(),
                "the store is untouched"
            );
            assert_eq!(target.stats().unwrap().bundles, 1);
            assert!(verify(bytes).is_err());
        };
        refuse(&bytes[..bytes.len() - 1], "ends before its trailer");
        refuse(&bytes[..bytes.len() / 2], "ends before its trailer");
        refuse(&bytes[..MAGIC.len() + 3], "cut off");
        let mut flipped = bytes.clone();
        let middle = bytes.len() / 2;
        flipped[middle] ^= 0x40;
        refuse(&flipped, "checksum");
        let mut longer = bytes.clone();
        longer.push(0);
        refuse(&longer, "after its trailer");
        refuse(b"something else entirely", "not a silver-relay backup");
    }

    #[test]
    fn a_backup_from_another_format_or_a_newer_relay_is_refused() {
        let (store, _, _) = populated();
        let (bytes, _) = dump(&store);
        let header_end = bytes
            .iter()
            .skip(MAGIC.len())
            .position(|b| *b == b'\n')
            .unwrap();
        let header_line = &bytes[MAGIC.len()..MAGIC.len() + header_end];
        let mut header: Header = serde_json::from_slice(header_line).unwrap();
        let with_header = |header: &Header| {
            let mut out = MAGIC.to_vec();
            out.extend(serde_json::to_vec(header).unwrap());
            out.push(b'\n');
            out.extend_from_slice(&bytes[MAGIC.len() + header_end + 1..]);
            out
        };
        header.format = FORMAT + 1;
        let err = verify(with_header(&header).as_slice()).unwrap_err();
        assert!(err.to_string().contains("format"), "{err}");
        // The format before this one passes the gate (it is a subset of
        // this one); the doctored file then fails its checksum, as it must.
        header.format = FORMAT - 1;
        let err = verify(with_header(&header).as_slice()).unwrap_err();
        assert!(!err.to_string().contains("format"), "{err}");
        header.format = FORMAT;
        header.schema = SCHEMA_VERSION + 1;
        let err = verify(with_header(&header).as_slice()).unwrap_err();
        assert!(err.to_string().contains("newer relay"), "{err}");
    }

    #[test]
    fn a_backup_from_an_unstamped_database_is_brought_up_to_date_on_the_way_in() {
        let (store, bob, _) = populated();
        store.stamp_schema(None).unwrap();
        let (bytes, _) = dump(&store);
        let (header, _) = verify(bytes.as_slice()).unwrap();
        assert_eq!(header.schema, 0);
        let restored = Store::in_memory().unwrap();
        load(&restored, bytes.as_slice()).unwrap();
        assert_eq!(restored.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(restored.bundle(&bob.user_id()).unwrap().is_some());
        // The log came with the backup, and bringing the layout up to date
        // did not seed it a second time.
        assert_eq!(restored.log_head().unwrap(), store.log_head().unwrap());
        assert!(restored.log_head().unwrap().index > 0);
    }

    #[test]
    fn to_file_leaves_a_whole_private_file_or_nothing() {
        let (store, _, _) = populated();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("relay.backup");
        let (header, summary) = to_file(&dest, |out| write(&store, out, 9).map(drop)).unwrap();
        assert_eq!(header.taken_at_ms, 9);
        assert_eq!(summary.identities, 2);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().len(),
            summary.bytes,
            "the summary counts what is on disk"
        );
        assert!(!part_of(&dest).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let bad = dir.path().join("bad.backup");
        let err = to_file(&bad, |out| {
            out.write_all(b"not a backup")?;
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("did not check out"), "{err:#}");
        assert!(!bad.exists() && !part_of(&bad).exists());

        let failed = dir.path().join("failed.backup");
        let err = to_file(&failed, |_| anyhow::bail!("the source went away")).unwrap_err();
        assert!(err.to_string().contains("went away"));
        assert!(!failed.exists() && !part_of(&failed).exists());
    }

    #[test]
    fn offline_backup_and_restore_between_data_directories() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let bob = Identity::generate();
        {
            let store = Store::open(&database_path(&first)).unwrap();
            store.put_bundle(&bob.key_bundle()).unwrap();
        }
        let file = dir.path().join("relay.backup");
        let (_, summary) = offline(&first, &file, 11).unwrap();
        assert_eq!(summary.identities, 1);
        assert!(offline(&second, &file, 11).is_err(), "no database there");

        let restored = restore(&second, &file, false, 100).unwrap();
        assert_eq!(restored.summary.identities, 1);
        assert_eq!(restored.replaced, None);
        {
            let store = Store::open(&database_path(&second)).unwrap();
            assert!(store.bundle(&bob.user_id()).unwrap().is_some());
            let carol = Identity::generate();
            store.put_bundle(&carol.key_bundle()).unwrap();
        }
        // Not over an existing database without saying so.
        let err = restore(&second, &file, false, 101).unwrap_err();
        assert!(err.to_string().contains("--replace"), "{err}");
        let restored = restore(&second, &file, true, 102).unwrap();
        let aside = restored.replaced.unwrap();
        assert_eq!(
            aside.file_name().unwrap().to_str().unwrap(),
            "relay.redb.before-restore-102"
        );
        assert_eq!(
            Store::open(&database_path(&second))
                .unwrap()
                .stats()
                .unwrap()
                .bundles,
            1
        );
        assert_eq!(Store::open(&aside).unwrap().stats().unwrap().bundles, 2);

        // A bad file disturbs nothing: the database stays, and no other
        // file appears.
        let mut damaged = std::fs::read(&file).unwrap();
        let at = damaged.len() / 2;
        damaged[at] ^= 1;
        let bad = dir.path().join("damaged.backup");
        std::fs::write(&bad, &damaged).unwrap();
        let err = restore(&second, &bad, true, 103).unwrap_err();
        assert!(format!("{err:#}").contains("checksum"), "{err:#}");
        assert!(database_path(&second).exists());
        assert!(!second.join("relay.redb.before-restore-103").exists());
    }

    #[test]
    fn a_running_relay_holds_its_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = database_path(dir.path());
        let running = Store::open(&path).unwrap();
        let file = dir.path().join("relay.backup");
        let err = offline(dir.path(), &file, 1).unwrap_err();
        assert!(err.to_string().contains("running"), "{err}");
        assert!(!file.exists());
        drop(running);
        offline(dir.path(), &file, 1).unwrap();
        let running = Store::open(&path).unwrap();
        let err = restore(dir.path(), &file, true, 5).unwrap_err();
        assert!(err.to_string().contains("running"), "{err}");
        drop(running);
        assert!(path.exists());
        restore(dir.path(), &file, true, 5).unwrap();
    }
}
