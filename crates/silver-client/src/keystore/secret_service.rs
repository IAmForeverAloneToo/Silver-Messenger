//! The Secret Service (`org.freedesktop.secrets`) on the session bus: GNOME
//! Keyring, KWallet, KeePassXC. A client of the few calls the key store
//! needs, rather than a general one.
//!
//! Entries are filed the way keyring 3 filed them, so a data directory an
//! earlier client protected still opens: an item in the default collection
//! with the attributes `service`, `username` and `target` (always
//! `default`), found by those three.
//!
//! The secret never crosses the bus in the clear. Every call opens a
//! session under `dh-ietf1024-sha256-aes128-cbc-pkcs7`, the encrypted
//! algorithm of the specification and the one keyring 3 used: a
//! Diffie-Hellman in the 1024-bit group of RFC 2409, HKDF-SHA256 over the
//! shared value to an AES-128 key, and each secret in CBC mode under a
//! fresh IV. That protects it from something watching the bus, not from a
//! program running as you, which can ask the service itself
//! (docs/THREAT_MODEL.md, "Program running as you").

use std::collections::HashMap;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{Context, anyhow, bail};
use futures_util::StreamExt;
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Proxy, Variant};
use zeroize::{Zeroize, Zeroizing};

use super::SERVICE;

const DESTINATION: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const PROMPT_INTERFACE: &str = "org.freedesktop.Secret.Prompt";
const ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
const CONTENT_TYPE: &str = "text/plain";
/// keyring 3's `target` attribute, and the alias of the collection new
/// items go into.
const TARGET: &str = "default";
/// The object path that means "none": no prompt needed, no collection.
const NONE: &str = "/";

/// RFC 2409 section 6.2, the Second Oakley Group: the prime the algorithm
/// names, with generator 2.
const PRIME: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF",
);
const PRIME_BYTES: usize = 128;

type Encryptor = cbc::Encryptor<aes::Aes128>;
type Decryptor = cbc::Decryptor<aes::Aes128>;

/// A secret as the service passes it, `(oayays)`: the session, the IV,
/// the encrypted value and its content type.
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// Whether the service answers: a bus, a service on it, and a session.
pub fn probe() -> anyhow::Result<()> {
    zbus::block_on(async {
        let session = Session::open().await?;
        session.find("probe").await?;
        // A service that answers but has nowhere to keep a new key is no
        // use for protecting a directory: see `collection_for_new`. Under
        // WSL that is the usual state.
        if session.default_collection().await?.is_some() || session.has_no_collections().await? {
            Ok(())
        } else {
            bail!("the key store has no default collection")
        }
    })
}

/// The text kept under `name`, if there is an entry.
pub fn get(name: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
    zbus::block_on(async {
        let session = Session::open().await?;
        let Some(item) = session.find(name).await? else {
            return Ok(None);
        };
        session.unlock_if(&item).await?;
        let secret: Secret = session
            .proxy(&item.path, ITEM_INTERFACE)
            .await?
            .call("GetSecret", &(&session.path,))
            .await
            .context("reading the key store entry")?;
        let mut plain = session.decrypt(secret)?;
        match String::from_utf8(std::mem::take(&mut *plain)) {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(e) => {
                e.into_bytes().zeroize();
                bail!("the key store entry is not text")
            }
        }
    })
}

/// Keep `text` under `name`, replacing what was there.
pub fn set(name: &str, text: &str) -> anyhow::Result<()> {
    // A prompt (making the first wallet, unlocking one) waits for a
    // person; one nobody answers, or that never shows, is given up on
    // rather than waited for until the program is killed.
    let (name, text) = (name.to_owned(), Zeroizing::new(text.to_owned()));
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("key store".into())
        .spawn(move || {
            let _ = done.send(set_now(&name, &text));
        })
        .context("starting the key store call")?;
    outcome.recv_timeout(PROMPT_WAIT).unwrap_or_else(|_| {
        bail!(
            "the key store did not answer within {} minutes",
            PROMPT_WAIT.as_secs() / 60
        )
    })
}

/// How long a prompt may wait for its answer.
const PROMPT_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

fn set_now(name: &str, text: &str) -> anyhow::Result<()> {
    zbus::block_on(async {
        let session = Session::open().await?;
        if let Some(item) = session.find(name).await? {
            session.unlock_if(&item).await?;
            let () = session
                .proxy(&item.path, ITEM_INTERFACE)
                .await?
                .call("SetSecret", &(session.encrypt(text.as_bytes()),))
                .await
                .context("writing the key store entry")?;
            return Ok(());
        }
        let collection = session.collection_for_new().await?;
        session.unlock(&collection).await?;
        let attributes = attributes(name);
        let label = format!("{name}@{SERVICE}:{TARGET}");
        let properties = HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label",
                Variant::from(label.as_str()),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Variant::from(attributes),
            ),
        ]);
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = session
            .proxy(&collection, COLLECTION_INTERFACE)
            .await?
            .call(
                "CreateItem",
                &(properties, session.encrypt(text.as_bytes()), true),
            )
            .await
            .context("creating the key store entry")?;
        session.prompt(&prompt).await.map(|_| ())
    })
}

/// Remove the entry under `name`; a missing one is fine.
pub fn remove(name: &str) -> anyhow::Result<()> {
    zbus::block_on(async {
        let session = Session::open().await?;
        let Some(item) = session.find(name).await? else {
            return Ok(());
        };
        session.unlock_if(&item).await?;
        let prompt: OwnedObjectPath = session
            .proxy(&item.path, ITEM_INTERFACE)
            .await?
            .call("Delete", &())
            .await
            .context("removing the key store entry")?;
        session.prompt(&prompt).await.map(|_| ())
    })
}

/// The attributes an entry is filed and found under, as keyring 3 had them.
fn attributes(name: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE), ("username", name), ("target", TARGET)])
}

/// An item that matched, and whether it has to be unlocked first.
struct Found {
    path: OwnedObjectPath,
    locked: bool,
}

/// One conversation with the service: a bus connection and an encrypted
/// session on it, which ends when the connection does.
struct Session {
    connection: Connection,
    service: Proxy<'static>,
    path: OwnedObjectPath,
    key: Zeroizing<[u8; 16]>,
}

impl Session {
    async fn open() -> anyhow::Result<Self> {
        let connection = Connection::session()
            .await
            .context("connecting to the session bus")?;
        let service = Proxy::new(&connection, DESTINATION, SERVICE_PATH, SERVICE_INTERFACE)
            .await
            .context("reaching the Secret Service")?;
        let prime = BigUint::parse_bytes(PRIME.as_bytes(), 16).expect("the prime is hexadecimal");
        // The private exponent, as wide as the group. num-bigint does not
        // clear its digits on drop; the exponent lives for this one call.
        let mut private = Zeroizing::new([0u8; PRIME_BYTES]);
        OsRng.fill_bytes(private.as_mut_slice());
        let exponent = BigUint::from_bytes_be(private.as_slice());
        let ours = BigUint::from(2u8).modpow(&exponent, &prime);
        let (output, path): (OwnedVariant, OwnedObjectPath) = service
            .call(
                "OpenSession",
                &(ALGORITHM, Variant::from(ours.to_bytes_be())),
            )
            .await
            .context("opening an encrypted session with the Secret Service")?;
        let theirs: Vec<u8> = output
            .try_into()
            .map_err(|_| anyhow!("the Secret Service's public key is not a byte string"))?;
        let theirs = BigUint::from_bytes_be(&theirs);
        // 1 and p - 1 are the small subgroup; 0 and p and up are not in the
        // group at all. Any of them would make the shared value guessable.
        if theirs <= BigUint::from(1u8) || theirs >= &prime - 1u8 {
            bail!("the Secret Service's public key is not in the group");
        }
        let shared = Zeroizing::new(theirs.modpow(&exponent, &prime).to_bytes_be());
        let mut input = Zeroizing::new([0u8; PRIME_BYTES]);
        input[PRIME_BYTES - shared.len()..].copy_from_slice(&shared);
        let mut key = Zeroizing::new([0u8; 16]);
        Hkdf::<Sha256>::new(None, input.as_slice())
            .expand(&[], key.as_mut_slice())
            .expect("16 bytes is a valid HKDF-SHA256 output");
        Ok(Self {
            connection,
            service,
            path,
            key,
        })
    }

    async fn proxy<'p>(
        &self,
        path: &'p OwnedObjectPath,
        interface: &'static str,
    ) -> anyhow::Result<Proxy<'p>> {
        Proxy::new(&self.connection, DESTINATION, path.as_ref(), interface)
            .await
            .context("reaching the key store entry")
    }

    /// The collection new entries go in: the one the `default` alias
    /// names, which a service need not have.
    async fn default_collection(&self) -> anyhow::Result<Option<OwnedObjectPath>> {
        let collection: OwnedObjectPath = self
            .service
            .call("ReadAlias", &(TARGET,))
            .await
            .context("finding the key store's default collection")?;
        Ok((collection.as_str() != NONE).then_some(collection))
    }

    /// Whether the service has no collection at all: one that starts
    /// empty, as KWallet does before its first wallet, makes the default
    /// collection when asked to, with a dialog of its own.
    async fn has_no_collections(&self) -> anyhow::Result<bool> {
        let collections: Vec<OwnedObjectPath> = self
            .service
            .get_property("Collections")
            .await
            .context("listing the key store's collections")?;
        Ok(collections.is_empty())
    }

    /// Where a new entry goes: the default collection, made first on a
    /// service that has none at all. One that has collections but no
    /// default (GNOME Keyring with only its in-memory `session`, as under
    /// WSL) is refused: making one there asks for a password nobody may
    /// be there to give.
    async fn collection_for_new(&self) -> anyhow::Result<OwnedObjectPath> {
        if let Some(collection) = self.default_collection().await? {
            return Ok(collection);
        }
        if !self.has_no_collections().await? {
            bail!("the key store has no default collection");
        }
        let properties = HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            Variant::from("Default keyring"),
        )]);
        let (made, prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .service
            .call("CreateCollection", &(properties, TARGET))
            .await
            .context("making the key store's default collection")?;
        if made.as_str() != NONE {
            return Ok(made);
        }
        let result = self
            .prompt(&prompt)
            .await?
            .context("the key store made no collection")?;
        OwnedObjectPath::try_from(result)
            .map_err(|_| anyhow!("the key store made something other than a collection"))
    }

    /// The one item filed under `name`. More than one is refused rather
    /// than one picked, as keyring 3 refused it.
    async fn find(&self, name: &str) -> anyhow::Result<Option<Found>> {
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .service
            .call("SearchItems", &(attributes(name),))
            .await
            .context("searching the key store")?;
        let found = unlocked
            .into_iter()
            .map(|path| Found {
                path,
                locked: false,
            })
            .chain(locked.into_iter().map(|path| Found { path, locked: true }));
        let mut found: Vec<Found> = found.collect();
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            n => bail!(
                "the key store has {n} entries for {name} under {SERVICE}; remove all but one"
            ),
        }
    }

    async fn unlock_if(&self, item: &Found) -> anyhow::Result<()> {
        if item.locked {
            self.unlock(&item.path).await?;
        }
        Ok(())
    }

    /// Unlock an item or a collection, asking the person if the service
    /// wants to; unlocking what is open already is a no-op.
    async fn unlock(&self, path: &OwnedObjectPath) -> anyhow::Result<()> {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = self
            .service
            .call("Unlock", &(vec![path],))
            .await
            .context("unlocking the key store")?;
        self.prompt(&prompt).await.map(|_| ())
    }

    /// Show a prompt the service handed back, if it handed one back, and
    /// wait for the person to answer it.
    async fn prompt(&self, path: &OwnedObjectPath) -> anyhow::Result<Option<OwnedVariant>> {
        if path.as_str() == NONE {
            return Ok(None);
        }
        let prompt = self.proxy(path, PROMPT_INTERFACE).await?;
        // Listening before asking, so the answer cannot come first.
        let mut completed = prompt
            .receive_signal("Completed")
            .await
            .context("waiting for the key store's prompt")?;
        let () = prompt
            .call("Prompt", &("",))
            .await
            .context("showing the key store's prompt")?;
        let message = completed
            .next()
            .await
            .context("the key store's prompt went away")?;
        let (dismissed, result): (bool, OwnedVariant) = message
            .body()
            .deserialize()
            .context("the key store's prompt answered with something else")?;
        if dismissed {
            bail!("the key store's prompt was dismissed");
        }
        Ok(Some(result))
    }

    fn encrypt(&self, plain: &[u8]) -> Secret {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let value = Encryptor::new((&*self.key).into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        (
            self.path.clone(),
            iv.to_vec(),
            value,
            CONTENT_TYPE.to_owned(),
        )
    }

    fn decrypt(&self, secret: Secret) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let (_, iv, value, _) = secret;
        let iv: [u8; 16] = iv
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("the key store entry came with no IV"))?;
        Decryptor::new((&*self.key).into(), (&iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&value)
            .map(Zeroizing::new)
            .map_err(|_| anyhow!("the key store entry does not decrypt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prime is the one RFC 2409 prints: 1024 bits, both ends all ones.
    #[test]
    fn the_prime_is_the_second_oakley_group() {
        let prime = BigUint::parse_bytes(PRIME.as_bytes(), 16).unwrap();
        assert_eq!(prime.bits(), 1024);
        assert_eq!(prime.to_bytes_be().len(), PRIME_BYTES);
        let bytes = prime.to_bytes_be();
        assert!(bytes[..8].iter().all(|&b| b == 0xFF));
        assert!(bytes[PRIME_BYTES - 8..].iter().all(|&b| b == 0xFF));
    }
}
