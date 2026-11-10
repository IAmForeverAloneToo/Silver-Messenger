# Design note: unlocking with a security key

Roadmap item 67. Written before the code, as the record of the decisions;
what ships is described in README.md and docs/THREAT_MODEL.md when the
code lands. Where this note and the code later disagree, the code wins
and this note is corrected.

What this is about: the data directory is encrypted at rest under a data
key, and today that key is unlocked by a passphrase or by a key kept in
the operating system's key store. This adds a third way, a FIDO2
security key (a YubiKey, or any key with the `hmac-secret` extension):
the key is touched and its PIN typed, and the directory opens. It is
not about the identity key (item 64): nothing here leaves the computer,
nothing on the wire changes, and a peer cannot tell.

## 1. Decisions

**The secret comes from `hmac-secret`.** A FIDO2 credential with the
`hmac-secret` extension turns a 32-byte salt into a 32-byte output that
only the key can compute, and only with a touch. The client registers a
credential once, keeps its id and a salt in `vault.json`, and at each
unlock asks the key for the output, which wraps the data key the way a
stretched passphrase does today. The salt is passed the way WebAuthn's
`prf` extension passes it (SHA-256 of `"WebAuthn PRF" || 0x00 || salt`),
so that a credential gives the same output whichever route reaches the
key: directly over USB, or through Windows 11's own API, which only
speaks `prf`. Tested (section 9) on the owner's YubiKey Security Key C
NFC, firmware 5.8: a stable 32-byte output, the same salt giving the same
output on a fresh run, a different salt a different one, and the same
credential giving the same output under Linux and under Windows.

**Touch and PIN, every time.** The credential is made with
`credProtect` level 3 (user verification required) and every unlock asks
for user verification, so the output comes only after the key's FIDO2
PIN. CTAP2 keeps two secrets per credential, one for an unlock with user
verification and one without, so this is decided when the key is
enrolled and cannot be changed afterwards without enrolling it again.
The point: a stolen laptop with the key still in it does not open; the
thief needs the PIN too, and the key locks itself after eight wrong
ones. A key with no PIN set is asked to set one at enrollment (the key
does that itself, through the client) rather than refused.

**Never without a way back.** Losing the only key would lose the
directory, so enrolling a key requires a recovery passphrase, and a
second key can be enrolled as well; either key, or the passphrase, opens
the directory. The recovery passphrase is stretched with Argon2id as the
passphrase is today and is meant to be written down and put away, not
typed every day.

**The key store does not mix with it.** A directory protected by a
security key has no key-store slot: the key store opens the directory
with nobody present, which is exactly what the security key is there to
prevent. Choosing a security key replaces key-store protection; going
back to it means removing every security key.

**Windows 10: a small elevated helper.** Windows 10's own security key
API (version 2, as on build 19045) passes `hmac-secret` through on
neither registration nor assertion, and Windows hides FIDO devices from
any process that is not elevated. So on Windows 10 a separate program,
`silver-key.exe`, does the one thing that needs the key: it is started
elevated (one UAC prompt), talks CTAP2 to the key over USB, asks for the
PIN in its own window, hands the 32-byte output back to the client, and
exits. The client itself never runs elevated; the elevated code is a few
hundred lines that parse nothing from the network or from the data
directory (section 5). Windows 11 needs none of this: its API speaks
`prf` and asks for the PIN in its own dialog. Linux and macOS talk to the
key directly; Linux needs the key's udev rule, which libfido2's packages
install.

## 2. Goals and non-goals

Goals:

* A data directory that a stolen or seized computer does not open, even
  with the security key taken with it, without the key's PIN.
* One key that opens the same directory on every system the owner uses
  it on: Linux, macOS, Windows 11, Windows 10 with the helper.
* No way to lock oneself out by losing one key.

Non-goals:

* Keeping the identity key on the security key. That is item 64, and
  most keys cannot hold an Ed25519 key in a way that signs for us.
* Protection while the directory is unlocked. The data key is in memory
  then, as it is with a passphrase; malware running as the user reads it
  either way (docs/THREAT_MODEL.md, "Program running as you"). `/lock`
  and the idle lock forget it; unlocking again asks for the key again.
* Smart-card (PIV) or YubiKey challenge-response slots. Both would work
  on Windows 10 without elevation, but neither is on every key: the
  owner's key, a Security Key C NFC, has FIDO2 alone. One mechanism,
  FIDO2, on every key that has it.
* Discoverable (resident) credentials. The credential id is kept in
  `vault.json`; nothing is stored on the key, and no slot on it is used.

## 3. On disk

`vault.json` today holds one wrapping of the data key and the naming key
under one key-encryption key, described by `kdf`. A directory with a
security key has several ways in, so the file gains a list of slots, each
wrapping the same data key and naming key under its own key-encryption
key:

```json
{
  "version": 2,
  "slots": [
    { "kind": "fido2", "credential_id": "<base64url>", "salt": "<32 bytes>",
      "rp_id": "silver-messenger.local", "label": "YubiKey",
      "wrapped_key": "...", "wrapped_naming_key": "..." },
    { "kind": "fido2", "credential_id": "...", "salt": "...", "rp_id": "...",
      "label": "backup YubiKey", "wrapped_key": "...", "wrapped_naming_key": "..." },
    { "kind": "passphrase", "kdf": { "algorithm": "argon2id", ... },
      "label": "recovery", "wrapped_key": "...", "wrapped_naming_key": "..." }
  ],
  "previous_key": "...",
  "state_generation": 12
}
```

* **A slot's key-encryption key** is HKDF-SHA256 over the key's output,
  with the slot's credential id and salt in the info, so that a slot's
  wrapping cannot be moved to another slot and still open. The wrap
  itself is the one used today (XChaCha20-Poly1305 with the vault's
  associated data).
* **The salt is fresh for every slot** and changes whenever the slot is
  rewrapped, so an output seen once (in memory, by malware, while
  unlocked) is useless against the next version of the file.
* **The credential id is in the clear,** as the Argon2 salt is today: it
  is meaningless without the key, which encrypts its own state into it.
* **`rp_id`** is one fixed string for the program, the same on every
  system and in every directory: a credential answers only under the
  `rp_id` it was made with, so one key opening the same directory on two
  systems needs the same one on both. It is what the key shows in its
  credential list and what Windows 11's dialog names.
* **Version 1 stays for directories without a security key.** A
  directory protected by a passphrase or by the key store keeps today's
  file exactly, so nothing changes for anyone who does not enroll a key.
  A version 2 file is refused by 0.21.0 and older with the message they
  already give for a format they do not know; the changelog's Upgrading
  paragraph says that a directory with a security key needs this
  version or later on every device that opens it. Removing the last
  security key brings the file back to version 1.

Rollback binding (format-changes.md, section 5) is unchanged:
`state_generation` stays in `vault.json`, and the files are encrypted
under the data key as before. A slot added or removed is a write of
`vault.json` like any other.

## 4. Enrolling, unlocking, removing

**Enrolling** (`silver --add-security-key`, or the same from the first
run's question about protection):

1. The directory is opened as it is now (passphrase, key store or
   nothing).
2. The client finds the key and checks it: CTAP 2.0 or later,
   `hmac-secret` and `credProtect` in its extensions. A key without them
   is refused with that reason.
3. If the key has no PIN, the client asks for one twice and sets it
   through the key's own `clientPin` command; it never sees the key's
   PIN otherwise.
4. The credential is registered (touch, PIN), a salt drawn, the output
   fetched (touch), and a slot written.
5. On the first key, the recovery passphrase is asked for twice and
   becomes a passphrase slot; a key-store slot, if there was one, goes.
   The client then offers to enroll a second key straight away.

Adding a slot needs only the data key, which is in memory once the
directory is open; nothing is rewritten but `vault.json`.

**Unlocking.** At start and after `/lock`: "Touch your security key
(Enter for the recovery passphrase)". The client tries each fido2 slot's
credential against the key that is plugged in (the key answers only for
its own), asks for the PIN, then for the touch. Wrong PINs are counted
by the key, and the client shows what the key reports ("3 tries left");
at zero the key blocks itself and only the recovery passphrase or the
other key opens the directory. No key and Enter: the recovery passphrase.

**Removing** (`silver --remove-security-key <label>`, for a key lost,
stolen or retired): the slot goes and the directory moves to a fresh
data key, as setting or dropping a passphrase does today, so that an old
copy of `vault.json` and the removed key together no longer open what is
written afterwards. Rewrapping the new data key under every remaining
slot needs each of them once: the other key's touch and PIN, the
recovery passphrase. A slot whose owner cannot present it (the
passphrase forgotten, the other key gone too) can be dropped in the same
step, after a confirmation that names what is left. Removing the last
key leaves the recovery passphrase as an ordinary passphrase, version 1.

**Changing the recovery passphrase** works as `--set-passphrase` does
now, on the passphrase slot alone.

## 5. Windows 10: the helper

`silver-key.exe` ships beside `silver.exe` in the Windows release, built
from the same workspace (a small binary crate of its own), and is used
only where the client finds Windows' API too old for `prf` (API version
below 4) and no other route. When it is needed:

1. The client creates a named pipe with a random name, an ACL that
   admits the current user alone, and one instance; then starts
   `silver-key.exe` elevated (`ShellExecuteEx` with `runas`), passing the
   pipe name, the credential ids and the salts on the command line. They
   are not secret.
2. Windows shows its UAC prompt, naming the helper. Until the Windows
   binaries are signed (item 53) the prompt says "Unknown publisher", as
   it would for any unsigned program; the release's checksums and
   signature are what vouch for it meanwhile.
3. The helper opens its own console, finds the key, asks for the PIN
   there, asks for the touch, computes the output and writes it to the
   pipe, then exits. It reads nothing else: not the data directory, not
   the network, not the client's configuration.
4. The client checks that the process at the other end of the pipe is
   the one it started (`GetNamedPipeClientProcessId` against the process
   handle `ShellExecuteEx` returned) before reading anything, and reads
   exactly one fixed-size answer.

The cost is a UAC prompt at every unlock on Windows 10, on top of touch
and PIN. Windows 10 is past the end of its support; this exists so the
owner's machine works today, and goes when Windows 10 does.

## 6. What it protects, and what it does not

* **A powered-off or locked computer, stolen with or without the key:**
  protected; the directory needs the key, its PIN, and its touch, or the
  recovery passphrase.
* **The key stolen alone:** protected; it opens nothing without the
  directory, and nothing at all without the PIN.
* **Malware running as the user while the directory is unlocked:** not
  protected, as with any other unlock (section 2).
* **Malware running as the user while the directory is locked:** it can
  wait for the next unlock and read the data key from memory then, as it
  can with a passphrase; the touch requirement means it cannot quietly
  ask the key on its own, because nobody touches it. On Windows 10 it
  could start the helper itself and hope the owner approves a UAC prompt
  that came from nowhere, and then touches the key and types the PIN in
  a window nobody asked for; each of those is a warning.
* **The recovery passphrase:** as strong as the passphrase is, which is
  why it is stretched with today's Argon2id parameters and is not meant
  for daily use.

docs/THREAT_MODEL.md gains a paragraph on this when the code lands.

## 7. What it is built with

* **Directly over USB (Linux, macOS, Windows 10's helper):** a CTAP2
  client of our own, the crate `silver-key`, in the manner of the Secret
  Service client: CBOR, CTAPHID, PIN protocols 1 and 2,
  `authenticatorMakeCredential` with `hmac-secret` and `credProtect`, and
  `authenticatorGetAssertion` with `hmac-secret`, in about 1,500
  lines that can be read in a sitting. It adds no crate to the tree: the
  P-256 arithmetic is the `p256` OpenMLS already builds, and AES-CBC,
  HMAC and HKDF are the client's. The crates there were (`ctap-hid-fido2`,
  Mozilla's `authenticator`) each bring a CBOR library, a HID library
  and a second generation of the cryptography crates, for far more than
  the two commands used here. On Linux the key is `/dev/hidraw*`, found
  by the FIDO usage page in its report descriptor, with no `hidapi`;
  Windows 10's helper gets its own HID transport in step 5, and macOS
  one when there is a Mac to try it on.
* **Windows 11:** `webauthn.dll` through the `windows` crate, with the
  `prf` extension.
* **Tests:** a software authenticator in the test suite, which answers
  CTAP2 with `hmac-secret` from a fixed seed, so that enrolling,
  unlocking, removing and the version 2 file are tested in CI on every
  platform. Fixtures in `tests/compat.rs` pin a version 2 directory as
  soon as one exists. A real key is tried by hand before each release
  that touches this, on Linux and on Windows.

## 8. Order

1. The CTAP2 client and the software authenticator, with tests.
2. The version 2 vault: slots, the passphrase slot, reading version 1
   unchanged, fixtures.
3. Enrolling, unlocking, removing; the unlock prompt in the terminal.
4. Windows 11 through `webauthn.dll`.
5. The Windows 10 helper.
6. README, THREAT_MODEL.md, UPGRADING.md, the changelog.

## 9. What was tested before this was written

On the owner's Windows 10 computer (build 19045, WebAuthn API version 2),
YubiKey Security Key C NFC, firmware 5.8, with a test script on Yubico's
python-fido2 2.2.1 using the `prf` extension and a throwaway,
non-discoverable credential:

* Windows' own API: registration succeeds, but `hmac-secret` is
  ignored, and no output comes back on assertion.
* Directly over USB, not elevated: the key is not listed at all.
* Directly over USB, elevated: a stable 32-byte output; same salt same
  output, different salt different output; the same on a fresh run.
* WSL 2 (kernel 6.18), the key attached with usbipd-win, directly over
  USB: the same.
* The credential made under WSL, read from Windows elevated: the same
  output, so one credential opens the same directory on both.
* The key reports FIDO 2.1 (and later), with `hmac-secret`, `credProtect`
  and `clientPin` (a PIN set). The runs used no user verification; the
  credential the client makes will require it (section 1).

Not yet tried: Windows 11's API with `prf`, and macOS.

## 10. Corrections

Where the code, once written, differs from what is above:

* **The previous data key in a version 2 vault** (section 3) is wrapped
  under the current data key, not under a slot's key-encryption key:
  with several slots there is no one key-encryption key to wrap it
  under, and under the data key every slot reaches it.
* **Changing the recovery passphrase** (section 4) moves the directory to
  a fresh data key and wraps it under every slot again, as removing a key
  does, rather than rewrapping the passphrase slot alone; otherwise an
  old `vault.json` and the old passphrase would go on opening what is
  written afterwards. It is `--set-passphrase` on a directory a security
  key protects, and asks for the current recovery passphrase and each
  key once.
* **Each key is asked for its own salt.** An unlock with two keys
  enrolled cannot pass one salt for both, since each slot has its own:
  the client gets one PIN token and asks for each credential in turn,
  and the key answers, after its touch, only for the one it holds.
* **The helper's request and answer** (section 5) are in
  `crates/silver-key/src/helper_wire.rs`: the request is the command
  line, hex only, refused if it holds anything the client would not
  write; the answer is 1,063 bytes (a status, the index, the secret, and
  for an enrollment the credential id). Windows 10's route is chosen by
  `webauthn.dll`'s API version: below 4, the helper.
* **macOS** has no route yet (section 7 named it with Linux): it needs an
  IOKit HID transport, which waits for a Mac to try it on, as section 9
  said of macOS before. `--add-security-key` says so there.
* **The unlock prompt** is the terminal's, before the interface opens:
  the client asks for the PIN, then for the touch, and an empty PIN or
  `r` at "no key found" goes to the recovery passphrase. With
  `SILVER_PASSPHRASE` set, the recovery passphrase is used and the key is
  not asked for, since a run nobody sits at has nobody to touch it.
* **One executable.** The Windows 10 helper is not a second program
  (`silver-key.exe`, as section 5 had it and 0.22.0 shipped) but
  `silver.exe` itself, started elevated with `--security-key-helper` as
  its first argument, which it checks before anything else runs and in
  which nothing else runs. A download is one file, `silver update`
  replaces all of it, and the UAC prompt names the program the person
  knows. What the elevated process holds is the whole binary rather than
  a small one, though only the helper's code runs in it.

