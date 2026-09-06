---
title: Silver Messenger Security and Privacy Audit
subtitle: Adversarial source review of the protocol, relay, client, terminal client, deployment and supply chain
Subject: IAmForeverAloneToo/Silver-Messenger (Rust workspace: silver-protocol, silver-relay, silver-client, silver-tui)
Version audited: 0.10.0 line, branch main
Commit: 05e1168 ("Terminal tests: the layout test waits for the answer to be sent")
Date: 6 September 2026
Prepared by: Independent adversarial audit (read-only; no changes were made to the repository)
Classification: Confidential to the maintainer until fixes ship, per SECURITY.md coordinated disclosure
Methodology: White-box source review against docs/PROTOCOL.md and docs/THREAT_MODEL.md; OWASP ASVS 4.0.3 L2 used as a checklist; severity aligned with CVSS v3.1 qualitative bands (Appendix A)
Note: Every finding quotes the file and line of the audited commit. Findings were verified by reading the code, and in one case by measurement (Appendix D); none was tested against a live relay. Line numbers refer to commit 05e1168.
---
# 1. Executive summary

Silver Messenger is a terminal end-to-end-encrypted messenger with a self-hosted relay. It uses a sealed-sender envelope over a PQXDH handshake and a Double Ratchet with ML-KEM steps for one-to-one messages, MLS on a hybrid post-quantum ciphersuite for groups, a hash-chained key-transparency log, multi-device with certified device keys, and encryption at rest under an OS-key-store- or passphrase-wrapped data key. The project ships a detailed protocol specification, a threat model, an OWASP ASVS Level 2 self-assessment, Verifpal models, known-answer vectors, fuzz targets, reproducible builds and provenance attestations. This audit set out to test those claims adversarially, component by component, from the source.

**The cryptographic core is sound.** Every construction in `silver-protocol` was traced against the specification and against standard attack classes; the key derivations, associated data, domain separation, contributory checks, signature strictness and ratchet state handling are correct and match the published vectors. No way was found for a relay, a network observer or a stranger to read message content or forge a message from another identity. The at-rest design, the file-name sanitiser, the proxy handling and the terminal output filtering are also well built.

**The serious findings are at the trust boundaries around that core**, where the implementation trusts a signed statement one step further than it should, lets a relay withdraw a protection silently, or lacks a bound that a hostile party can exploit. Seventy-six findings are reported: 1 Critical, 10 High, 24 Medium, 30 Low and 11 Informational.

The findings that most need attention:

- **SM-R-01 (Critical).** Any registered identity can permanently destroy any other identity's account on a relay: it publishes a device list that names the victim's id as its own device, then revokes it. The relay wipes the victim's mailbox and prekeys and refuses every future login and publish, with no way to undo it; because the resulting statement is logged under the victim's subject and clients act on device revocations by device id alone (SM-P-01, High), the victim's contacts also drop their sessions with the victim. The specification names this exact attack as the reason for a check that turns out to be insufficient.
- **SM-R-02 / SM-C-04 (High / Medium).** The host-bound relay login, introduced so a relay in the middle cannot replay a login to another relay, verifies the signed host against the connection's own `Host` header, which the attacker chooses; and the client falls back to the unbound login whenever a relay omits the `bound` flag. A hostile relay can therefore authenticate as its users at the real relay and read, acknowledge and delete their queued mail.
- **SM-C-01 (High).** TLS key pinning accepts a pin match on *any* certificate the server presents, so a TLS-inspecting proxy with a locally trusted certificate defeats the pin by appending the relay's public certificate to its chain. This is the precise adversary the threat model says pins stop.
- **SM-C-02 (High).** Adding protection to an existing data directory re-encrypts ten files but not the MLS group secrets or the revocation certificate, which stay in plaintext; removing protection makes them permanently unreadable.
- **SM-P-02 (High).** User and group ids are base58-decoded with a quadratic algorithm before any length check, inside frame parsing, before authentication or rate limiting. One 128 KiB frame costs the relay about 4.5 seconds of CPU (measured); a single address can saturate a small relay.
- **SM-R-03 to SM-R-05 (High).** Connections are neither timed out nor counted before the WebSocket upgrade; envelopes are stored for recipients that do not exist with no global cap; and `publish` has no rate limit, so one connection can grow the append-only transparency log without bound while starving every other writer.
- **SM-G-01 / SM-G-02 (High).** A group member can make every other member download 16 MiB per envelope and hold 256 MiB of unauthenticated bytes that are rewritten to disk on every group event; and a newly linked device accepts a Welcome for a group the primary named from anyone who declares themselves admin, after which the genuine Welcome is refused.

A second cluster of Medium findings concerns **silent downgrades by a hostile relay**: v1 bodies are still sent when a relay strips a peer's prekeys (the specification says 0.10.0 refuses); transparency checking is switched off per connection on the relay's word; a transparency refusal does not actually stop the send; and an inbound handshake is never compared with the pinned key, so a holder of the identity key impersonates without the promised loud warning. A third cluster concerns **resource bounds a hostile contact or member can exceed** on the client: session and prekey files, history rewrites and tombstones, invitation floods, unbounded leaves per identity, and admin actions the client performs automatically in a group whose admin list someone else wrote.

On the **supply chain**, the pipeline is stronger than most: pinned actions, read-only tokens, reproducible builds, attestations, SBOMs, and packaging pinned by checksum. The maintainer signature the threat model relies on does not yet exist, and its designed form (an unencrypted key in GitHub Secrets) would add no independence from the platform. The dependency tree has no known vulnerability; the two post-quantum crates carry "never independently audited" notices.

On **privacy**, the design delivers what it promises for content and hides senders from the relay in every body version. The gaps are in what the client leaks on disk (contact graph in file names, plaintext group secrets after protection is added, umask-mode files with proxy credentials in the no-key-store case), in one deanonymising command (`--check-release` ignores the remembered Tor proxy), and in downgrades the user cannot see (anonymous submission abandoned silently).

Almost every finding has a small, local fix, and the first ten items of the remediation plan in section 13 would close the Critical and every High. The project's documentation is precise enough that the discrepancies in section 12 read as a to-do list; correcting them is part of the fix, because users are trusting the threat model as written.
# 2. Scope, methodology and limitations

## 2.1 Scope

The audit covered everything the repository ships at commit `05e1168` (version 0.10.0 on the `main` line), namely:

| Component | Path | Lines (Rust) | What it is |
| --- | --- | --- | --- |
| `silver-protocol` | `crates/silver-protocol` | ~7,700 | Identities, sealed envelopes, X3DH/PQXDH handshake, Double Ratchet with ML-KEM steps, prekeys, bundles, device certificates, MLS group glue, transparency log, lifecycle statements, blob chunks, wire frames |
| `silver-relay` | `crates/silver-relay` | ~9,600 | The store-and-forward relay: WebSocket frame handler, redb store, rate limits, TLS termination with built-in ACME, admin socket, backups, Prometheus metrics |
| `silver-client` | `crates/silver-client` | ~17,900 | The client library: connections, sessions, storage and at-rest encryption, files, groups (OpenMLS), devices and linking, transparency checks, receipts, cover traffic, proxies, update check |
| `silver-tui` | `crates/silver-tui` | ~12,600 | The terminal client binary `silver`: UI, commands, terminal safety, notifications, clipboard, QR codes |
| Deployment | `deploy/` | — | Installer script, systemd units, Dockerfile, Compose file, alert rules |
| Packaging | `packaging/`, `HomebrewFormula/` | — | Debian package builder, AUR PKGBUILD, Homebrew formula, winget manifests |
| CI/CD | `.github/workflows/` | — | CI, release, deploy and Scorecard workflows |
| Formal models | `formal/` | — | Verifpal models of the handshake and ratchet |
| Documentation | `docs/`, `README.md`, `SECURITY.md` | — | Protocol specification, threat model, ASVS self-assessment, operating guide |
| Dependencies | `Cargo.lock`, `fuzz/Cargo.lock` | 619 crates | The full dependency tree of the workspace |

The reference relay at `test-silver.duckdns.org` was **not** tested: no traffic was sent to any live system, in keeping with the security policy's request not to load-test it and with the audit's read-only mandate.

## 2.2 Methodology

The audit was a white-box, adversarial source review. It combined:

- **Specification-driven review.** `docs/PROTOCOL.md` (2,079 lines) and `docs/THREAT_MODEL.md` were read in full first, and each claim was then traced to the code that is supposed to implement it. Where the specification and the code disagree, both are reported.
- **Line-by-line review of the cryptographic core** (`envelope.rs`, `session.rs`, `identity.rs`, `pq.rs`, `prekey.rs`, `bundle.rs`) by the lead auditor, checking every key derivation, associated-data construction, signature domain and contributory check against the specification and against known attack classes (key-compromise impersonation, unknown-key-share, canonicalisation ambiguity, downgrade, replay, nonce misuse).
- **Parallel component deep-dives** by seven reviewers with explicit attacker models per component (hostile relay, hostile contact, hostile group member, stranger with an id, device thief, local user, network attacker, supply-chain attacker), each required to quote the code that supports every finding.
- **Dependency analysis** with `cargo audit` 0.22 against the RustSec database (1,239 advisories), inspection of the fetched sources of security-relevant crates (`bs58`, `ml-kem`, `x-wing`, `rustls`, `axum-server`, `instant-acme`) to verify inherited defaults rather than assume them, and a review of the pinning and provenance chain from source to installed package.
- **Targeted experiments** where a finding's practical impact needed a number: a benchmark of the base58 decoder at the relay's frame size (Appendix D). No experiment touched a live system.
- **Framework.** Findings are organised by component and rated on the scale in Appendix A, which is aligned with CVSS v3.1 qualitative bands. The OWASP ASVS 4.0.3 Level 2 self-assessment shipped with the project was used as a checklist to confirm or challenge each control it marks "Met".

## 2.3 Limitations

- This is a source review, not a penetration test. Findings whose exploitation depends on runtime conditions (timing windows, platform behaviour) are marked accordingly.
- The cryptographic primitives themselves (Ed25519, X25519, ML-KEM-768, XChaCha20-Poly1305, HKDF, Argon2id, and the OpenMLS implementation of RFC 9420) were treated as correct. Where an implementation crate has not been independently audited, that is reported as a finding because it is a risk the project inherits.
- The Verifpal models were read and their claims cross-checked against the code; they were not re-run.
- No changes were made to the repository; every recommendation is advisory.
# 3. System overview and trust boundaries

## 3.1 Components

Silver Messenger is a Rust workspace of four crates and the material around them:

- **`silver-protocol`** holds every cryptographic construction and wire type: identities (Ed25519 identity key whose public half is the user id, plus an X25519 long-term key), signed key bundles with X25519 and ML-KEM-768 prekeys, the sealed-sender envelope, the X3DH/PQXDH handshake and the Double Ratchet (classical v2, post-quantum and deniable v4), MLS glue for groups (v5 bodies, leaf extensions, invite links, sequencer tokens), device certificates and revocations, lifecycle statements, the transparency log, encrypted blob chunks, and the relay frame types.
- **`silver-relay`** is a WebSocket store-and-forward server over a redb database. It authenticates identities by a signed challenge, stores bundles and prekeys, queues sealed envelopes per recipient, stores encrypted blob chunks, keeps MLS key packages on deposit, runs a per-group epoch sequencer, appends every served key change to a hash-chained log, terminates TLS with a built-in ACME client, and exposes a Unix-socket admin interface and an optional Prometheus listener.
- **`silver-client`** is the client library: connection management (an authenticated connection and an anonymous submission connection, optionally through SOCKS5 or HTTP CONNECT), session and prekey management, storage with encryption at rest, files, groups on OpenMLS, devices and linking, transparency checking, receipts, cover traffic, and an opt-in release check.
- **`silver-tui`** is the terminal client `silver`, built on ratatui, with a screen-reader mode, notifications, clipboard, QR codes, and the command set.

## 3.2 Trust boundaries

| Boundary | Trusted for | Never trusted for |
| --- | --- | --- |
| Relay operator | Availability; metadata the threat model enumerates | Content, sender identity, forging or substituting keys |
| Network path | Nothing beyond TLS | Anything |
| Contact | What they send being from them | Anything about third parties; well-formed input |
| Group member | Group content they legitimately hold | Membership changes outside the rules; well-formed input |
| Own device | Everything, until revoked | — |
| Stranger with an id | Nothing | Anything |
| Local operating system | Everything (out of scope) | — |

The audit's findings are almost all located at these boundaries: statements from one party accepted as if they were from another (SM-R-01, SM-P-01, SM-G-02), a relay's word accepted for a security downgrade (SM-C-03 to SM-C-06, SM-R-02), or a bound that a hostile party at the boundary can exceed (SM-P-02, SM-R-03 to SM-R-06, SM-G-01, SM-G-05).

## 3.3 Cryptographic summary as implemented

| Layer | Construction | Verified |
| --- | --- | --- |
| Identity | Ed25519 (strict verification), user id = public key in base58 | Yes |
| Sealed envelope | X25519 ephemeral with the recipient's long-term key; HKDF-SHA256; XChaCha20-Poly1305; plaintext `sender || signature || body`; AAD `recipient || ephemeral`; signature omitted for v4/v5 | Yes |
| Handshake | X3DH (DH1–DH4) or PQXDH (plus ML-KEM-768 encapsulation to a signed key), HKDF with zero salt and versioned info | Yes |
| Ratchet | Signal Double Ratchet; v4 adds an ML-KEM-768 step per DH step; message keys expand to a 32-byte key and 24-byte nonce | Yes |
| Groups | OpenMLS 0.9 on `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (X-Wing HPKE), private messages only, ratchet tree in the Welcome | Yes |
| Transparency | SHA-256 hash chain of bundle and statement leaves with fixed-width layouts; client-side replay and gossip | Yes |
| Files | Per-file random key and nonce, 64 KiB chunks bound to blob id, index and count; SHA-256 over the plaintext | Yes |
| At rest (client) | Random 256-bit data key wrapped by the OS key store or Argon2id (64 MiB, 3 passes); XChaCha20-Poly1305 per file with the file name as AAD | Yes (with the gaps in SM-C-02, SM-C-24) |
| Relay TLS | rustls 1.2/1.3, AEAD suites, ACME TLS-ALPN-01, key reused across renewals | Yes |
| Relay login | Ed25519 signature over a 32-byte nonce, bound to the host name when both sides support it | Binding is verified incorrectly (SM-R-02) |

## 3.4 What the project already does well

The audit team wants to record, before the findings, that this codebase is considerably more careful than is typical for a project of its size. `unsafe` is forbidden in three crates and confined to one documented block in the fourth; every parser is a typed serde structure with size caps; every peer-facing parser has a fuzz target; the specification gives byte-exact layouts that the code, the vectors and the tests cross-check; the threat model states what each actor can do rather than what the project hopes; the ASVS self-assessment marks its own gaps; the relay runs under a hardened systemd unit as an unprivileged user; builds are reproducible and attested. Those properties made this audit more productive, not less: it was possible to test precise claims and report precise gaps.
# 4. Summary of findings

Seventy-six findings, ordered by severity within each component. Full detail, evidence and recommendations follow in sections 5 to 9; Appendix E gives the count by component.

## 4.1 Critical and High

| ID | Severity | Title | Component |
| --- | --- | --- | --- |
| SM-R-01 | Critical | Any registered identity can permanently destroy any other identity's account via a device list naming the victim plus `revoke_device` | Relay |
| SM-P-01 | High | Device revocation statements are not bound to the device's real account; clients drop sessions on any account's say-so | Protocol / client |
| SM-P-02 | High | Quadratic base58 decoding of unbounded ids before any check, pre-authentication (4.5 s CPU per 128 KiB frame) | Protocol / relay |
| SM-R-02 | High | Bound login verified against the connection's own `Host` header; hostile relay can replay logins | Relay |
| SM-R-03 | High | No timeout or accounting before the WebSocket upgrade; hyper's header timeout is inert | Relay |
| SM-R-04 | High | Envelopes stored for unregistered recipients; no global mailbox cap | Relay |
| SM-R-05 | High | `publish` unrated: unbounded transparency-log growth and fsync storm | Relay |
| SM-C-01 | High | TLS key pin matches any presented certificate, not the validated path | Client |
| SM-C-02 | High | Re-encryption skips `groups.json`, `groups.mls`, `revocation.json` | Client |
| SM-G-01 | High | A member forces 16 MiB downloads per envelope and 256 MiB of held unauthenticated bytes rewritten per event | Groups |
| SM-G-02 | High | Newly linked device accepts an "expected" group's Welcome from any self-declared admin; the real one is refused | Devices |

## 4.2 Medium

| ID | Title | Component |
| --- | --- | --- |
| SM-P-03 | Capability-list signature not injective; relay can strip signed capabilities by merging | Protocol |
| SM-P-04 | v4 makes the long-term DH key sufficient for impersonation; threat model understates it | Protocol |
| SM-P-05 | Inline MLS threshold exceeds what encodes; commit merged and sequencer moved before framing | Protocol / groups |
| SM-R-06 | `ack` unrated; each is a durable write on a runtime worker | Relay |
| SM-R-07 | Unbounded per-connection outbound queue pins memory | Relay |
| SM-R-08 | Anyone with a group id can seize an absent sequencer entry | Relay |
| SM-R-09 | `u64` epoch overflow panic reachable anonymously | Relay |
| SM-C-03 | v1 bodies still sent when a relay strips prekeys; spec says refused | Client |
| SM-C-04 | Host-bound login downgraded when the relay omits `bound` | Client |
| SM-C-05 | Transparency switched off per connection on the relay's word | Client |
| SM-C-06 | Transparency refusal does not stop the send; pinned bundle used | Client |
| SM-C-07 | Inbound handshake DH key never compared with the pin; silent impersonation by an identity-key holder | Client |
| SM-C-08 | Crash between re-encryption and vault write loses everything | Client |
| SM-C-09 | `--check-release` ignores the remembered proxy; deanonymises Tor users | Client |
| SM-C-10 | Data directory and most files at umask modes; plaintext fallback exposes config, contacts, history | Client |
| SM-C-11 | `/open` denylist incomplete; decrypted copy lacks mark-of-the-web | Client |
| SM-C-12 | Saved-file path parsed from message text; open/decrypt will decrypt store files | Terminal client |
| SM-G-03 | Honest leaves break the group (consumed proposal store, admin leaving) | Groups |
| SM-G-04 | Update-path leaf and Update proposals never validated | Groups |
| SM-G-05 | Invitation flood: unbounded persisted groups, reusable last-resort package, orphan state | Groups |
| SM-G-06 | Victim made admin of a crafted group performs admin actions automatically | Groups |
| SM-G-07 | Device link hijack by racing the primary; device confirms nothing | Devices |
| SM-G-08 | Leaves per identity unbounded on the tree | Groups |
| SM-S-01 | Releases unsigned; designed signing key lives unencrypted in GitHub Secrets | Supply chain |

## 4.3 Low

| ID | Title | Component |
| --- | --- | --- |
| SM-P-06 | Ratchet-header AAD lacks length prefixes; KEM field lengths unenforced at parse | Protocol |
| SM-P-07 | Device-list signature and leaf omit certificate content; rename reuses timestamp | Protocol |
| SM-P-08 | Group and device names admit invisible and bidi characters | Protocol |
| SM-P-09 | Group message ids have no character-set rule | Protocol |
| SM-R-10 | A revoked identity can still authenticate | Relay |
| SM-R-11 | IPv4-mapped IPv6 peers bypass loopback, proxy and ban checks | Relay |
| SM-R-12 | Attacker text written to the relay log; rejected sends log at line rate | Relay |
| SM-R-13 | Smaller relay items: tiny-chunk accounting, unvalidated envelope ids, admin socket window and no peer credentials, backup symlink following, `unban` id leak, ACME counter and directory pinning, unencrypted backups with the invite token, relay-side TLS resumption, metrics exposure, others | Relay |
| SM-C-13 | Unauthenticated sender hint rendered as a contact's name | Client |
| SM-C-14 | Strangers grow `sessions.json` without bound; whole-file rewrite per message | Client |
| SM-C-15 | Single `(epoch, seq)` state drops reordered messages; relay bloats prekey file | Client |
| SM-C-16 | Anonymous submission abandoned silently | Client |
| SM-C-17 | No client-side cap on relay frame or chunk sizes | Client |
| SM-C-18 | Forks and rewinds reported, not enforced; evidence discarded | Client |
| SM-C-19 | History files grow without bound and are rewritten per inbound deletion | Client |
| SM-C-20 | Peer text raw on four output paths: export, release check, clipboard, reader mode | Client / terminal |
| SM-C-21 | Unbounded Argon2 parameters from vault and backup files | Client |
| SM-C-22 | Passphrases not zeroised; environment passphrase re-opens the lock | Client / terminal |
| SM-C-23 | Data key not rotated on passphrase change | Client |
| SM-C-24 | No rollback binding for key files; history lines unbound to position | Client |
| SM-C-25 | Encrypted directory leaks contact graph and message lengths | Client |
| SM-C-26 | Note-prefix heuristic spoofable; multi-line paste executes commands without bracketed paste | Terminal client |
| SM-G-09 | Sequencer recovery documented but not wired | Groups |
| SM-G-10 | Unauthenticated Welcome wipes out-of-sync state before any check | Groups |
| SM-G-11 | Key-package deposit pushed over the relay cap | Groups |
| SM-G-12 | `receive()` persists only on success; memory and disk diverge | Groups |
| SM-S-02 | Toolchain unpinned; reproducibility decays | Supply chain |
| SM-S-03 | Installer: `curl | bash`, unverified rustup, plaintext default, third-party IP lookup, tokens in URLs | Deployment |
| SM-S-04 | Deploy workflow trusts the host key on first use every run | CI/CD |
| SM-S-05 | Container and CI images pinned by tag, not digest | Supply chain |

## 4.4 Informational

| ID | Title | Component |
| --- | --- | --- |
| SM-P-10 | Non-canonical Ed25519 encodings accepted as distinct ids | Protocol |
| SM-P-11 | Provisioning plaintext cap unreachable; revocation list unbounded | Protocol |
| SM-P-12 | `DeviceCertificate::encode` truncates long names silently | Protocol |
| SM-P-13 | Post-quantum crates carry "never independently audited" warnings | Dependencies |
| SM-P-14 | Envelope id and body `id` outside every AEAD (documented) | Protocol |
| SM-C-27 | Smaller client items: false fork after absence, `silver.log`, `observe_relay`, no instance lock, link relay string, reader-mode lock scrollback, relay error strings | Client / terminal |
| SM-G-13 | Sender ratchet default 5 vs documented 64; linked device pins bundles; invite link use unbounded | Groups |
| SM-S-06 | systemd hardening gaps | Deployment |
| SM-S-07 | Dependency audit: no vulnerabilities, one unmaintained build-time crate, duplicate versions | Dependencies |
| SM-S-08 | Fuzzing depth one minute per target per push | CI/CD |
| SM-S-09 | Release publishing details | CI/CD |
# 5. Findings: protocol and cryptography (`silver-protocol`)

The cryptographic core was reviewed line by line against `docs/PROTOCOL.md`. The constructions themselves are sound and match the specification: every X25519 output is checked for contributory behaviour, every signature is domain-separated with a NUL-terminated ASCII prefix and verified with `verify_strict`, the X3DH/PQXDH derivation, the root and chain KDFs, the per-message key expansion and the AEAD associated data all match the documented byte layouts, and the Double Ratchet advances state only after a successful trial decryption on a clone. The findings below are about the edges of the design: what the specification leaves unbound, what the parser accepts before it checks, and what the threat model claims that the protocol does not deliver.

## SM-P-01 Device revocation statements are not bound to the device's real account

**Severity:** High. Unauthenticated, one message, repeatable; causes loss of in-flight messages and suppression of a contact's device.

**Location:** `crates/silver-protocol/src/device.rs:159-170` (`DeviceRevocation::verify`), `crates/silver-client/src/connection.rs:3072-3084`, `docs/PROTOCOL.md` §14.2.

**Description.** A `DeviceRevocation` is `{account, device, created_at_ms, signature}` with the signature by `account` over the three fields. `verify()` proves only that *some* account signed a statement about *some* device id; nothing checks that `device` actually belongs to `account`. The specification says the statement "carries its own signature and is trusted however it arrived", and the client implements that literally:

```rust
Content::DeviceRevocation(revocation) => {
    if revocation.verify().is_err() { ...; return; }
    if let Some(sessions) = &setup.sessions
        && let Err(e) = lock(sessions).forget(&revocation.device) { ... }
    lock(&setup.device_bundles).remove(&revocation.device);
    let _ = ev_tx.send(ClientEvent::DeviceRevoked { revocation }).await;
}
```

This arm runs in `plain_received` before the contact/stranger/blocked triage, which happens only in the default arm. The relay-served path has the same gap: `connection.rs:961-966` filters `device_revocations` by `.device` only, and the transparency check (`tail.rs:432-437`) validates the leaf under the *device's* subject, which is exactly what a hostile relay controls.

**Attack.** Stranger S learns that victim V's contact A has a linked device D (device ids are public in A's bundle). S signs `DeviceRevocation { account: S, device: D }` with S's own key, which is valid because S ≠ D, seals it into a plain v1 body addressed to V and submits it anonymously. V's client drops every ratchet session with D, so any message D already sent under those sessions is lost as "could not read envelope", and V stops sealing to D until the next hourly device-list refresh. Repeated once a second this permanently severs D from V. Combined with SM-R-01, a hostile identity can have the relay serve such a statement on every lookup of V.

**Recommendation.** Make the binding explicit in the protocol: `DeviceRevocation::verify_for(account)` (or make `verify` take the expected account) and reword §14.2 to "valid for the account the recipient knows the device under". In the client, accept a revocation only when `revocation.account` equals the account whose signed device list contains `device`, or the `device_of` of D's pinned bundle. The `Sync::Devices` path already does this correctly (`devices.rs:309-332`) and is the model to follow. Add a test that a foreign-account revocation is ignored.

## SM-P-02 Quadratic base58 decoding of unbounded identifiers before any length check

**Severity:** High. Pre-authentication CPU exhaustion of the relay with a ~35,000:1 cost ratio; also usable by a hostile relay against clients.

**Location:** `crates/silver-protocol/src/identity.rs:75-81` (`UserId::from_str`), `crates/silver-protocol/src/group.rs:114-119` (`GroupId::from_str`), `crates/silver-relay/src/lib.rs:1890-1891` and `2292-2314` (`next_frame`).

**Description.** `UserId::from_str` calls `bs58::decode(s.trim()).into_vec()` and only afterwards checks that the result is 32 bytes. The `bs58` 0.5.1 decoder is the classic big-integer conversion: for every input character it multiplies the whole output accumulated so far by 58 (`decode.rs:415-429`), so the cost is quadratic in the input length. `UserId` is deserialised through serde on every frame field that carries an id (`ClientFrame::Auth.user_id`, `Lookup.user_id`, `KeyPackage.user_id`, `Envelope.to`, and on the client side `LookupResult.user_id` and `Deliver.envelope.to`). The relay accepts frames of up to 128 KiB (`max_message_size`) and parses the first frame of every connection into a `ClientFrame` before rate limiting, authentication or anything else (`next_frame` → `ClientFrame::decode`).

**Evidence.** The decoder was benchmarked in isolation (Appendix D):

| Input length (chars) | Decode time |
| --- | --- |
| 1,000 | 0.26 ms |
| 10,000 | 26 ms |
| 50,000 | 651 ms |
| 131,000 | 4.45 s |

A single WebSocket frame `{"type":"lookup","user_id":"zzzz…"}` of 128 KiB therefore costs the relay about 4.5 s of one core. Each address may hold 16 connections, and frames on different connections are parsed on different runtime workers, so one address saturates a small VPS with a few hundred kilobytes per second of traffic. Only valid base58 characters are needed (`z` = 57 maximises carry propagation).

**Recommendation.** Reject any candidate longer than 44 characters (a 32-byte key is 43 or 44 base58 characters) before decoding, in both `UserId::from_str` and `GroupId::from_str`. As defence in depth, give the relay a cheap per-connection budget of frames parsed per second and cap the size of the first frame on a connection well below 128 KiB, since a legitimate `auth` is under 300 bytes.

## SM-P-03 Capability-list signature is not injective: a relay can strip signed capabilities undetected

**Severity:** Medium. Defeats the stated purpose of the signature; a relay can force a v3 (non-deniable, classical ratchet) session, hide `groups` and `devices`, and the signature still verifies.

**Location:** `crates/silver-protocol/src/bundle.rs:85-90` and `184-186`; `docs/PROTOCOL.md` §2.

**Description.** The signed bytes are `dh_public || caps.join("\n")`. The lists `["pq_ratchet", "groups", "devices"]` and `["pq_ratchet\ngroups\ndevices"]` produce identical signed bytes, and `KeyBundle::verify` does not reject capability names containing a newline. `advertises()` is an exact string match, so a relay that re-serialises the bundle with the three names merged into one string serves a bundle whose signature verifies and that advertises nothing. The specification claims the opposite ("the relay cannot add or strip one undetected"). The transparency leaf does length-prefix each capability (`transparency.rs:212-215`), so the leaf differs, but the relay also writes the log, so only the bundle's owner auditing its own subject would notice.

**Recommendation.** In `KeyBundle::verify`, reject any capability containing a character outside `[a-z0-9_]` (which makes the join injective without a wire change); length-prefix each capability in the signed bytes at the next domain-string bump. Add a test with a newline inside a capability.

## SM-P-04 The v4 handshake makes the long-term Diffie–Hellman key sufficient for impersonation, which the threat model understates

**Severity:** Medium. Design-level; widens the impact of a partial key compromise beyond what `docs/THREAT_MODEL.md` says.

**Location:** `crates/silver-protocol/src/session.rs:304-317` and `344-356`; `docs/PROTOCOL.md` §4.2.1; `docs/THREAT_MODEL.md` "Holder of a compromised long-term Diffie–Hellman key".

**Description.** A v2 message is authenticated to the recipient by the sealed-layer Ed25519 signature, so impersonating A required A's identity (signing) key. A v4 message carries no sealed-layer signature; the responder's assurance that the initiator is A rests on `init.identity_dh_signature`, which is A's *published, public* bundle signature over A's `dh_public`, and on the fact that DH1 = X25519(IKdh_A, SPK_B) requires A's DH secret. Consequently anyone holding A's X25519 secret alone can start v4 sessions as A with every contact of A, using the public bundle signature verbatim. The threat model's section on a compromised DH key lists only decryption consequences ("opens the sealed layer of every envelope…") and reserves impersonation for the identity-key section. In practice both keys live in the same file, but the two are distinct assets in the threat model's own table, and a memory read of the X25519 scalar (the key used on every envelope) is not the same event as a read of the Ed25519 seed. The Verifpal models guard both identity keys together, so they do not exercise this split.

**Recommendation.** Either document that, from v4 on, the X25519 key is an impersonation key of equal weight to the identity key, or bind the v4 handshake to the identity key freshly (a signature by IK over the handshake transcript, `EK || SPK_B || session id`, which stays deniable-in-practice the way Signal's is not but X3DH's `AD` binding is). At minimum, correct `docs/THREAT_MODEL.md`.

## SM-P-05 Inline MLS size threshold exceeds what actually encodes; a commit is merged and the sequencer moved before the body is framed

**Severity:** Medium. Availability: a group can be wedged for every member, and a joiner has some control over the triggering size.

**Location:** `crates/silver-protocol/src/group.rs:29` and `236-238` (`MAX_INLINE_MLS_BYTES`, `fits_inline`), `251` (`validate`), `crates/silver-protocol/src/envelope.rs:483-486`; consumer `crates/silver-client/src/groups/mod.rs:1389-1420` (`commit_staged`) and `1680` (`seal_to`).

**Description.** `fits_inline` allows an MLS message of up to 24,576 bytes inline. The body is JSON with a base64 field, padded to 160-byte steps, under a 32,768-byte cap applied *after* padding, so the largest encodable pre-padding body is 32,640 bytes and the fixed JSON overhead is 90 bytes; the largest `mls` that encodes is 24,411 bytes (`handshake`) or 24,414 (`welcome`). Messages of 24,412–24,576 bytes pass `fits_inline` and fail in `Body::encode` with `TooLarge`. `GroupBody::validate` enforces only the body cap, contradicting §13.2. In the client, `commit_staged` calls `merge_pending_commit` first, records the new epoch's token, and only then frames and seals; the relay's sequencer entry has already moved to e+1 (the commit is sent to the sequencer before `commit_staged`). When `encode` fails, no envelope is produced and `persist()` is never reached: every other member's next commit is refused as `stale` waiting for a commit that never arrives, and the committer's own state reverts to epoch e on restart. The property test tolerates the `TooLarge` outcome, so nothing catches it. A joiner controls its key package size (device name, capability entries), so an admin's Add commit can be nudged into the window.

**Recommendation.** Define `MAX_INLINE_MLS_BYTES` as what fits (24,400 or less), or implement `fits_inline` by trial encoding, and enforce it in `validate()`. In the client, frame and seal before merging and before contacting the sequencer, so a framing failure is a no-op.

## SM-P-06 Ratchet-header associated data concatenates variable-length KEM fields without length prefixes

**Severity:** Low. No practical attack found (key divergence catches every shift), but the AAD is not a canonical encoding and the field lengths are never enforced at parse time.

**Location:** `crates/silver-protocol/src/session.rs:120-137` (`RatchetHeader::bytes`), `crates/silver-protocol/src/pq.rs:40` (`KemPublic(Vec<u8>)`), `session.rs:117` (`kem_ct: Option<Vec<u8>>`).

**Description.** The AAD is `dh || pn || n || kem? || kem_ct?`. `kem` and `kem_ct` are arbitrary-length vectors at the type level; the fixed lengths (1184, 1088) are only checked when they are used. A header with `kem` of 2,272 bytes and no `kem_ct` has the same AAD as one with `kem`(1184) and `kem_ct`(1088). Today the mismatch is caught because the receiver's root-key derivation then omits the ML-KEM secret and the message key diverges, so the AEAD fails and the trial state is discarded. The construction nevertheless relies on a downstream accident rather than on the AAD being unambiguous, and `kem_remote` is stored from a header without a length check, so a peer could in principle leave a session unable to encapsulate.

**Recommendation.** Enforce `KEM_PUBLIC_LEN` and `KEM_CIPHERTEXT_LEN` in deserialisation (or in `decrypt` before any use), and at the next protocol revision prefix each optional field with its length (or a presence byte) in the AAD, as the transparency leaf already does.

## SM-P-07 Device-list signature and transparency leaf omit certificate content; rename reuses `created_at_ms`

**Severity:** Low. Cosmetic today (names are shown to the owner's devices only), but it means the list signature covers a set of ids, not a set of certificates.

**Location:** `crates/silver-protocol/src/device.rs:219-231`, `crates/silver-protocol/src/transparency.rs:228-232`, `crates/silver-client/src/connection.rs:1574-1586` (`rename_device`).

**Description.** `device_list_signed_bytes` signs `(device, created_at_ms)` per entry, and the leaf hashes the same. `rename_device` re-certifies with the old `created_at_ms`, so the old and new certificates are interchangeable under both the list signature and the leaf, and a relay can serve either for the same list. §14.1 says "the signature covers the set", which is true only for ids.

**Recommendation.** Include the certificate's signature (or its full encoded bytes) in `device_list_signed_bytes` and the leaf, or bump `created_at_ms` on every re-certification.

## SM-P-08 Group and device names admit invisible and bidirectional-override characters

**Severity:** Low. UI spoofing by a hostile admin or a hostile account.

**Location:** `crates/silver-protocol/src/group.rs:387-389`, `crates/silver-protocol/src/device.rs:64`.

**Description.** Both name checks reject only `char::is_control`, whereas reactions also reject the invisible set (`envelope.rs:150-162`: zero-width characters, bidi embeddings and overrides, word joiners, BOM). A group name such as `"Team\u{202E}"` or a device name padded with U+200B reaches the "X joined" lines and the device list.

**Recommendation.** Apply the same `is_invisible` filter to group and device names, and normalise to NFC before the length check.

## SM-P-09 Group application-message ids have no character-set rule

**Severity:** Low. Ids flow into logs and the UI through edits, deletes and reactions.

**Location:** `crates/silver-protocol/src/group.rs:299-301`; `docs/PROTOCOL.md` §13.3 vs §14.4.

**Description.** A group message id is checked only for 1–64 bytes, while one-to-one copy ids must be printable ASCII (`is_valid_message_id`). A newline or an escape sequence inside a group message id is accepted, and `edit`/`delete`/`reaction` bodies name such ids.

**Recommendation.** Apply `is_valid_message_id` to group ids and align §13.3 with §14.4.

## SM-P-10 Non-canonical Ed25519 public-key encodings are accepted as distinct user ids

**Severity:** Informational.

**Location:** `crates/silver-protocol/src/identity.rs:28-31`.

**Description.** `UserId::from_bytes` relies on `VerifyingKey::from_bytes`, which decompresses but does not require canonical `y` (values with y ≥ p are accepted for the few points with y < 19). Small-order keys are rejected at `verify_strict`, and none of the aliasable points has a usable private key, so this is not exploitable; ids are simply not canonical by construction.

**Recommendation.** Compare `bytes` with `point.compress()` at construction and reject on mismatch.

## SM-P-11 Provisioning plaintext cap is unreachable and the revocation list inside it is unbounded

**Severity:** Informational (latent availability).

**Location:** `crates/silver-protocol/src/device.rs:45` (`MAX_PROVISION_BYTES` = 8 MiB), `docs/PROTOCOL.md` §14.6.

**Description.** A `Provision` rides inside a plain body inside a ratchet body, each base64 and each under the 32 KiB body cap, so the effective plaintext limit is roughly 18–24 KB, not 8 MiB. The plaintext carries every device revocation the account has ever issued, so an account with many revocations will eventually be unable to link a device.

**Recommendation.** Send the provisioning payload through the blob store like the snapshot, or cap the `revoked` list to what the device needs.

## SM-P-12 `DeviceCertificate::encode` truncates the name length silently

**Severity:** Informational.

**Location:** `crates/silver-protocol/src/device.rs:79` and `102-106`; `transparency.rs:244`.

**Description.** `v.push(name.len() as u8)` runs from `encode()` without `check_name`; `transparency_leaf` calls `encode()` on unverified bundles. `verify()` rejects such a bundle anyway, so there is no panic and no exploit, but the encoding of a name longer than 255 bytes is silently wrong.

**Recommendation.** Route `encode()` through `check_name` or assert the bound.

## SM-P-13 Post-quantum primitives come from crates that carry "never independently audited" warnings

**Severity:** Informational. A risk the project inherits rather than a defect in its code.

**Location:** `Cargo.lock`: `ml-kem` 0.3.2 (RustCrypto), `x-wing` 0.1.0 (draft-06 of X-Wing, used by OpenMLS for the hybrid ciphersuite), both depending on `ml-kem`.

**Description.** Both crates' README files state: "The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!". The PQXDH handshake, the v4 ratchet and the MLS hybrid suite all rest on them. The hybrid design means a flaw in the ML-KEM implementation cannot weaken the session below its classical strength, which is the right mitigation; the residual exposure is to implementation bugs that leak the classical inputs (timing, memory safety is ruled out by Rust) or that produce a panic on crafted ciphertexts.

**Recommendation.** Track upstream audit status; consider `libcrux-ml-kem` (formally verified, already in the tree via `hpke-rs`) as the ML-KEM backend for both paths when the API allows, and keep the fuzz targets that exercise decapsulation with crafted ciphertexts.

## SM-P-14 The envelope id and the body-level `id` are chosen by the sender and sit outside every AEAD and signature

**Severity:** Informational (documented in §12.1; recorded here because two consumers now depend on ids).

**Location:** `crates/silver-protocol/src/envelope.rs:750` (`id: id.unwrap_or(opened.id)`), `docs/PROTOCOL.md` §12.1, §14.4.

**Description.** The specification records that a relay can rename an envelope. Since 0.9.0 a plain body may also carry an `id` that overrides the envelope id for the recipient's store, and since 0.10.0 edits, deletions, reactions, receipts and tombstones all name messages by that id. Nothing binds an id to a sender beyond the recipient's own bookkeeping, so a relay (or, for the body field, any sender) chooses under which id a message is stored. The client-side consequences (replay of v1 envelopes under fresh ids, a tombstone matching a renamed envelope) are covered under SM-C-15 and SM-C-19.

**Recommendation.** At the next protocol revision, include the message id inside the signed/authenticated body (a copy in the plain body already exists for device copies; make it mandatory and compare it with the envelope id).
# 6. Findings: relay (`silver-relay`)

The relay is a store-and-forward service that sees only sealed envelopes and public keys, so none of the findings below touch message confidentiality. They concern availability, resource exhaustion, one account-takedown path, and one authentication-downgrade path that undermines a control the threat model relies on. The relay's happy path is well guarded: anonymous connections are confined to five frame types, publish requires a matching signed bundle, prekey hand-out and blob storage are transactional, and the transparency log is appended in the same write transaction as the change it records.

## SM-R-01 Any registered identity can permanently destroy any other identity's account

**Severity:** Critical. One authenticated frame, arbitrary victim named by public id, irreversible, low cost.

**Location:** `crates/silver-relay/src/lib.rs:1166-1223` (`apply_device_revocation`), `1575-1630` (`publish`), `1235-1242` (`device_refusal`), `store.rs:620-626` (`cut_off`); `docs/PROTOCOL.md` §14.2.

**Description.** A device revocation is accepted from an account `me` for a device that is either listed on `me`'s published device list or whose own bundle claims `me`. The device list, however, is signed only by the account, and `publish` never checks that a listed device id is not an independent, already-registered identity. So attacker X can:

1. `publish` a bundle whose `devices` list contains a certificate X signs for victim Y's id: `X.certify_device(&Y, "", t)`. `bundle.verify()` passes (X validly signed the certificate and the list), and `publish` accepts it, because the only device-related refusal is that a listed device is not already revoked.
2. Send `RevokeDevice { revocation: X.revoke_device(&Y, t) }`. `apply_device_revocation` sees `listed == true` and proceeds.

The effects are all keyed by Y's public id:

- `cut_off(Y)` deletes Y's mailbox, both kinds of prekeys, and key packages.
- `set_device_revocation(Y)` is permanent; there is no admin "unrevoke" and no path that removes the entry (only a backup restore or a test deletes the table).
- Y's future logins are refused forever: `device_refusal(Y)` returns "this device has been revoked" because `is_device_revoked(Y)` is checked before anything considers whether Y is actually a device.
- Y's future `publish` is refused, envelopes to Y are refused with `NotFound`, and a revocation entry is appended to the transparency log under Y's subject.

The cost is one of the address's 20 hourly registrations. The existing test `a_device_revocation_takes_only_a_device_of_the_account` enshrines the very vector, but only with an unregistered "phone" device, so it does not catch the case where the named id is someone's real identity.

**Amplification.** Because the served revocation is logged under Y's subject and the client acts on device revocations by device id without binding them to Y's real account (SM-P-01), Y's *contacts* also drop their sessions with Y and stop sending to Y when they next look Y up. The takedown reaches beyond the one relay.

**Impact.** Permanent, unrecoverable denial of the victim's account on that relay, plus contact-side session teardown. The threat model states the exact opposite: "otherwise any account could cut any identity off by calling it a device of its own" is given as the reason the check exists, but the check is insufficient.

**Recommendation.** At `publish`, refuse a device list that names an id which already has a bundle not carrying this account's `device_of` (a real identity cannot also be someone's device). At `apply_device_revocation`, require `claims_me`, or `listed` together with the device having no bundle of its own. Add an admin `unrevoke-device` for recovery. Fix SM-P-01 in tandem. Longer term, have the device key counter-sign its own certificate so an account cannot unilaterally enroll a stranger's key as its device.

## SM-R-02 The bound login is verified against the connection's own Host header, so a hostile relay can replay logins

**Severity:** High. Defeats the mitigation built for this exact threat; yields full mailbox read, acknowledge (delete) and publish as the victim.

**Location:** `crates/silver-relay/src/lib.rs:1885-1889` (`host` from the request), `1934-1947` (verification); `docs/PROTOCOL.md` §7.1; `docs/THREAT_MODEL.md` "Relay operator — Cannot".

**Description.** The bound login is meant to stop a relay in the middle from forwarding a challenge from another relay and using the answer there: the client signs `host || nonce`, and the relay checks the signed `host` against "the host it was reached as". But the relay derives that host solely from the incoming `Host` header, which the connecting party chooses:

```rust
let host = headers.get(HOST).and_then(|v| v.to_str().ok()).map(normalize_host).filter(...);
...
if our_host.as_deref() != Some(host.as_str()) { Err(...) }
else { verify_auth_bound(&user_id, &host, &nonce, &signature) }
```

Nothing compares `our_host` with the relay's ACME domain, its certificate SANs, or any configured name.

**Attack.** Victim V is steered to hostile relay H (a bad invite link, a migration). H opens a connection to the real relay R with `Host: h.example`, receives R's nonce, and relays it to V as its own challenge. V answers `Auth { host: "h.example", signature = sign("h.example" || nonce) }`. H forwards the frame verbatim to R. At R, `our_host == "h.example" == host`, the signature verifies, and H is now authenticated as V: it reads and acknowledges (deletes) V's queued ciphertext, replaces V's live session, deposits garbage key packages under V's id (which needs no signature), and drains V's one-time prekeys through lookups. `--require-bound-auth` does not help, because the bound login itself is satisfied. With the installer's default built-in TLS there is no front that would constrain `Host`.

**Recommendation.** Derive the accepted host set from configuration (the ACME domain, the certificate SANs, or an explicit `--host`) and verify the login's `host` against that set, treating the request `Host` header as a hint at most. Make the bound login the default and refuse the unbound v1 login unless explicitly enabled.

## SM-R-03 Pre-WebSocket connections are neither timed out nor counted

**Severity:** High. Unauthenticated file-descriptor and task exhaustion below every configured cap.

**Location:** `crates/silver-relay/src/lib.rs:1907` (`connect` runs after the upgrade), `1927` (`AUTH_TIMEOUT` starts after the upgrade); axum 0.8.9 and axum-server 0.8.0 build hyper without a timer, so the HTTP header-read timeout is inert.

**Description.** Connection accounting (`state.connect`) and the 10-second authentication timeout both begin only after the WebSocket upgrade completes. axum's `serve` builds hyper with `Time::Empty` and no timer, and axum-server does the same, so hyper's default 30-second header-read timeout is discarded with a warning; the TLS handshake has a 10-second cap but the HTTP phase after it has none. An attacker can therefore open connections (or complete a TLS handshake) and then send a partial request line, or nothing, holding a socket, a task and buffers indefinitely, invisible to `max_connections`, `connections_per_address` and address bans, up to the process file-descriptor limit (65,536 in the shipped unit). The ASVS self-assessment cites "a 10-second authentication timeout" as the anti-automation control for this.

**Recommendation.** Install a hyper timer and an explicit header-read timeout on both the plain and TLS paths (`builder.http1().timer(TokioTimer::new())` with a short `header_read_timeout`), and do per-address accept-time accounting before the upgrade.

## SM-R-04 Unbounded persistent storage: envelopes to unregistered recipients, no global mailbox cap

**Severity:** High. Anonymous disk exhaustion, persisted for the mailbox TTL (30 days).

**Location:** `crates/silver-relay/src/lib.rs:1742-1760` (`route`), `store.rs:1534-1560` (`enqueue`); `docs/THREAT_MODEL.md` "Stranger".

**Description.** `route` checks only the ciphertext length and whether the recipient is a revoked device, then enqueues. `enqueue` enforces only the *per-recipient* count and byte caps; it never checks that the recipient exists. The recipient id only has to be a valid Ed25519 point. There is no relay-wide mailbox cap (blobs have a global cap; mailboxes do not).

**Attack.** An anonymous connection sends 30 envelopes per minute, each up to ~34 KB of ciphertext, to fresh random recipient ids. With 16 connections per address that is on the order of 16 MB/minute, roughly 20 GB per day per address, none of it ever acknowledged (there is no owner to ack), deleted only after the TTL. The hourly expiry sweep decodes every mailbox entry, and the usage walk runs on every registration, so both degrade as the store grows. The threat model claims "mailboxes, file storage and the number of identities are capped".

**Recommendation.** Require a published bundle for `envelope.to` (a device must publish before anyone can seal to it in any case), and add a global mailbox-bytes cap analogous to the blob storage cap.

## SM-R-05 `publish` is unrated: unbounded transparency-log growth and an fsync storm from one connection

**Severity:** High. Permanent, unprunable storage growth plus write-lock starvation for all users.

**Location:** `crates/silver-relay/src/lib.rs:2171-2192` (dispatch with no rate bucket), `store.rs:239-268` and `996-1002` (append-only log, one entry per changed bundle leaf).

**Description.** Unlike lookups, `log_since` and key-package deposits, `Publish` has no per-connection rate bucket. Each accepted publish verifies the identity signature plus the signed prekey plus up to 50 signed ML-KEM one-time keys, then performs three durable (fsync) write transactions, and appends a transparency-log entry whenever the bundle leaf differs, which a fresh signed prekey guarantees. The log is append-only and never pruned, and every client replays it. An attacker looping `publish` with a fresh signed prekey each time imposes ~50 signature verifications and 3 fsyncs per frame and roughly 200 permanent, unprunable bytes per frame in the log, while every other connection's writes queue behind the single redb writer (which blocks a runtime worker thread).

**Recommendation.** Add a per-connection publish bucket, rate-limit *logged* bundle changes per identity per hour, and verify signatures only after the bucket check.

## SM-R-06 `ack` is unrated and each one is a durable write transaction

**Severity:** Medium. Write-lock and fsync storm from any authenticated client; store work runs synchronously on runtime workers.

**Location:** `crates/silver-relay/src/lib.rs:2258-2261`, `store.rs:1594-1620`.

**Description.** `Ack { id }` has no rate bucket, and `store.ack` opens a write transaction and commits even when the id is unknown. redb serialises writers and fsyncs on commit, and all store calls run synchronously on the tokio worker inside `handle_frame`, so a client spamming `ack` holds the write lock and worker threads continuously, delaying every send and publish relay-wide.

**Recommendation.** Rate-limit `ack` (tie it to the send/lookup bucket), check the id in a read transaction first, batch acknowledgements, and move store work to `spawn_blocking`.

## SM-R-07 Unbounded outbound queue lets a non-reading client pin memory

**Severity:** Medium. Roughly 32 MiB or more per held socket, 16 sockets per address.

**Location:** `crates/silver-relay/src/lib.rs:2028` (unbounded channel), `1550-1565` (whole mailbox pushed at register), `2047-2051` (writer awaits `send`).

**Description.** The per-connection outbound channel is unbounded. On authentication the relay loads the entire mailbox (up to 1,000 envelopes or 32 MiB) and pushes every delivery into the channel at once; blob replies (up to 256 chunks of ~65 KB) are built in memory and queued too. The writer task awaits `send` inside its `select!`, so a peer that stops reading stalls the task there and never observes the idle timeout or a close from a replacing session. An attacker fills its own mailbox, then authenticates repeatedly and never reads, holding the replay in memory per socket.

**Recommendation.** Use a bounded channel with backpressure, page the mailbox lazily as acknowledgements arrive, and put a write timeout on the sink.

## SM-R-08 A non-member who knows a group id can seize its sequencer entry

**Severity:** Medium. Wedges a group on that relay; removed members and invite-link holders know the id.

**Location:** `crates/silver-relay/src/lib.rs:1035-1075` (`group_create`), `store.rs:1420-1450`; `docs/PROTOCOL.md` §13.5.

**Description.** `group_create` accepts any `(group, epoch, next)` on any connection when no entry exists, with no proof of membership. Group ids appear in every invite link and are known to removed members. After the 180-day idle expiry, a relay restore, or in the race before the creator's first `group_create`, an outsider creates the entry with an arbitrary `next` that only they can satisfy; honest members then get `exists`/`stale`/`forbidden` and can never commit, so the entry never refreshes and the squatter can re-seize it after each expiry. `Exists(epoch)` also discloses any group's current epoch to anyone who knows the id. The specification attributes counter scrambling to a hostile relay only.

**Recommendation.** Require the current epoch's token (or an admin's authenticated connection) to re-create an entry for a known group id, keeping the last token hash for a grace period after expiry.

## SM-R-09 `u64` epoch overflow panics from an anonymous connection

**Severity:** Medium. Deterministic panic inside a write transaction; leaves a stale online-session entry.

**Location:** `crates/silver-relay/src/store.rs:1476` (`entry.epoch += 1`).

**Description.** The sequencer increments the epoch with `+=` under `overflow-checks = true`. An anonymous connection sends `group_create { epoch: u64::MAX }` followed by `group_commit { epoch: u64::MAX, token }`; the increment panics. The panic unwinds the frame-handling task: the connection guard is dropped (count released) but `unregister` is skipped for an authenticated connection, leaving a dead `Session` in the online map until the next login for that user. The database stays usable, but pages allocated by the un-aborted transaction are not reclaimed until reopen.

**Recommendation.** Use `checked_add` and reject overflow as `Stale`/`Malformed`; wrap the frame handler so a panic still runs `unregister`; consider `catch_unwind` at the frame boundary.

## SM-R-10 A revoked identity can still authenticate and act on the relay

**Severity:** Low. Design asymmetry between identity and device revocation.

**Location:** `crates/silver-relay/src/lib.rs:1930-1980` (auth path checks `user_banned` and `device_refusal`, not `is_revoked`).

**Description.** The auth path does not consult `is_revoked(user)`, so the holder of a compromised-then-revoked identity key keeps reading and acknowledging the victim's mailbox, depositing key packages and consuming lookups, whereas a *device* of a revoked account is refused. The specification (§10.1) promises only disconnect plus publish refusal on revocation, so this is not a documented contradiction, but the "compromised identity key" narrative implies the relay side ends too.

**Recommendation.** Refuse `auth` for revoked identities and drop the mailbox on revocation.

## SM-R-11 IPv4-mapped IPv6 peers bypass loopback, trusted-proxy and ban checks

**Severity:** Low.

**Location:** `crates/silver-relay/src/lib.rs:567-587` (address handling), `570`, `572`.

**Description.** Loopback detection, the trusted-proxy list and ban matching all use the raw `IpAddr`. With a dual-stack listener, an IPv4 peer arrives as `::ffff:a.b.c.d`: a loopback front is not recognised as trusted (so all forwarded clients collapse to one address and share the 16-connection cap), and `admin ban 1.2.3.4` does not match `::ffff:1.2.3.4`.

**Recommendation.** Canonicalise with `IpAddr::to_canonical()` before every comparison.

## SM-R-12 Attacker-chosen text is written to the relay log; rejected sends log at line rate

**Severity:** Low. Log injection and log-spam, unauthenticated.

**Location:** `crates/silver-relay/src/lib.rs:2312` (`warn!("malformed client frame: {e}")`), `1795-1799`.

**Description.** serde_json error text embeds the offending input verbatim, and JSON escapes are decoded, so a frame such as `{"type":"\nERROR forged log line"}` writes a forged line into a text-format log, unauthenticated, one per connection. The ASVS self-assessment states "no user-controlled text reaches the relay log".

**Recommendation.** Log only the error kind and position, or drop the detail to `debug`.

## SM-R-13 Smaller relay hardening items

**Severity:** Low to Informational. Grouped for brevity; each is individually minor.

- **Zero-byte and tiny blob chunks** bypass byte accounting and the per-address upload budget while still consuming a database entry each, so a client can bloat the store well past `--blob-storage-mib` with uncounted entries (`lib.rs:1425`, `store.rs:922`). Require a minimum chunk size and charge a fixed per-chunk overhead.
- **Envelope `id` is unvalidated on the relay** (`is_valid_message_id` exists but is not applied), so an empty, oversized or control-laden id becomes a global `BY_ID` key and reaches the recipient's client and log. Enforce the id rule on `send` and `ack`.
- **`--lookups-per-minute 0` cannot disable lookups**: `Bucket::per_minute` clamps 0 to 1 (`lib.rs:284-287`).
- **The startup line reports the CLI invite policy, not the effective one**: an admin override that opens registration is not reflected, so the journal can claim a token is required when it is not (`main.rs:671`).
- **`--message-ttl-days` multiplication can panic at startup** under overflow checks (`main.rs:698`); operator-only.
- **`Store::open` chmods the database's parent directory to 0700**, so `--data-dir .` would chmod the working directory (`store.rs:431-440`).
- **The transparency log stores `at_ms` for every publish**, a permanent, publicly served per-identity activity timeline; this is inherent to key transparency but is worth stating next to the journal-pseudonym privacy claim.
# 7. Findings: client library and terminal client (`silver-client`, `silver-tui`)

The client is where trust decisions are made: which relay to believe, which bundle to pin, whether a downgrade is a downgrade, and what to write to disk and in what form. The at-rest design (a random data key wrapped by the OS key store or Argon2id, every file AEAD-bound to its name) is well built, the file-name sanitiser and exclusive-create save path are careful, SOCKS5 proxying never resolves names locally and never falls back to a direct connection, and every screen pane renders through a layer that strips control and zero-width characters. The findings concern the pinning verifier, gaps in the re-encryption file list, a set of silent downgrades a hostile relay can trigger, and several places where peer-controlled data is trusted one step further than the design intends.

## SM-C-01 TLS key pinning accepts a pin match on any certificate the server presents, not only the validated path

**Severity:** High. Defeats the one control the threat model offers against a TLS-inspecting proxy, using only public information.

**Location:** `crates/silver-client/src/tls.rs:287-301` (`PinnedVerifier::verify_server_cert`).

**Description.** After ordinary chain validation, the verifier walks `end_entity` followed by every certificate in `intermediates` and accepts if *any* of them matches a pin:

```rust
for cert in std::iter::once(end_entity).chain(intermediates) {
    let pin = Pin::of(cert)...;
    if self.pins.contains(&pin) { return Ok(verified); }
    presented.push(pin);
}
```

`intermediates` is whatever the server sent after the leaf. The webpki path builder uses only the certificates it needs and ignores extras that do not chain, so an unrelated certificate appended to the chain does not fail validation.

**Attack.** A corporate TLS proxy (or anyone holding a mis-issued certificate for the relay's name) terminates the connection with its own leaf for `relay.example`, validated through the installed root, and appends the relay's genuine leaf certificate, which is public (`--print-pin` fetches it, and any client can), as an extra "intermediate". Validation passes on the proxy's leaf, the pin loop reaches the appended genuine certificate, the pin matches, and the proxy reads the WebSocket in the clear. The existing test only covers a wrong key with no extra certificates.

**Recommendation.** Match pins against the *verified* path only: the simplest correct rule is to require the pin to match `end_entity` (which is what `--print-pin` recommends pinning), or rebuild the path with webpki's `verify_for_usage` and pin against the `VerifiedPath`. Add a test that serves a trusted-but-wrong leaf with the pinned certificate appended.

## SM-C-02 Adding or removing protection re-encrypts ten files but not `groups.json`, `groups.mls` or `revocation.json`

**Severity:** High. Confidentiality (MLS epoch secrets, leaf private keys and key-package private halves stay in plaintext on a "protected" directory) and availability (unprotecting leaves the three files permanently unreadable).

**Location:** `crates/silver-client/src/store.rs:836-847` (`recrypt_all`), compared with `1109-1123` (`wipe`, which knows all three files) and `crates/silver-client/src/groups/mod.rs:79-80, 2626-2644`.

**Description.** `recrypt_all` iterates a fixed list of ten file names. The store also owns `revocation.json` and the groups engine owns `groups.json` and `groups.mls`, all written through the cipher-aware helpers, but none of them is in the list. Two consequences follow:

1. **Protect** (`set_passphrase_with`, or `protect_with_keystore`, which runs automatically on first start on a machine with a key store): an existing directory's `groups.mls` (OpenMLS storage: epoch secrets, leaf private keys, key-package private halves), `groups.json` and the pre-signed revocation certificate remain plaintext until each is next rewritten. The file reader accepts plaintext silently, so nothing warns. A thief of a "key-store protected" directory reads every group the user is in.
2. **Unprotect** (`remove_protection`, reached by `--no-keystore` or `--remove-passphrase` without a key store): the three files stay ciphertext under a key that no longer exists. The next read fails with "is encrypted but the data directory is not unlocked"; every group becomes unreadable and `/revoke` and `--export-backup` (which needs the revocation certificate) fail.

**Recommendation.** Derive the file list from a single definition shared with `wipe()`, include the three files, and add a test that protects and unprotects a directory holding every known file and asserts each file's encryption state afterwards.

## SM-C-03 Plain v1 bodies are still sent when a relay strips a peer's prekeys, with only a debug log

**Severity:** Medium. A hostile relay downgrades a new conversation to non-forward-secret, non-deniable v1, readable later by anyone holding the recipient's long-term key.

**Location:** `crates/silver-client/src/connection.rs:1103-1115` (`seal_for`), `1089-1100`; `docs/PROTOCOL.md` §8 ("0.10.0 refuses to send it"); `tests/e2e.rs:831`.

**Description.** When the recipient's bundle carries no prekeys, `seal_for` logs at `debug` and sends a plain v1 body sealed to the long-term X25519 key and signed by the sender's identity key. The specification says 0.10.0 refuses to send v1; the end-to-end test asserts the opposite. The TUI never inspects `Delivery.forward_secret`; the only signal is the status-bar label, and the stripped bundle is silently re-pinned. Because `prekeys` is optional, `bundle.verify()` passes on a stripped bundle. With transparency the stripped leaf would differ, but the relay can withdraw the transparency feature for that connection (SM-C-05) and a refusal does not stop the send (SM-C-06).

**Recommendation.** Return an error (as the specification promises) when `!to.supports_sessions()`; treat the loss of prekeys on a contact that previously had them as a key change (warn, do not re-pin); at minimum raise `ClientEvent::Error` as the stale-prekey path does.

## SM-C-04 The host-bound login is downgraded to the unbound form whenever the relay omits `bound`

**Severity:** Medium. Restores the relay-in-the-middle login replay the bound login was introduced to stop; combines with SM-R-02.

**Location:** `crates/silver-client/src/connection.rs:1966-1980`.

**Description.** `let host = bound.then(|| url_host(relay_url)).flatten();` — the decision is the relay's, per connection; nothing is remembered and there is no client option to require binding. A hostile relay in the middle forwards the real relay's challenge without `bound`; the client signs the bare nonce; the attacker presents that signature to the real relay and reads the mailbox. The threat model frames the unbound login as a relay-side tolerance for old clients, but the 0.10.0 client itself downgrades on the relay's word.

**Recommendation.** Remember per host that `bound` was offered (as `secure_hosts` already does for TLS) and refuse to fall back; add a client-side `--require-bound-auth`; make bound-only the default.

## SM-C-05 Transparency checking is switched off per connection on the relay's word, silently

**Severity:** Medium. A relay wanting to serve one client a stale or stripped bundle omits `transparency` from that client's `auth_ok`; the client then checks nothing, warns nothing, and stops gossiping heads.

**Location:** `crates/silver-client/src/connection.rs:1994`, `2022`; `tail.rs:152-157`; `828-836` (`gossip_head`).

**Description.** `keeps_log` is recomputed from the relay's feature list on every connection. With it false, every lookup settles unchecked, peer heads are ignored, and this client's bodies stop carrying a head, so its contacts lose the ability to detect a fork through it too. The TUI prints "relay is older than 0.8.0" only on `/log`. Nothing compares with previously advertised features. The same applies to `anonymous_send` (SM-C-16).

**Recommendation.** Persist per host that `transparency`, `anonymous_send`, `pq_prekeys` and `prekeys` were offered; treat their disappearance as a `Withheld`-class transparency event and refuse lookups, or warn loudly, until the user accepts the change.

## SM-C-06 A transparency refusal does not stop the send: the pinned bundle is used instead

**Severity:** Medium. The specification and the UI both say "nothing is sent with the key"; the message goes out under the pin, and a withheld revocation never reaches the user.

**Location:** `crates/silver-client/src/connection.rs:1180-1196` (`send_content`), `tail.rs:493`; `docs/PROTOCOL.md` §11.4; TUI `app.rs:3510-3520`.

**Description.** `lookup_full` returns `ClientError::Transparency` when the answer is refused; `send_content` matches every lookup error the same way (`Err(e) => debug!("using the pinned bundle…")`) and proceeds with the pinned bundle. Lifecycle statements inside a refused answer are never raised, because `settle()` runs only on accepted answers. So when the log holds Bob's revocation and the relay withholds it, Alice's client reports the refusal, tells her nothing was sent, and sends the message to the revoked key in her pin; when the served bundle is not the latest logged leaf, the old pinned prekeys are used.

**Recommendation.** Match `ClientError::Transparency` explicitly and abort the send; raise verified lifecycle statements even from refused answers.

## SM-C-07 An inbound handshake's `identity_dh` is never compared with the pinned key, so a holder of the identity key impersonates without a key-change warning

**Severity:** Medium. Bypasses the "contacts see the published key change (loudly)" guarantee for the receive path.

**Location:** `crates/silver-client/src/sessions.rs:485-492`; `crates/silver-protocol/src/session.rs:347-375`; `connection.rs:1196-1201` (the only key-change comparison, on the send path).

**Description.** `Session::respond` verifies `identity_dh_signature` against the sender id (v4) or relies on the sealed-layer signature (v2), which proves the initiator holds the Ed25519 key, not that `identity_dh` is the *published* key; the AD is then built from whatever the init says. Nothing on the receive path consults the contact's pinned bundle. An attacker with Bob's identity key publishes nothing, starts a session with Alice using a fresh DH key and a self-signed binding, and Alice's client accepts it, prints "session started by them", and her replies go to the attacker. No key-change warning, no log entry, nothing to gossip. (See also SM-P-04 for the DH-key-only variant.)

**Recommendation.** On a new inbound session, compare `init.identity_dh` with the pinned `dh_public` and warn or drop on mismatch; surface the key in `SessionEstablished`.

## SM-C-08 A crash between re-encryption and the vault write leaves the directory unrecoverable

**Severity:** Medium. Data loss of every key, contact and message from a crash during an operation that runs automatically on first start.

**Location:** `crates/silver-client/src/store.rs:741-746` (`protect_with_keystore`), `777-779` (`set_passphrase_with`).

**Description.** Files are rewritten under a fresh random data key that exists only in process memory; `vault.json` (the wrapped key) is written last. A kill after any part of `recrypt_all` and before `write_vault` leaves encrypted files with no way to recover the key. The crash-consistency test covers steady-state writes only.

**Recommendation.** Write `vault.json` first (readers already tolerate a mix of plain and encrypted files), then re-encrypt; on unprotect, remove `vault.json` last, which is already the order.

## SM-C-09 `--check-release` ignores the proxy remembered in `config.json` and connects directly

**Severity:** Medium. Deanonymises a Tor user with one documented command.

**Location:** `crates/silver-tui/src/main.rs:552-556` versus `400`; `crates/silver-client/src/update.rs:59-64`.

**Description.** The relay path takes the proxy from `config.proxy` (remembered from an earlier `--proxy`), but the release check takes it only from the command line or the environment, never opens the store, and then does a local DNS resolution and a direct TLS connection to `api.github.com`. `update.rs` documents that the check uses "the same TLS configuration the relay connection uses (… an HTTP or SOCKS5 proxy)", which is true only for CLI-supplied proxies.

**Recommendation.** Read `config.json`'s proxy and CA settings when no CLI value is given, or refuse to run the check without an explicit proxy when the config names one.

## SM-C-10 The data directory and most of its files are created at umask modes; the plaintext fallback exposes proxy credentials, the invite token, contacts and history to other local users

**Severity:** Medium. Applies precisely in the headless-Linux case where the key-store fallback yields plain files.

**Location:** `crates/silver-client/src/store.rs:641-646` (`create_dir_all`, no mode), `1749-1758` (`write_atomic`, `File::create`), `1146-1152` (`save_config` uses the non-private writer), `outbox.rs:103-106`, `transparency.rs:436-439`, `files.rs:317-333`, `backup.rs:93`, `export.rs:122`.

**Description.** Only `identity`, `prekeys`, `sessions`, `revocation`, `vault`, the groups files, `silver.log` and `.open/` are created 0600/0700. The data directory itself is 0755 under a normal umask; `config.json` (which holds `proxy` with `user:password@`, `invite_token`, `relay_pins`, `secure_hosts`), `contacts.json`, `devices.json`, `requests.json`, `blocked.json`, every history file, downloads, exports and backups are 0644. With `Protection::None` these are world-readable plaintext; even when encrypted, the history file names (`history/<user id>.jsonl`, `history/group-<id>.jsonl`) reveal the contact graph to any local user (SM-C-25).

**Recommendation.** Create the data directory with mode 0700 (and chmod an existing one); use the private writer for every store file; create downloads, exports and backups 0600 in a 0700 directory; `fsync` the outbox and transparency writes.

## SM-C-11 The `/open` refusal list is incomplete, and the decrypted `.open/` copy carries no mark-of-the-web

**Severity:** Medium. A hostile contact sends a file whose extension is absent from the list; `/open` hands it to the platform opener, which executes it.

**Location:** `crates/silver-client/src/files.rs:19-112` (`RUNNABLE`), `crates/silver-tui/src/app.rs:3706-3737` (`plain_copy_for_opening`).

**Description.** Missing, and executable-on-open on the named platform: Windows `.appref-ms` (ClickOnce), `.scf`, `.chm`, `.xll`, `.search-ms`, `.rdp`, `.theme`, `.wsc`, `.msh*`, `.ps2`, `.pyz`/`.pyzw`, `.ahk`, `.udl`, `.iso`/`.img`/`.vhd`/`.vhdx` (auto-mount), `.job`; macOS `.inetloc`, `.fileloc`, `.ftploc`, `.afploc`, `.vncloc`; Linux `.bin`, `.class`, `.lua`, `.tcl`, `.service`; and macro documents (`.docm`, `.xlsm`, `.pptm`). Separately, the plain copy written for opening an encrypted download never calls `mark_of_the_web`, so on Windows SmartScreen, Protected View and Office macro blocking do not apply to files opened from encrypted downloads while they do for plain ones; mark-of-the-web failures are silently ignored.

**Recommendation.** Prefer an allowlist of viewer types (images, PDF, plain text, audio/video, archives) and refuse everything else; tag the `.open/` copy with `Zone.Identifier`; report a failed tag.

## SM-C-12 The saved-file path of a received attachment is re-parsed from the message *text*, and the open/decrypt routine will decrypt any file bound under the data key

**Severity:** Medium. Needs a guessed path and a user action the UI itself invites; impact is opening any local file in its handler, or writing a plaintext copy of `identity.json`, `sessions.json` or `prekeys.json` into the downloads folder.

**Location:** `crates/silver-tui/src/app.rs:123-127` (`from_history`), `182-192` (`saved_file_path`), `3706-3720` (`plain_copy_for_opening`), `3789-3825` (`cmd_files_decrypt`); `crates/silver-client/src/store.rs:1700-1711` (files encrypted under the bare file name as AAD).

**Description.** A received line's `file` field is not persisted; it is recomputed at every load by parsing the line's text for `[file] name (size) → /path`. A contact's plain text body is stored verbatim, so after the next restart or lock cycle a message such as `[file] notes.txt (1 KiB) → /home/alice/.local/share/silver-messenger/identity.json` carries `file = Some(that path)`; a click shows "Double-click to open identity.json, or /open". `/open` reads the file, sees the store's encryption magic, decrypts it with the data-directory cipher under AAD `identity.json` (the same name binding the store used to write it), and writes the plaintext to `downloads/.open/` (0600, removed at exit) before launching the JSON viewer; `/files decrypt` writes a permanent plain copy into `downloads/` at umask mode. Without secrets the weaker variant remains: opening any attacker-chosen existing file in its handler.

**Recommendation.** Persist the saved path in a dedicated history field written only by the download handlers; never derive it from text. As defence in depth, canonicalise the path in `open_file`, `plain_copy_for_opening` and `cmd_files_decrypt` and require it to be inside the downloads directory. Consider a distinct AAD prefix for store files and for downloads so one cipher context cannot decrypt the other.

## SM-C-13 An unauthenticated sender hint is rendered as a contact's name

**Severity:** Low. A spam and social-engineering channel that bypasses `/block`.

**Location:** `crates/silver-client/src/connection.rs:2803`, `2870-2873` (`Undecryptable { from, .. }`), doc comment at `69`; TUI `app.rs:3365-3373`.

**Description.** For v4 and v5 bodies the sealed-layer `from` is unverified. Any decryption failure, including `UnknownSession` (which needs no keys at all), emits `Undecryptable { from }`, and the TUI prints "A message from {name} could not be read … sending them a message starts a fresh session" with a toast, ungated by the blocked list. A stranger, a blocked id or the relay sends `{"v":4,"session":<random>,…}` with `from` set to a contact's id and the victim is nudged to message that contact. The doc comment claims the envelope "was authentic".

**Recommendation.** Carry the hint as an `Option` and never render a contact name from it; aggregate and rate-limit such notices; fix the comment.

## SM-C-14 Strangers grow `sessions.json` without bound, and every message rewrites the whole file under the sessions mutex

**Severity:** Low.

**Location:** `crates/silver-client/src/sessions.rs:441-544`, `546-558` (`prune`, per peer only), `605-625` (`persist_sessions`).

**Description.** Any successful handshake persists a session; the cap is five *per peer id* and nothing expires peers. A v4 session carries ~3.4 KB of ML-KEM state plus up to 2,000 skipped keys (~136 KB). An attacker registering identities (20 per hour per address) sends five far-ahead handshakes each; the Requests cap drops the *message* after the session is already stored.

**Recommendation.** Do not persist sessions from non-contacts until accepted; cap total sessions and expire by last use; persist incrementally.

## SM-C-15 Sequence state is only the last `(epoch, seq)`; the relay can bloat the prekey file through `prekey_status`

**Severity:** Low.

**Location:** `crates/silver-client/src/sequence.rs:27-31`; TUI `app.rs:3212-3231`; `connection.rs:2366-2385`, `sessions.rs:217-247`.

**Description.** A message that arrives late after a reported gap is dropped as a "replay" once `note_received` has advanced past it, so relay reordering loses messages; and because the envelope id is outside every AEAD, the relay can re-deliver an old v1 envelope under a fresh id past the bounded `known_ids` set, where any different epoch is accepted as "new installation". Separately, relay-supplied `consumed` and `one_time_remaining` drive key retention (30 days) and regeneration (20 X25519 + 10 ML-KEM keys, ~1.2 KB each) with republish backoff reset on every reconnect, so a relay that closes the socket each time accumulates retained keys.

**Recommendation.** Keep bounded per-epoch state with a small acceptance window for late seqs; cap retained handed-out keys and rate-limit republishes per hour.

## SM-C-16 Anonymous submission is abandoned silently

**Severity:** Low. A Tor user cannot see when the relay deanonymises their sends.

**Location:** `crates/silver-client/src/submitter.rs:198-200`, `connection.rs:2188-2190`, `2338`, `2486`.

**Description.** When the relay answers `unauthenticated` once, or omits `anonymous_send`, the client falls back to submitting on the authenticated connection with a `warn!` and no event or status indicator. The threat model documents the fallback but the user has no way to notice it.

**Recommendation.** Raise an event and a status flag; add `--require-anonymous`.

## SM-C-17 No client-side cap on relay frame or blob-chunk sizes

**Severity:** Low. A hostile relay can make the client buffer hundreds of megabytes.

**Location:** `crates/silver-client/src/connection.rs:3167` (default WebSocket config), `2632` (`handle_blob_frame`).

**Description.** `connect_async_tls_with_config(url, None, …)` uses tungstenite's 64 MiB default message size, `read_frame` decodes anything, and blob chunks of any length are stored per index. `MAX_FRAME_BYTES` is enforced by the relay only.

**Recommendation.** Pass a `WebSocketConfig` with `max_message_size = MAX_FRAME_BYTES`; reject chunks larger than `CHUNK_BYTES + 16`.

## SM-C-18 Forks and rewinds are reported but not enforced, and the evidence is discarded

**Severity:** Low.

**Location:** `crates/silver-client/src/tail.rs:122-140`; TUI `app.rs:3522-3560`.

**Description.** On a lower head (`Rewound`) or a differing hash at the same index (`Fork`), the client resets its log store and re-tails from zero, then keeps answering lookups on the relay's new chain; sending continues; a first-time client accepts any chain without a warning. Resetting throws away the checkpoints that are the only proof of the fork.

**Recommendation.** Keep the old head and checkpoints alongside; require acknowledgement before trusting new lookups.

## SM-C-19 History files grow without bound and are rewritten whole for every inbound deletion or unknown-id update

**Severity:** Low. Denial of service on one conversation by a contact or group member; blocking stops it.

**Location:** TUI `app/everyday.rs:606-610`, `653-679`, `742`; `crates/silver-client/src/store.rs:1490-1524`, `1579-1625`, `1446-1464`.

**Description.** Each of up to 64 ids in a `delete` body triggers `mark_deleted`, which reads, filters and rewrites the whole history file and, for an unknown id, appends a permanent tombstone; edits from non-authors and reactions for messages not held are appended to disk unconditionally (the author check runs only at load and the in-memory "late" list is the only thing pruned after a day). The whole file is read and parsed on every load.

**Recommendation.** Keep updates for unheld messages in the bounded in-memory store only; coalesce a `delete` into one rewrite; prune tombstones and orphan updates older than the tombstone window on rewrite; add a per-conversation size ceiling with compaction.

## SM-C-20 Peer text reaches the terminal raw through the plaintext export, the release-check output, the clipboard and reader mode

**Severity:** Low. The screen path is protected; these four paths are not.

**Location:** `crates/silver-client/src/export.rs:153-174`; `crates/silver-tui/src/main.rs:562-575`; `app.rs:1606-1615` and `1401-1405` (`/copy`, selection), `clipboard.rs:54-62`; `journal.rs:59-64`, `95-96`, `383-393`; `reader.rs:50`, `67`; `ui.rs:861`, `358-363`.

**Description.** The text export writes message text verbatim, so an escape sequence in a message runs when the file is `cat`'ed (the JSON export is safe). `--check-release` prints the tag and URL from the API response unfiltered, and the server's status line lands in the error. `/copy` and Ctrl-C place the pre-filter text on the clipboard (or forward it by OSC 52 to the local terminal through SSH/tmux), so `ok\rcurl … | sh\r` pasted into a shell runs. In reader mode the journal splits on `\n`, so a message `hi\nalice: send me the passphrase\nWarning: …` is spoken as three independent lines indistinguishable from other members' lines or system warnings; on screen the same split aligns a forged second line into the System pane's text column after `/search`; the reader-mode compose line echoes pasted bytes raw.

**Recommendation.** Filter control characters (keeping `\n` only where a line break is intended) in the text export, the release-check output and `copy_text`; replace `\n` with a visible separator in the journal and prefix continuation rows with a glyph on screen; filter the reader-mode compose echo.

## SM-C-21 Argon2 parameters are taken from `vault.json` and backup files without bounds

**Severity:** Low. A crafted backup handed to a user, or a modified copy of a real one, aborts the client on a multi-terabyte allocation.

**Location:** `crates/silver-client/src/vault.rs:237-243`, `backup.rs:103-109`.

**Description.** `Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, ..)` is built straight from the file; the `argon2` crate accepts `m_cost` up to `u32::MAX` KiB. The `kdf` block sits outside the AEAD.

**Recommendation.** Reject parameters above a ceiling (for example 1 GiB, 16 passes, 8 lanes) on read.

## SM-C-22 Passphrases and unwrapped secrets are not zeroised; an environment-supplied passphrase re-opens the lock by itself

**Severity:** Low.

**Location:** `crates/silver-tui/src/main.rs:176-198`, `608-611`, `633-639`; `crates/silver-client/src/keystore.rs:80`; `store.rs:891`, `1700`.

**Description.** `EnvSecrets.passphrase` is a plain `String` kept for the whole process so that `/lock` can re-unlock: with `SILVER_PASSPHRASE` set, both `/lock` and the idle lock drop the keys and immediately re-derive them with no interaction (the terminal test asserts this). `rpassword` returns plain strings that are never zeroised; the base64 key-encryption key is a plain string; `decode_file` copies zeroising buffers into ordinary vectors. On Linux the original environment block stays readable through `/proc/<pid>/environ` regardless of `remove_var` (shielded from same-user readers only by the non-dumpable flag, and never from root); macOS has no equivalent shield.

**Recommendation.** Hold passphrases in `Zeroizing<String>`, discard the environment passphrase after the first unlock unless explicitly asked to keep it, and prompt (or refuse `/lock` with an explanation) when only an environment passphrase exists.

## SM-C-23 The data key never rotates when the passphrase is changed or removed

**Severity:** Low.

**Location:** `crates/silver-client/src/store.rs:763-772`, `797-801`; `vault.rs:177-193`.

**Description.** Changing or removing the passphrase re-wraps the same data key. Any old copy of `vault.json` plus the passphrase in force at that time decrypts every file written since, including after the user "changed" the passphrase. Nothing in the documentation says so.

**Recommendation.** Offer (or default to) re-encryption under a fresh data key on passphrase change, or document the limitation.

## SM-C-24 No rollback binding for key-bearing files; history lines are not bound to their position

**Severity:** Low. Requires write access to a live directory (evil-maid), not the copy-only thief.

**Location:** `crates/silver-client/src/vault.rs:200-230`; `store.rs:1679-1694`.

**Description.** The AAD is the file name only: no counter, no cross-file MAC. An attacker with write access can restore an older `sessions.json` or `prekeys.json` (re-using ratchet state, so the next send reuses a message key), an older `contacts.json` (reverting a key-change warning or a `verified` mark), or drop, reorder or duplicate history lines (removing an `edit` or a tombstone) undetected.

**Recommendation.** Bind a monotonic generation into the AAD of the key-bearing files and check it on load; for history, include the line index in the AAD or periodically seal a manifest.

## SM-C-25 An encrypted data directory still leaks the contact graph and message lengths

**Severity:** Low (documentation).

**Location:** `crates/silver-client/src/store.rs:1679-1685`.

**Description.** History files are named `history/<user id>.jsonl` and `history/group-<id>.jsonl`; a directory listing plus modification times gives every contact and group and their activity times, and each encrypted line's base64 length gives the plaintext length within a few bytes. The threat model says a thief of the directory alone "gets nothing readable".

**Recommendation.** Name history files by an HMAC of the id under the data key (or keep a random map inside an encrypted index) and pad lines; or document the leak.

## SM-C-26 Two UI heuristics let peer text pass as something else

**Severity:** Low.

**Location:** `crates/silver-tui/src/app.rs:161-165` (`is_note`), `1522` and `terminal.rs:72` (paste handling).

**Description.** A one-to-one line is treated as a conversation note purely because its text starts with `"· "`: a received text `· alice revoked her identity` is dimmed like a note, loses its author in reader mode, is skipped by `/reply`, `/react`, `/edit`, `/delete`, and is attributed to the group by `/search`. Separately, on terminals without bracketed paste (the Linux console, older Windows consoles, some multiplexer setups) each pasted line arrives as a keystroke sequence ending in Enter, so a pasted `hello\r/revoke confirm\r` executes the command, and the destructive commands accept their confirmation on the same line.

**Recommendation.** Add an explicit `note` flag to history entries set only by the note writers; treat a burst of key events containing Enter within a few milliseconds as a paste; require a separate interactive keystroke for `/revoke`, `/rotate` and `/devices leave`.

## SM-C-27 Smaller client items

**Severity:** Informational. Grouped for brevity.

- **False fork after a long absence**: peer heads below the last 4,096 entries are checked against every-256th checkpoints, so a genuine head that is not on a checkpoint after the log grew by more than 4,096 entries is reported as a fork against the contact (`tail.rs:230`, `transparency.rs:398`).
- **`silver.log`** is outside the data key, never rotated, not wiped by `wipe()`, and at `debug` level records envelope ids, contact ids, the relay URL and relay error strings; the ASVS self-assessment says it gets "sanitised aliases only" (`main.rs:427-441`).
- **`observe_relay`** sends the WebSocket upgrade despite its comment saying nothing is sent (`tls.rs:203-206`, `connection.rs:3145-3151`).
- **No single-instance lock** on the data directory: two clients interleave appends and race on the shared `.tmp` name (`store.rs:1750`).
- **Invite and group links** accept any relay string, unbounded and unvalidated (no scheme check), and the client prints a copy-pasteable `/relay <string>` suggestion even for `ws://` (`invite.rs:68-74`, `app.rs:2219-2228`).
- **Reader mode on lock** prints the remaining journal and leaves the whole conversation in the scrollback while "locked" (`reader.rs:84-95`, `main.rs:527-537`).
- **Relay-controlled error strings** (`Error`, `Disconnected`, `Rejected` reasons) reach the System pane and the log unfiltered; screen cells are filtered but a `\n` yields the System-pane line forgery above, and `tracing_subscriber::fmt` does not escape newlines.
- **`/add <id> <alias>`** stores the alias unsanitised; harmless because every display goes through `printable`.
# 8. Findings: groups, devices and linking (`silver-client/groups`, `devices.rs`, `linking.rs`)

The MLS integration is careful where the specification is explicit: the ciphersuite is pinned at every entry point, only private messages are accepted (so external commits and proposals cannot arrive), the required capabilities are re-checked per commit, every added leaf and every leaf in a Welcome's tree goes through the identity rule, membership rules are evaluated with the committer's identity from the MLS sender against the pre-commit context, and the sequencer token is an exporter output whose hash is compared in constant time. The findings are in the places the specification is silent or optimistic: what a member can make other members *hold*, whose word a newly linked device takes, what happens on the honest leave path, and which leaves are never validated.

## SM-G-01 A member can force every other member to download 16 MiB per envelope and to hold up to 256 MiB of unauthenticated handshake bytes on disk

**Severity:** High. One hostile member, one upload; hits every member and every group's persistence; repeatable indefinitely.

**Location:** `crates/silver-client/src/groups/mod.rs:1614-1652` (`frame`, parks up to `MAX_FILE_BYTES`), `1926-1947` (held queue), `587-593` (`persist`); `crates/silver-protocol/src/group.rs:157-168` (`BlobRef::validate` accepts `size <= MAX_FILE_BYTES`); TUI `app/groups.rs:1227-1238` (unconditional fetch of every parked body).

**Description.** A group body may park its MLS message in the blob store up to the file limit of 16 MiB. The TUI fetches every parked body it is told about, deduplicating by envelope id only, never by blob id. A handshake message whose plaintext epoch header is ahead of the group's epoch is held verbatim in `record.held` (bounded by count, 16, and time, 10 minutes, never by bytes); `Held.mls` is base64-serialised inside `groups.json`, which, together with the whole `groups.mls` map, is rewritten on every `receive` and `send` in *any* group.

**Attack.** A member uploads one 16 MiB blob containing a `PrivateMessage` whose plaintext header says `content_type = commit`, `epoch = e+1…e+16` (both are unauthenticated header fields; nothing needs to decrypt for the message to be held) and sends N envelopes referencing it as `kind: handshake`. Each victim downloads 16 MiB per envelope (a full mailbox of 1,000 envelopes is 16 GB of transfer), holds 16 × 16 MiB in memory, and base64-serialises ~341 MiB into `groups.json` on every subsequent group event for ten minutes; atomic writes double the disk footprint. The documented "a rogue member can wedge a group" does not cover bandwidth and disk exhaustion of every member's client.

**Recommendation.** Never hold parked messages (hold only inline-sized ones, ≤ 24 KiB); cap total held bytes; fetch a blob at most once per blob id; cap handshake blobs well below the file limit (a 256-member Welcome is about 700 KB per §13.10).

## SM-G-02 A newly linked device accepts a Welcome for an "expected" group from anyone who declares themselves admin, and the real Welcome is then refused

**Severity:** High. A former member or anyone who ever held an invite link knows the group id; the device is silently placed in an attacker-controlled group under the real group's name and alias, and the primary's genuine Welcome is refused as "a group we are in".

**Location:** `crates/silver-client/src/groups/mod.rs:1755-1782`; `linking.rs:350-362`, `mod.rs:665-681` (`expect_groups`); `docs/PROTOCOL.md` §14.6–14.7.

**Description.** The admin check reads the Welcome's *own* `silver_group` extension, which the Welcome's author built, so "is an admin" is self-asserted. `expected` (populated from the link-time snapshot) is satisfied by the *first* Welcome for that group id, whoever sent it:

```rust
if !inviter_in || !(extension.is_admin(&inviter.account) || inviter.account == me) { ... }
let expected = self.file.expected.remove(&group);
let ours = inviter.account == me;
let taken = asked || expected.is_some() || ours;
```

The device then holds the group as `Active` with the snapshot alias, and the primary's genuine Welcome hits the "a Welcome to a group we are in" refusal. The race window is real: the primary retries the device's key package every 5 s up to 12 times; the attacker needs the same key-package hand-out and can be first, and the new device's id is public in the account's device list.

**Recommendation.** For `expected` groups require `ours` (the account's own identity as inviter, which §14.7 already says is who adds a new device); use `expected` only for the alias. More generally, never derive admin status from the Welcome's own extension when deciding to auto-accept.

## SM-G-03 Honest leaves break the group

**Severity:** Medium. Availability on the ordinary path; every member marks the group broken and blames an honest member; also usable as a stealthy targeted wedge.

**Location:** `crates/silver-client/src/groups/mod.rs:1305-1319` (`stage`), `1445-1452` (`leave`), `2022-2041` (stored leave proposals), `2510` and `2557` (`check_commit`); OpenMLS 0.9.0 `commit_builder.rs:125-128` (`consume_proposal_store: true` by default).

**Description.** OpenMLS's commit builder consumes the stored proposal queue by default, and every member stores a leaver's by-reference Remove. Three consequences:

- (a) A non-admin whose weekly self-update (or own-device add) fires while a leave proposal sits in its store produces a commit that carries the leaver's Remove; every receiver applies the rule `!admin && removed.any(|who| who != committer)` and marks the group `Broken { by: <honest non-admin> }`. The design document explicitly intends to allow "Remove proposals it merely references that were made by the members they remove".
- (b) `leave()` lets an admin leave when other admins exist; the co-admin's automatic self-update commit does not change the extension, so `after.admins` still names the leaver, the "admins must be members" rule fails, and the group breaks blaming the honest co-admin. The tests exercise only a non-admin leaving.
- (c) Targeted variant: a member sends its leave proposal to one non-admin only; that member's next commit references a proposal the admins never received, fails staging at the admins (`MissingProposal`), and the sequencer has moved on: the group silently desynchronises, misattributed.

**Recommendation.** In `check_commit`, allow a by-reference Remove whose proposal sender equals the removed leaf for any committer; when committing a leave, drop the leaver from `admins` in the same commit (or tolerate an admin removed by its own proposal); for non-admin self-updates, build with `consume_proposal_store(false)` unless every stored proposal is a self-remove.

## SM-G-04 The committer's update-path leaf and Update proposals are never validated

**Severity:** Medium. A member can make its own leaf unverifiable (wedging the group and blaming the next committer) or swap its credential to another identity it controls.

**Location:** `crates/silver-client/src/groups/mod.rs:2478-2481` (only `add_proposals()` are checked), `2081-2083`, `2101`; OpenMLS exposes `StagedCommit::update_path_leaf_node()` and `update_proposals()` and does not bind a new leaf's credential to the old one.

**Description.** (a) A member self-updates with a leaf lacking `silver_seal` or carrying a broken `silver_device`. The merge succeeds, then `members_of` errors, so `receive` returns an error, the record is not updated, and the merged MLS state is persisted by the next unrelated write; from then on every `leaves_of` fails, so the next commit from any honest member yields `Broken { by: <honest committer> }`, and all of the rogue member's messages become errors rather than refusals. (b) A member changes its credential to another identity it controls (self-consistent, no certificate needed): the change is read as an update, no rule fires, the shown membership now contains an identity no admin added, and `stage_remove(old)` fails with `NotAMember`.

**Recommendation.** Run the leaf rule on `update_path_leaf_node()` and every `update_proposals()` leaf; require the new leaf's `(account, device)` to equal the old leaf's; run `members_of` on the *staged* tree before merging, and on failure mark the group broken by the committer rather than returning an error.

## SM-G-05 Invitation flood: every Welcome from a stranger persists an MLS group, the last-resort key package allows unlimited Welcomes, and failed Welcomes leave orphan state

**Severity:** Medium. Denial of service by a stranger or a hostile relay; up to 256 signature verifications plus an X-Wing decapsulation per Welcome; unbounded disk growth with a full rewrite of `groups.mls` per persist.

**Location:** `crates/silver-client/src/groups/mod.rs:1780-1781` (`into_group` before `members_of`); OpenMLS `creation.rs:706` (last-resort package not deleted after use); TUI `app/groups.rs:1413-1424`.

**Description.** `staged.into_group` persists the group before the tree is verified; on failure the function returns an error, no record is created, and nothing ever deletes that group's storage entries. Invited groups are unbounded, each a full tree. Once the 20 one-time key packages are consumed (the relay hands out 30 an hour), the last-resort package remains reusable, so a stranger can build unlimited Welcomes for distinct group ids at no budget.

**Recommendation.** Cap held invitations (for example 20, oldest declined); delete the group on any failure after `into_group`; verify the tree before `into_group` where the API allows; rate-limit Welcomes from non-contacts.

## SM-G-06 A hostile contact can make the victim an admin of a crafted group and drive automatic admin actions without consent

**Severity:** Medium. Bandwidth and CPU amplification through the victim; a contact's invitation is auto-accepted.

**Location:** TUI `app/groups.rs:1389-1392` (auto-accept from a contact), `1442-1464` (`JoinRequest` → `stage_add`), `1477-1492` (`LeaveProposed` → self-update), `1493-1508` (`RejoinRequest` → `stage_rejoin`), `916` (timer re-send); `mod.rs:2179-2213` (any member's self-rejoin honoured).

**Description.** A Welcome from a contact is accepted with no prompt; the attacker's `silver_group.admins` can list the victim. Thereafter each one-envelope join or rejoin request makes the victim upload a commit plus a Welcome (about 700 KB for a large group as a blob) and seal up to 256 envelopes, repeatable for up to 256 identities and unlimited for rejoin spam.

**Recommendation.** Never act as admin automatically in a group where admin status was conferred by someone else's Welcome (or require confirmation on `JoinRequest`); rate-limit rejoin commits per member.

## SM-G-07 Whoever sees a device link can provision the device under their own account by racing the primary

**Severity:** Medium. Needs sight of the QR code or link within its ten-minute lifetime; the device then belongs to the attacker, shows the attacker's snapshot, and everything typed on it goes to the attacker's account and devices, while the real primary is told the device "belongs to an account already".

**Location:** `crates/silver-client/src/linking.rs:256-289` (`check`), `654-673` (`take_link`); `devices.rs:194` (`adopt`, single use).

**Description.** The new device accepts the first provisioning message that opens under the link key; `check` requires only that the claimed account equals the sealed sender and that the certificate for this device is signed by *that* account. The link is not bound to the intended account, and the device asks the user to confirm nothing.

**Recommendation.** Show the account id (or its safety number) on the new device and require confirmation before `adopt`; or let the user type the expected account id on the new device and include it in the provisioning AAD.

## SM-G-08 Leaves per identity are unbounded

**Severity:** Medium. Fan-out cost for everyone is per leaf; commits and Welcomes grow; a single member can bloat the tree with thousands of self-certified "device" leaves.

**Location:** `crates/silver-client/src/groups/mod.rs:2504`, `2560` (caps identities, not leaves), `1052-1055` (`stage_add`); `MAX_DEVICES` (8) is enforced only on one's own list in `devices.rs`, never on the tree.

**Recommendation.** In `check_commit` and `stage_add`, refuse more than `MAX_DEVICES` leaves per identity and cap the total number of leaves.

## SM-G-09 Sequencer recovery is documented but not wired

**Severity:** Low.

**Location:** `crates/silver-client/src/groups/mod.rs:989` (`sequencer_entry`), `1003` (`catch_up`), TUI `app/groups.rs:921-945`; `docs/PROTOCOL.md` §13.5.

**Description.** The engine's re-creation on `not_found` and token catch-up on a rewound relay have no caller in the TUI; both cases end in "try again". Combined with SM-R-08, a lost entry is seizable by anyone holding the group id.

**Recommendation.** Wire the two recovery paths; see SM-R-08 for the relay side.

## SM-G-10 An unauthenticated Welcome wipes an out-of-sync group's MLS state before any check

**Severity:** Low.

**Location:** `crates/silver-client/src/groups/mod.rs:1727-1739`.

**Description.** For a group in `OutOfSync` (and `Left`, `Removed`, `Broken`), `drop_state` runs before the Welcome is parsed or its sender checked, so any sender who knows the group id can delete an out-of-sync member's state (which could still have recovered from held messages) with a garbage `welcome` body.

**Recommendation.** Parse and verify the Welcome before dropping the old state.

## SM-G-11 Key-package deposits can be pushed over the relay's cap and stay refused for up to 90 days

**Severity:** Low.

**Location:** `crates/silver-client/src/groups/mod.rs:1555`, `1587`, `801-850`; relay `lib.rs:951-953`.

**Description.** Join and rejoin requests push extra packages into the deposit list; the deposit sends all of them and the relay refuses the whole batch above 30; the TUI just retries. A member who repeatedly drives a victim out of sync adds one package per cycle; after about ten cycles the victim cannot deposit until packages expire.

**Recommendation.** Trim the deposit to the cap before sending; drop request-only packages after use or after a day.

## SM-G-12 `receive()` persists only on success, so memory and disk diverge after any error following an MLS mutation

**Severity:** Low.

**Location:** `crates/silver-client/src/groups/mod.rs:1699-1717`, `2081`, `2101`, `1979`.

**Description.** A merge followed by a `members_of` error, or a message key consumed followed by a plaintext decode error, leaves the in-memory MLS state advanced but unpersisted; a crash restores a pre-commit or pre-consumption state (desynchronisation, or a re-delivered ciphertext decrypting again, with the `seen` dedup set also unpersisted).

**Recommendation.** Persist after every MLS mutation regardless of the outcome of the surrounding logic, or make the logic fail before mutating.

## SM-G-13 Smaller group and device items

**Severity:** Informational.

- **Sender ratchet configuration** is left at OpenMLS's default out-of-order tolerance of 5 generations; the design document says 64. Messages from one sender arriving more than five generations out of order are reported unreadable (`mod.rs:900-931`).
- **A linked device can pin bundles and set `verified`** on the primary through `sync contact`, and that state persists after the device is revoked (`app/devices.rs:834-871`, `899-903`). Consider restricting bundle pinning and verification to the primary.
- **Invite links** check duplicates at the device level (§13.7 says "not a member") and have no per-link use bound, so one link can add up to 256 identities, each costing the admin an automatic commit and Welcome (`mod.rs:2164-2168`).
- **`GroupEvent::Head`** is emitted for unaccepted invitations and blocked members, so a stranger may be able to raise a split-view alarm through the head-gossip path; not traced to a confirmed alarm.
# 9. Findings: deployment, packaging, CI/CD and supply chain

The build and release pipeline is above the norm for a single-maintainer project: every GitHub Action is pinned to a commit hash, workflow tokens are read-only except where publishing needs to write, binaries are built with `cargo auditable` and remapped paths, a reproducibility job rebuilds twice on every push, SLSA provenance attestations are published for every file and for the container image, `cargo deny` refuses unknown sources and licences, and every package manifest pins release archives by SHA-256. The dependency tree has no known vulnerability. The findings below are about the parts of the chain that are designed but not yet in place, and about defaults that are weaker than the documentation implies.

## SM-S-01 Releases are currently unsigned, and the designed signing key adds no independence from the GitHub account

**Severity:** Medium. The threat model claims the maintainer's signature leaves "a compromised GitHub account without the signing key nothing to offer"; today there is no signature, and by design the key will live inside GitHub.

**Location:** repository root (no `minisign.pub`); `.github/workflows/release.yml:289-311`; `README.md` "Signing releases" ("the key is generated unencrypted so the workflow can use it; the secret store protects it"); `docs/THREAT_MODEL.md` "Supply chain".

**Description.** The repository carries no `minisign.pub`, so the release workflow publishes `SHA256SUMS` unsigned (the workflow notices and says so). When the key is set up as documented, it is generated with `minisign -G -W` (no passphrase) and stored in the repository secret `MINISIGN_SECRET_KEY`, where any workflow run with access to secrets, any collaborator with the ability to run workflows, or an attacker with the maintainer's GitHub account can use it. The provenance attestation already says "GitHub built this from that commit"; a signature made by a key GitHub holds says the same thing again. The independent assurance the threat model describes (maintainer's key separate from the platform) does not exist in this design.

**Recommendation.** Sign release checksums out of band on a maintainer-controlled machine (or with a hardware key), publish `minisign.pub`, and document that the GitHub attestation and the maintainer signature are two *independent* roots of trust. Until then, correct the threat model and README so they do not describe a signature that is not published.

## SM-S-02 The Rust toolchain is not pinned, so reproducibility decays and verifiers must recover the compiler version from workflow logs

**Severity:** Low.

**Location:** `rust-toolchain.toml` (`channel = "stable"`); `.github/workflows/release.yml:65-68`; `README.md` "Verifying a release" ("with the same stable toolchain as the release (see the workflow run)").

**Description.** Byte-for-byte reproduction depends on the exact `rustc` version. "stable" floats, so a rebuild a month later uses a different compiler and different bytes. The reproducibility CI job compares two builds on the same runner minutes apart, which does not test this. A verifier must dig the compiler version out of the workflow run logs, which are retained for a limited time.

**Recommendation.** Pin `channel = "1.94.1"` (bumped deliberately), record the exact toolchain in the release notes and next to `SHA256SUMS`, and have the reproducibility job build once with the pinned toolchain from a clean container.

## SM-S-03 Installer weaknesses: `curl | bash`, unverified rustup bootstrap, plaintext transport by default without a domain, third-party IP lookup, and credentials in URLs

**Severity:** Low. Operator-facing defaults that are weaker than the documentation implies.

**Location:** `deploy/install.sh:14`, `98`, `113`, `133`, `170-177`, `311-312`.

**Description.**

- The documented invocation is `curl … | bash` of a script from `raw.githubusercontent.com` at `main`, which is neither pinned nor signed; the script itself installs Rust with `curl https://sh.rustup.rs | sh` with no checksum.
- Without `SILVER_DOMAIN` the installer configures `0.0.0.0:7777` and prints `silver --relay ws://<ip>:7777/ws`, a plaintext deployment; the README treats `wss://` as the default.
- It discovers the public address by calling `https://api.ipify.org`, telling a third party that this host runs the relay.
- It suggests `SILVER_REPO=https://<token>@github.com/…` for private repositories, placing a token in the git remote configuration on disk.
- `set_env` interpolates the domain into a `sed` expression with `|` as the delimiter and no escaping; a domain containing `|` or `&` corrupts the environment file (operator-supplied, so not an attack, but a footgun).

**Recommendation.** Publish the installer as a release asset covered by `SHA256SUMS` and instruct operators to verify before running; verify the rustup script's checksum or install Rust from the distribution; refuse to configure a plaintext listener on a non-loopback address without an explicit flag; drop the ipify call (or make it opt-in); document the token-in-URL risk.

## SM-S-04 The deploy workflow trusts the server's host key on first use every run

**Severity:** Low.

**Location:** `.github/workflows/deploy.yml:57` (`ssh-keyscan -H "$VPS_HOST" >> ~/.ssh/known_hosts`).

**Description.** The host key is fetched from the network on every run, so an on-path attacker between GitHub's runners and the VPS can present their own host key and receive the deploy session (the private key is not exposed by SSH authentication, but the attacker learns the deploy inputs and can fake success, and could serve a modified install script back if the flow ever pulled from the server).

**Recommendation.** Store the server's public host key as a repository variable and write it to `known_hosts` verbatim.

## SM-S-05 Container base images and CI containers are pinned by tag, not by digest

**Severity:** Low.

**Location:** `deploy/Dockerfile:23`, `27`, `32` (`rust:1.94-alpine`, `alpine:3.22`); `.github/workflows/ci.yml:133`, `144` (`debian:stable-slim`, `archlinux:base-devel`).

**Description.** A tag can be moved; a digest cannot. The reproducible-image claim ("a rebuild of the same release gives the same layers") holds only while the tags resolve to the same images. The CI containers only run tests, so their exposure is smaller.

**Recommendation.** Pin `FROM` images by `@sha256:` digest and bump them deliberately; the same for the images CI runs.

## SM-S-06 systemd hardening gaps

**Severity:** Informational. The unit is already well above average; these are the remaining directives a hardened service usually carries.

**Location:** `deploy/silver-relay.service`.

**Description.** Missing: `UMask=0077` (the backup unit has it; its absence is what opens the admin-socket window in SM-R-13), `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM`, `ProtectClock=true`, `ProtectHostname=true`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictRealtime=true`, `RestrictSUIDSGID=true`, `RemoveIPC=true`, `CapabilityBoundingSet` is correct but `AmbientCapabilities=CAP_NET_BIND_SERVICE` could be replaced with a socket unit or `net.ipv4.ip_unprivileged_port_start` where available. `systemd-analyze security silver-relay` will list the same.

**Recommendation.** Add the directives above and check with `systemd-analyze security`.

## SM-S-07 Dependency audit results and tree observations

**Severity:** Informational.

**Description.** `cargo audit` 0.22.2 against the RustSec database (1,239 advisories) over the workspace lockfile (619 crates) and the fuzz lockfile reports **no vulnerabilities** and one warning: `proc-macro-error2` 2.0.1 is unmaintained (RUSTSEC-2026-0173), pulled in by `hax-lib-macros` through the `libcrux` verified-crypto crates that back `hpke-rs`/OpenMLS. It is a build-time procedural-macro helper with no runtime exposure. The tree carries several duplicate major versions (`curve25519-dalek` 4 and 5, `x25519-dalek` 2 and 3, `rand` 0.8/0.9/0.10, `getrandom` 0.2/0.3/0.4, `tokio-tungstenite` 0.29 via axum and 0.30 directly, `hkdf`/`hmac`/`sha2` in two generations), which `cargo deny` only warns about; each duplicate is more code in the binary and more advisories to track. Two security-relevant crates carry "never independently audited" warnings (SM-P-13).

**Recommendation.** Consolidate versions where upstreams allow; consider raising `multiple-versions` to `deny` with explicit `skip` entries so new duplicates are noticed.

## SM-S-08 Fuzzing depth is one minute per target per push

**Severity:** Informational.

**Location:** `.github/workflows/ci.yml:284-318`.

**Description.** Nine targets, 60 seconds each with `-max_len=4096`, no persisted corpus (the corpus directory is git-ignored), no sanitiser coverage beyond ASan. A minute from an empty corpus explores little; the seeded random tests in the ordinary suite do more. The parsers are the right ones (frames, envelopes, sessions, blobs, links, file names, stored data, group bodies, device statements).

**Recommendation.** Persist the corpus as a CI artifact (or in a branch) and seed each run from it; run a longer job on a schedule; consider OSS-Fuzz or ClusterFuzzLite, and add a target for the base58/JSON frame path with large inputs (SM-P-02).

## SM-S-09 Release publishing details

**Severity:** Informational.

- `workflow_dispatch` with a `tag` input creates the tag and publishes a release from whatever branch is selected; anyone with permission to run workflows can publish a release from an arbitrary commit. Standard GitHub behaviour; worth restricting with an environment protection rule.
- The Homebrew CI job installs the formula from the *live* release named in the formula, so CI depends on GitHub's release hosting and on the previous release's archives.
- The release notes are generated from `CHANGELOG.md` plus GitHub's auto-generated notes; the auto-generated part includes PR titles from contributors, which reach users unreviewed.
- The packaging tarball's checksum is appended to `SHA256SUMS` before signing, which is correct; `packaging/update.sh` run by hand fetches `SHA256SUMS` over HTTPS without verifying the (future) minisign signature.
# 10. Privacy assessment

This section evaluates what each party learns, measured against the threat model's own statements, and records where the implementation gives away more than the document says. The design's privacy properties are strong for the content layer: the relay never sees a sender identity, a message body, a capability list, a receipt, or a file name, and the sealed-sender construction was verified to hide the sender from the relay in every body version.

## 10.1 What the relay learns (metadata)

| Data | Documented? | Observed in code | Assessment |
| --- | --- | --- | --- |
| Recipient id, timing and 160-byte size class of every envelope | Yes | `route`, `enqueue` | As documented. |
| Which connection submitted an envelope (address, timing) | Yes | Anonymous connection by default; silent fallback to the authenticated connection | The fallback is undetectable by the user (SM-C-16). A Tor user whose relay withdraws `anonymous_send` is deanonymised without notice. |
| Device names | Yes | Certificates in the bundle | As documented; names like "office laptop" are public to anyone who looks the account up. |
| Per-identity publish timestamps, forever | Partly | Transparency log `at_ms`, never pruned, served to any authenticated client | The log is a permanent public activity timeline per pseudonymised subject; a contact who knows the id de-pseudonymises it. Should be stated beside the journal-pseudonym claim. |
| Group epoch counter and timing, group id | Yes | Sequencer entries | `Exists(epoch)` also answers a non-member who knows the id (SM-R-08). |
| Which identity fetched whose key package | Yes | Authenticated connection | As documented. |
| Failed-login addresses | Yes | Logged at warn after 20/hour; evictable by address churn | As documented. |
| Full user ids in the operator's view | No (pseudonyms promised) | `unban` error prints the raw id; ban keys and backups hold raw ids | Minor leak against the operator's own privacy design (SM-R-13, backup contents). |

## 10.2 What a network observer learns

Over `wss://` the observer sees the relay host, traffic volume and timing. Two implementation gaps widen this:

- **Pinning is bypassable** by an observer who can obtain a locally trusted certificate for the relay name (SM-C-01), which is the corporate-proxy case the threat model names as the reason for pins.
- **The release check leaks the user's address to GitHub directly** even when the user routed the relay through Tor (SM-C-09).

The "once `wss://`, never `ws://`" rule was verified to be per normalised host and enforced on every relay change path, including links; a link can still name a different host on `ws://`, which the client suggests rather than refuses.

## 10.3 What a contact, a group member or a stranger learns

- A contact learns delivery and (unless disabled) read timing, with the documented random delays; verified.
- A group member learns the member list and everything said; verified, and group messages are non-deniable by design.
- A stranger learns the number, ids and names of a person's devices from the bundle; verified.
- A stranger can cause the client to display a *contact's* name in a warning ("a message from X could not be read", SM-C-13), which is a small information-free but manipulable channel.
- A stranger's Welcome consumes the victim's key package and persists a full MLS group on the victim's disk before any decision (SM-G-05).

## 10.4 Data at rest on the client

The at-rest design (random data key wrapped by the OS key store or by Argon2id, XChaCha20-Poly1305 per file with the file name as associated data, history encrypted line by line) is sound. Deviations from the "with the data directory alone they get nothing readable" claim:

- Three files, including the MLS group secrets, are left in plaintext when protection is added to an existing directory (SM-C-02).
- History file names expose the full contact and group list, modification times expose activity, and line lengths approximate message lengths (SM-C-25).
- On a machine without a key store and without a passphrase (the headless-Linux case) everything is plaintext and, at the modes used, readable by any local user; `config.json` then exposes proxy credentials and the invite token (SM-C-10).
- Received files are plaintext by default, as documented; the option to keep them encrypted is undermined for other purposes by SM-C-12.
- Changing the passphrase does not rotate the data key (SM-C-23), and the log file is outside the data key (SM-C-27).

## 10.5 Data at rest on the relay

The database holds ciphertext, public bundles, key packages, the transparency log, bans and the invite token. Backups are integrity-checked but not encrypted or authenticated and contain the invite token and raw ids (SM-R-13 group). The TLS private key and ACME account live in files at mode 0600 in a 0700 directory, verified.

## 10.6 Deletion and retention

- "Delete for everyone" and disappearing timers are enforced by the other side's software only; the documentation says so clearly and the implementation matches: history files are rewritten without the entry rather than marked, verified.
- Tombstones for unknown ids, non-author edits and reactions are appended permanently (SM-C-19), which is a retention leak of the *fact* that a peer named an id, and a growth vector.
- Relay-side retention is 30 days for envelopes and blobs, verified; there is no way for a user to delete their identity from a relay, as the assessment already notes.

## 10.7 Telemetry and phone-home

The client contacts only its relay and, on explicit request, `api.github.com`; no telemetry exists, verified by reading every network call site. The relay contacts only the ACME directory. The installer contacts `api.ipify.org` (SM-S-03).
# 11. Controls verified as correctly implemented

A security audit that reports only defects misrepresents a codebase. The following documented claims were traced to the code and found to hold. File and line references are to the audited commit.

## 11.1 Cryptography (`silver-protocol`)

- **Domain separation.** Every signature is over `domain || 0x00 || message`; all thirteen domain strings are distinct, NUL-free and none is a prefix-plus-NUL of another; MLS leaf signatures use OpenMLS's own labels, so there is no cross-protocol overlap (`identity.rs:204-210`).
- **Strict Ed25519 verification** everywhere (`identity.rs:48-51`); small-order keys are rejected at verification.
- **Contributory X25519** checks on every shared secret: envelope seal and open, all four X3DH terms, every ratchet step (`envelope.rs:687, 783`; `session.rs:275, 575, 610, 679-683`).
- **Sealed envelope**: fresh ephemeral per envelope, HKDF info bound to both public keys, AAD binds recipient and ephemeral, signature covers recipient, ephemeral, nonce and body; the deniable-body decision is keyed off the version field inside the AEAD so a relay cannot strip a signature check (`envelope.rs:672-733, 771-843`). The vectors and a property test pin re-addressing and tampering.
- **X3DH/PQXDH**: 0xFF prefix, zero salt, versioned info; ML-KEM secret mixed into the same KDF; session id from ephemeral and signed prekey; AD binds both identities and both DH keys (`session.rs:672-738`).
- **Double Ratchet**: HKDF root chain, HMAC message chains with distinct constants, 56-byte key-and-nonce expansion, skip limit 1,000, stored-key cap 2,000 with oldest-first eviction, trial decryption on a clone so a forged message leaves state untouched, skipped keys removed only on successful decryption (`session.rs:436-642`).
- **Post-quantum ratchet**: ML-KEM step beside every DH step, bootstrap chains DH-only as specified, header KEM fields inside the AAD (`session.rs:561-642`).
- **Signed prekey age**: 21-day cut-off before use; one-time prekeys deleted only after a successful decryption (`sessions.rs:397-406, 497-505`).
- **Bundle verification** covers the DH key, the signed prekey, every ML-KEM key (length-checked before the signature), the capability list, the device list (cap 8, strictly ascending, certificates verified against the account before the list signature) and `device_of` (`bundle.rs:96-135`, `device.rs:237-258`).
- **Transparency log**: fixed-width entry hash, explicit presence bytes and length prefixes in the bundle leaf, checkpoints and chain verification, fork and rewind detection (`transparency.rs:130-140, 175-244, 298-320`); the layouts match the vectors byte for byte.
- **Lifecycle statements**: revocation self-signed, succession cross-signed with `old != new`, revocation final at the relay and the client (`lifecycle.rs`, `relay/lib.rs:1129-1157, 1283-1359`).
- **Blob chunks**: per-file key and nonce, index XORed into the nonce, AAD binds blob id, index and count, size and count validated before any fetch, SHA-256 over the truncated plaintext last (`blob.rs:55-130`; `files.rs:172-188, 276-297`).
- **Invite links and join proofs**: link key and proof derived by HMAC and bound to group and joiner, compared in constant time; sequencer token stored as its hash (`group.rs:509-544`).
- **Parsers** are typed serde structures with fixed-size byte arrays, the default recursion limit, and no `unwrap`, `expect` or unchecked slice on peer data in the protocol crate; nine fuzz targets cover every peer-facing parser.

## 11.2 Relay

- Challenge nonce: 32 bytes from `OsRng`, single use; a second `auth` is refused; anonymous connections confined to five frame types plus `ping` (`lib.rs:1913-1995, 2124-2169`).
- `publish` requires `bundle.user_id == me` and a valid signature; revoked identities and devices refused; invite token compared in constant time; identity cap and per-address registration budget enforced before storing (`lib.rs:1582-1662`).
- `ack` verifies mailbox ownership; duplicate envelope ids are deduplicated, never overwritten; per-recipient caps checked inside the write transaction (`store.rs:1548-1603`).
- One-time prekey hand-out is budgeted per target and performed in one write transaction that removes the key and records it as used; only connections that published prekeys receive one (`lib.rs:1710-1733, 2211-2215`).
- Blob ids are 32 hex characters; `total` fixed by the first chunk; caps enforced transactionally; partial blobs accounted and expired; incomplete blobs never served (`store.rs:892-994`).
- Sequencer: first committer wins; constant-time token comparison; documented rejection codes (`store.rs:1420-1480`).
- Every logged change is appended in the same transaction as the write; an unchanged republish adds nothing; `log_since` pages by 256 with saturating arithmetic (`store.rs:239-282, 996-1042`).
- X-Forwarded-For honoured only from loopback or listed proxies, last element taken (`lib.rs:567-587`).
- Identities appear in logs as per-run salted pseudonyms unless `--log-ids`; the invite token is never logged; addresses only at debug or after 20 failures (`lib.rs:538-548, 829-833`).
- Data directory 0700, database 0600, ACME cache 0700 with 0600 files written through temp-fsync-rename, admin socket 0600 in a 0700 runtime directory, backups 0600 and verified before rename (`store.rs:431-441`, `acme.rs:125-156`, `admin.rs:309`, `backup.rs:1021-1050`).
- TLS: 1.2 and 1.3 only, AEAD suites, no client auth, ALPN restricted to `acme-tls/1` and `http/1.1`, 0-RTT off; the challenge certificate is served only for the ACME ALPN with a matching SNI and carries the critical `acmeIdentifier` extension; the ACME key is generated once and reused so pins stay stable; the directory is HTTPS-only; a cached certificate is installed before the CA is contacted and failures back off up to 12 hours while the old certificate keeps serving (`tls.rs:120-176`, `acme.rs:66-119, 158-171, 244-260`).
- Backup format: length-prefixed fields capped at 16 MiB, header capped at 4 KiB, unknown tags refused, nothing committed unless the whole file reads; restore moves the old database aside and rolls back on failure; no paths in the format (`backup.rs:37-38, 407, 843-898, 995-1150`).
- Metrics: off unless configured, `GET /metrics` only, addresses never emitted, label escaping, tracked addresses bounded (`metrics.rs:36-142, 329-343`).
- Poisoned mutexes are recovered everywhere; store calls handle every error as a `Result`.

## 11.3 Client library

- v1/v2 sealed-layer signatures are verified against the sender id inside the plaintext before any body processing, and that same id is used for attribution (`envelope.rs:808-832`, `connection.rs:2803`).
- A stranger using a contact's id as the sealed-sender hint cannot complete a handshake (DH1 needs the contact's DH secret); a failed decryption leaves state and one-time prekeys untouched (`session.rs:375, 476`; `sessions.rs:497-505`).
- Init is ignored when the session already exists and the session id must match the handshake; at most five sessions per peer with LRU among inactive ones; the crossed-start tie-break works as specified (`sessions.rs:441-558`).
- Sequence numbers are checked per contact and per device; capabilities are recorded only from authenticated messages; receipts go only to accepted contacts; strangers are held under the documented caps; blocked ids are dropped first; cover traffic goes only to contacts whose last message advertised it and only while connected (`app.rs:277-282, 3187-3231, 4110-4130`; `cover.rs`).
- Transparency: an answer without a head is refused; answers are held until the log is replayed to their head; the served leaf must be the latest logged; withheld revocations and successions are detected; device bundles are checked individually; peer heads below the head are verified through checkpoints or a fetched segment (`tail.rs:161-236`; `transparency.rs:297-380`).
- At rest: random 256-bit data key; XChaCha20-Poly1305 with a fresh random nonce per seal; Argon2id 64 MiB / 3 passes / 16-byte salt; empty passphrase refused; wrapped key bound with its own AAD; every file bound to its relative name so files cannot be swapped; key-bearing files written 0600 through temp-fsync-rename; appends repair a cut line; the kill test covers plain and passphrase modes (`vault.rs:52-72, 123-264`; `store.rs:1284-1288, 1679-1694, 1761-1778`).
- Passphrases are read with echo off and three attempts; `SILVER_PASSPHRASE` is removed from the environment before any thread exists; core dumps are disabled and the process is non-dumpable on Linux (`main.rs:176-220, 608-623`).
- File names: last path component only, control, format, bidi and zero-width characters removed, NFC, Windows-reserved characters and device names handled, 120 characters with the extension preserved, idempotent, fuzzed; saves use exclusive create so nothing is overwritten or followed; quota checked before the name is claimed; the opener is invoked without a shell with a `./` or `--` guard; mark-of-the-web set on Windows for plain saves (`files.rs:317-533`).
- Update check: HTTPS to a fixed URL, chain-verified, 256 KiB cap, 20-second timeout, only two JSON fields used, nothing downloaded or executed, never automatic (`update.rs:26-137`).
- TLS: webpki roots plus the native store plus `--ca-cert`; the pinned verifier runs full chain validation first; the anonymous connection disables resumption; SNI is the URL host (`tls.rs:193-268`).
- Proxies: SOCKS5 sends the relay name to the proxy (no local resolution) with fresh random credentials per connection for Tor stream isolation; HTTP CONNECT validates the status and caps the head; no path ever falls back to a direct connection when a proxy is configured (`proxy.rs:137-272`; `connection.rs:3160-3192`).
- Links never switch the relay by themselves; `/relay` enforces the no-downgrade rule per normalised host (`app.rs:2219-2228, 2613-2640`; `devices.rs:232-242`).
- `sync` content is accepted only from certified devices of one's own account, `sync devices` only from the primary, and a linked device cannot link, revoke or rename; provisioning uses HKDF and an AAD bound to the device id (`connection.rs:3020-3056`; `devices.rs:151-333`; `device.rs:263-344`).
- Groups: ciphersuite pinned at every entry point; pure-ciphertext wire format so external proposals and commits cannot arrive; required capabilities re-checked per commit; every added leaf and every Welcome tree leaf verified; rules evaluated with the committer from the MLS sender against the pre-commit context; only a leaf's own Remove is stored by reference; a rule violation marks the group broken naming the committer; a foreign commit clears a pending one; edits and deletions apply only to the MLS sender's own messages; timers in groups only from admins (`groups/mod.rs:863-931, 1727-1782, 1963-2077, 2352-2382, 2478-2560`; `everyday.rs:652`).

## 11.4 Terminal client

- Every pane renders through ratatui's buffer, which drops any grapheme containing a control character and any of width zero; a test drives the real crossterm backend with hostile text and asserts nothing unescaped reaches it (`ui.rs:1129-1244`).
- The terminal title carries no peer text; desktop notifications carry only a sanitised name and never message content, and use terminal escapes rather than external commands (`notify.rs:82-123`).
- Nothing is copied to the clipboard without an explicit action; the device link secret is only ever printed, never copied.
- The single `unsafe` block runs as the first statement of `main`, before the runtime and the input thread; no other environment mutation exists in the workspace (`main.rs:182-207`).
- The lock consumes the application, dropping the store cipher, the identity, sessions and every screen buffer before the passphrase prompt; a panic hook restores the terminal in both modes, tested (`main.rs:526-542`; `terminal.rs:56-62`).
- Memory bounds exist for conversation lines, system lines, late updates, known ids, input history and stranger requests (`app/bounds.rs`).

## 11.5 Build, release and repository

- Every action pinned by commit hash; read-only tokens except in the publish job; `cargo deny` with `unknown-registry`/`unknown-git` denied; `cargo audit` on every push; reproducible build job; `cargo auditable` binaries; CycloneDX SBOMs; SLSA attestations for files and image; packaging manifests pin archives by SHA-256; no secrets in the git history (scanned); `forbid(unsafe_code)` in three crates and `deny` with one documented `allow` in the fourth; `overflow-checks` on in release.
# 12. Discrepancies between the documentation and the code

The project's documentation is unusually precise, which makes the places where it and the code disagree worth listing. Each row names the document, what it says, and what the code does. Where a discrepancy is also a finding, the finding id is given.

| Document | Statement | Code | Finding |
| --- | --- | --- | --- |
| PROTOCOL §14.2, relay comment | "otherwise any account could cut off any identity by calling it a device of its own" is given as the reason for the check | The check trusts the account's own signed list; the attack is possible | SM-R-01 |
| PROTOCOL §14.2 | A device revocation is "trusted however it arrived" | Neither spec nor client binds it to the device's real account | SM-P-01 |
| PROTOCOL §7.1, THREAT_MODEL, ASSESSMENT 2.9.3 / 3.2 | "a relay in the middle cannot forward a challenge from another relay and use the answer there" | Host is taken from the attacker-controlled request header; the client downgrades when `bound` is absent | SM-R-02, SM-C-04 |
| THREAT_MODEL "Network observer" | With a pin "the connection fails loudly instead of going through the proxy's certificate" | A pin matches any presented certificate, so an appended genuine leaf passes | SM-C-01 |
| THREAT_MODEL "Device thief"; `vault.rs:5-6` | "every file is encrypted under a key that only the passphrase unlocks" | `groups.json`, `groups.mls`, `revocation.json` are not re-encrypted when protection is added | SM-C-02 |
| README `--remove-passphrase` | Files "are stored unencrypted otherwise" | Three files become unreadable instead | SM-C-02 |
| THREAT_MODEL "Device thief" | "With the data directory alone they get nothing readable" | History file names reveal every contact and group; line lengths approximate message lengths | SM-C-25 |
| PROTOCOL §8 | "0.10.0 refuses to send [v1]" | v1 is sent to a peer without prekeys, and the e2e test asserts it | SM-C-03 |
| PROTOCOL §11.4; TUI | "nothing is sent with the key" after a transparency refusal | The message is sent with the pinned bundle | SM-C-06 |
| THREAT_MODEL "Compromised identity key" | "Contacts see the published key change (loudly)" | Not on the receive path: an inbound init with a different DH key is accepted silently | SM-C-07 |
| THREAT_MODEL "Compromised long-term DH key" | Lists only decryption consequences | From v4 the DH key alone suffices to impersonate | SM-P-04 |
| PROTOCOL §2 | Caps signature: "the relay cannot add or strip one undetected" | The newline join is not injective; merging strips undetected | SM-P-03 |
| THREAT_MODEL "Stranger" | "mailboxes, file storage and the number of identities are capped" | No global mailbox cap; recipients need not exist | SM-R-04 |
| ASSESSMENT 2.2.1 | "a 10-second authentication timeout" | Starts only after the WebSocket upgrade; no pre-upgrade timeout | SM-R-03 |
| ASSESSMENT 1.1.6, 11.1.3 | Every action rate-limited | `publish` and `ack` have no bucket | SM-R-05, SM-R-06 |
| ASSESSMENT 5.4.x | "size arithmetic uses saturating or checked forms" | `entry.epoch += 1` is unchecked and peer-reachable | SM-R-09 |
| ASSESSMENT 7.3.1 | "no user-controlled text reaches the relay log"; "the client log gets sanitised aliases only" | serde error text logged verbatim; the client log holds ids, the relay URL and relay error strings | SM-R-12, SM-C-27 |
| ASSESSMENT 7.4.3, Gaps table | "installs no panic hook … next TUI pass" | Stale: a hook exists and is tested | — |
| ASSESSMENT 3.7.1, 8.3.6; THREAT_MODEL | `/lock` asks for the passphrase again; passphrases are zeroised | With `SILVER_PASSPHRASE` the lock re-opens itself; TUI passphrase strings are never zeroised | SM-C-22 |
| ASSESSMENT 6.4.2; `main.rs:173-175` | "no other reader of the environment sees them" | The exec-time environment block is not scrubbed; shielded on Linux by the non-dumpable flag only, not from root; macOS unshielded | SM-C-22 |
| THREAT_MODEL "Malicious contact" | "messages are cut at 4000 characters" | Only strangers' held messages; contact and group texts are bounded by the 32 KiB body | — |
| THREAT_MODEL; ASSESSMENT 5.3.1 | "everything shown is passed through the terminal-safety layer" | Clipboard, text export, release-check output and the reader-mode compose line are outside it | SM-C-20 |
| PROTOCOL §14.6–14.7, design/devices 6.3 | A Welcome "for a group the primary named at link time is taken without asking" | Taken from any self-declared admin, not only the account | SM-G-02 |
| design/groups 7.6, PROTOCOL §13.7 | A non-admin may carry referenced self-Removes; an admin may leave with co-admins | Both produce commits every member refuses | SM-G-03 |
| PROTOCOL §13.1 | Leaves refused "wherever a leaf is seen" | Not the update-path leaf or Update proposals | SM-G-04 |
| PROTOCOL §13.7 | "every member's leaf in the tree" verified on Welcome | Verified after `into_group`; a failure leaves orphan state | SM-G-05 |
| PROTOCOL §13.5 | Re-creation on `not_found` and token catch-up on a rewound relay | Exist in the engine; no caller in the TUI | SM-G-09 |
| PROTOCOL §13.5 | Counter scrambling attributed to the relay only | Any holder of the group id can seize an absent entry | SM-R-08 |
| PROTOCOL §13.2 | `mls` inline "when the message is at most 24 576 bytes" | Only ~24,411 bytes actually encode; `validate` allows up to the body cap | SM-P-05 |
| PROTOCOL §14.6 | Provisioning plaintext "at most 8 MiB" | Effective cap ~18–24 KB | SM-P-11 |
| PROTOCOL §13.3 vs §14.4 | Group ids "1 to 64 bytes"; copy ids "printable ASCII" | The two rules differ | SM-P-09 |
| PROTOCOL §14.1 | The device-list signature "covers the set" | Covers `(device, created_at_ms)` only, not certificates | SM-P-07 |
| PROTOCOL §4.7 | Pending edits and tombstones "kept for a day" | True in memory; permanent on disk | SM-C-19 |
| PROTOCOL §13.4 | A key package's private half "is deleted when a Welcome uses it" | Not the last-resort package (by design, unstated) | SM-G-05 |
| design/groups 4.4 | Out-of-order tolerance 64 | OpenMLS default 5 | SM-G-13 |
| THREAT_MODEL "Supply chain"; README | `SHA256SUMS` "is signed with the project's minisign key"; a compromised account "without the signing key" gains nothing | No `minisign.pub` exists; the designed key lives unencrypted in GitHub Secrets | SM-S-01 |
| OPERATING.md §metrics | `silver_relay_refused_total{reason}` includes `login` | Only `connection`, `registration`, `upload` are emitted | — |
| OPERATING.md, THREAT_MODEL, `backup.rs` | A backup holds "ciphertext, public keys, bans (counters)"; "checked before it is trusted" | Also the invite token, usage, full ids in ban keys; the trailer is a plain SHA-256 (corruption, not tampering) | SM-R-13 |
| OPERATING.md §pseudonyms | The full id is "something you get from the person, not from the relay" | `unban` error prints the full id | SM-R-13 |
| `update.rs:8-11` | The release check uses "the same … proxy" as the relay connection | Only a CLI or environment proxy; the remembered one is ignored | SM-C-09 |
| `tls.rs:203-206` | `observe_relay`: "nothing is sent over the connection" | The WebSocket upgrade request is sent | SM-C-27 |
| `connection.rs:69` | `Undecryptable`: the envelope "was authentic" | Not for v4/v5 bodies | SM-C-13 |
| TERMINALS.md | Pasted text arrives "one message per line" | Lines beginning with `/` run as commands | SM-C-26 |
| PROTOCOL §7 `auth.host` | "lower case, without port or IPv6 brackets" | Also trims whitespace and a trailing dot (harmless, undocumented) | — |
| PROTOCOL §3 | "body at most 32 768 bytes" | Effective pre-padding maximum is 32,640 | — |
# 13. Prioritised remediation plan

The order below weighs severity against the effort of the fix and the number of findings a single change closes. Items in the first group are small changes with large effect and should ship as a patch release; the second group belongs to the next minor release; the third is design work for 1.0.

## 13.1 Patch release (days)

1. **Bind device revocations to the device's real account, at the relay and in the client** (SM-R-01, SM-P-01). Relay: refuse a device list that names an id which has a bundle not carrying this account's `device_of`; require `claims_me`, or `listed` with no bundle of the device's own, in `apply_device_revocation`; add an admin `unrevoke-device`. Client: accept a revocation only when `account` matches the account whose signed list contains the device. Two tests: a foreign identity listed as a device; a foreign-account revocation delivered to a contact.
2. **Verify the bound login against a configured host set, not the request header, and stop the client's fallback** (SM-R-02, SM-C-04). Relay: derive accepted hosts from the ACME domain, certificate SANs or `--host`. Client: remember per host that `bound` was offered and refuse the unbound login thereafter; add `--require-bound-auth`.
3. **Cap identifier length before base58 decoding** (SM-P-02): reject anything longer than 44 characters in `UserId::from_str` and `GroupId::from_str`; add a small per-connection frame-parse budget on the relay.
4. **Pin against the validated path only** (SM-C-01): match pins on `end_entity`, or rebuild the path with webpki and pin against it; add the appended-certificate test.
5. **Re-encrypt every file the store owns** (SM-C-02, SM-C-08): one shared file list with `wipe()`, including the three missing files; write `vault.json` before re-encrypting.
6. **Add the missing relay budgets and timeouts** (SM-R-03, SM-R-04, SM-R-05, SM-R-06): a hyper timer and header-read timeout on both listeners with accept-time per-address accounting; require a bundle for `envelope.to` and add a global mailbox-bytes cap; a publish bucket and a per-identity cap on logged changes per hour; an `ack` bucket with a read-before-write check.
7. **Persist the saved-file path as data, and contain open/decrypt to the downloads directory** (SM-C-12).
8. **Never hold parked group messages; fetch each blob once; cap handshake blob size** (SM-G-01).
9. **Require the account's own identity as inviter for link-time "expected" groups** (SM-G-02).
10. **Make transparency refusals abort the send and raise lifecycle statements from refused answers** (SM-C-06); **refuse to send v1** as the specification already says (SM-C-03).

## 13.2 Next minor release (weeks)

11. Make capability names injective in the signed bytes (reject non-`[a-z0-9_]` names now; length-prefix at the next domain bump) (SM-P-03).
12. Remember offered relay features per host and treat their withdrawal as a downgrade event; surface the anonymous-submission fallback; add `--require-anonymous` (SM-C-05, SM-C-16).
13. Compare an inbound handshake's `identity_dh` with the pinned key and warn on mismatch; surface the key in `SessionEstablished` (SM-C-07).
14. Fix the inline MLS threshold and frame before merging and before contacting the sequencer (SM-P-05); allow referenced self-Removes for any committer and drop a leaving admin from `admins` in the same commit (SM-G-03); validate update-path leaves and Update proposals and bind `(account, device)` across an update (SM-G-04); cap leaves per identity on the tree (SM-G-08).
15. Bound invitations, delete orphan MLS state on a failed Welcome, rate-limit Welcomes from non-contacts, and never act as admin automatically in a group whose admin list someone else wrote (SM-G-05, SM-G-06); confirm the account on the new device before adopting a link (SM-G-07).
16. Use `checked_add` in the sequencer and run `unregister` on panic (SM-R-09); require the current token or an admin's authenticated connection to re-create a sequencer entry (SM-R-08, SM-G-09).
17. Data-directory hygiene: 0700 directory, private writer for every file, 0600 downloads/exports/backups, `fsync` on outbox and transparency writes; route `--check-release` through the remembered proxy (SM-C-09, SM-C-10).
18. Replace the `/open` denylist with a viewer allowlist and tag the `.open/` copy with mark-of-the-web (SM-C-11).
19. Filter control characters on the four unprotected output paths (export, release check, clipboard, reader mode) and mark continuation lines visibly (SM-C-20); add an explicit note flag; require a separate keystroke for destructive commands (SM-C-26).
20. Bound Argon2 parameters on read; hold passphrases in zeroising strings and drop the environment passphrase after first use (SM-C-21, SM-C-22).
21. Relay hygiene: canonicalise IPv4-mapped addresses, refuse revoked identities at login, validate envelope ids, log error kinds not text, minimum chunk size and per-chunk accounting, bounded outbound queue with lazy mailbox paging, `UMask=0077` and a peer-credential check on the admin socket, `create_new` for backup temp files, `state.who()` in the `unban` message, no TLS resumption on the relay (SM-R-07, SM-R-10 to SM-R-13).
22. Sign releases with a key held outside GitHub and publish `minisign.pub`; pin the toolchain and record it beside `SHA256SUMS`; pin container images by digest; store the deploy host key (SM-S-01, SM-S-02, SM-S-04, SM-S-05); harden the installer defaults (SM-S-03).

## 13.3 Design work before 1.0 (months)

23. **Message ids inside the authenticated body** (SM-P-14) and a per-epoch acceptance window for sequence numbers (SM-C-15), so that relay renaming and reordering cannot drop or replay messages.
24. **Rollback protection for key-bearing files** (SM-C-24) and data-key rotation on passphrase change (SM-C-23).
25. **A fresh identity-key binding in the v4 handshake, or an explicit statement that the X25519 key is an impersonation key** (SM-P-04); re-run the Verifpal models with the identity and DH keys leaked separately.
26. **Device-key counter-signatures on certificates**, so an account cannot enroll a stranger's key (SM-R-01 root cause), and length-prefixed optional fields in the ratchet AAD (SM-P-06).
27. **Metadata hygiene at rest**: HMAC-named history files and padded lines (SM-C-25); a single-instance lock; compaction and pruning of history updates (SM-C-19).
28. **Continuous fuzzing** with a persisted corpus and a target for the frame path at full size (SM-S-08); consider `libcrux-ml-kem` for both PQ paths when the API allows (SM-P-13).
29. **Documentation pass** over every row of section 12, so the threat model and the assessment describe the code that ships.
# Appendix A. Severity rating methodology

Each finding is rated on a five-level scale aligned with the qualitative bands of CVSS v3.1, judged against the project's own threat model: an attacker capability the threat model already concedes (for example, a relay delaying mail) is not rated as if it were a new one, and a claim the threat model makes that the code does not deliver is rated by the gap.

| Level | Meaning in this report |
| --- | --- |
| **Critical** | Exploitable by a low-privilege party (a registered identity, a stranger, a network attacker) with trivial effort, with an impact that is irreversible or breaks a core security promise for arbitrary victims. |
| **High** | Breaks a documented security or privacy property, or enables denial of service with a large asymmetry, from a position the threat model treats as hostile (relay, contact, member, stranger, on-path observer). |
| **Medium** | Weakens a documented property under realistic conditions, requires a specific precondition (a race, a user action the UI invites, a particular configuration), or enables resource exhaustion that a single party can trigger. |
| **Low** | Hardening gaps, defence-in-depth misses, or issues that need an unusual configuration, physical or local access, or cooperation from the victim. |
| **Informational** | Observations with no direct security impact: inherited risks, documentation inaccuracies, and design notes worth recording. |

Availability findings against the relay are rated by asymmetry and by whether the documented limits should have stopped them, following the project's security policy, which places "relay resource exhaustion that the documented limits should have stopped" in scope and "denial of service by sheer volume" out of scope.

# Appendix B. Coverage

Files read in full by the audit team, grouped by crate. Line counts are of the audited commit.

| Crate / area | Files | Lines |
| --- | --- | --- |
| `silver-protocol` | `envelope`, `session`, `identity`, `pq`, `prekey`, `bundle`, `wire`, `device`, `group`, `transparency`, `lifecycle`, `blob`, `encoding`, `verify`, `error`, `lib`; tests `garbage`, `properties`, `vectors` (skimmed) | 7,700 |
| `silver-relay` | `lib`, `main`, `store`, `admin`, `tls`, `acme`, `backup`, `metrics`; tests `admin`, `backup`, `tls_alpn`, `acme`, `metrics` | 9,600 |
| `silver-client` | `connection`, `sessions`, `transparency`, `tail`, `receipts`, `cover`, `sequence`, `submitter`, `outbox`, `store`, `vault`, `keystore`, `backup`, `export`, `files`, `update`, `tls`, `proxy`, `invite`, `groups/{mod,link,provider,tests}`, `devices`, `linking`, `everyday`, `lib`; tests `tls`, `proxy`, `update`, `kill`, `e2e`, `relay_limits` (as needed) | 17,900 |
| `silver-tui` | `main`, `app`, `ui`, `terminal`, `clipboard`, `notify`, `link`, `qr`, `commands`, `glyphs`, `reader`, `theme`, `app/{journal,bounds,devices,everyday,groups}`; `tests/tui/{harness,test_panic,test_lock,test_files}.py` | 12,600 |
| Deployment and packaging | `deploy/*`, `packaging/**`, `HomebrewFormula/*` | — |
| CI/CD | `.github/workflows/{ci,release,deploy,scorecard}.yml` | — |
| Formal models | `formal/README.md`, `expected.txt`, `check.sh` | — |
| Documentation | `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`, `docs/SECURITY_ASSESSMENT.md`, `docs/OPERATING.md`, `docs/design/{groups,devices,robustness}.md`, `README.md`, `SECURITY.md`, `ROADMAP.md` (1.0 items), `CHANGELOG.md` (security entries) | — |
| Dependencies (sources inspected) | `bs58` 0.5.1, `ml-kem` 0.3.2, `x-wing` 0.1.0, `openmls` 0.9.0 (commit builder, staged commit, creation, sender ratchet), `rustls` 0.23.43 (server builder defaults), `axum` 0.8.9 and `axum-server` 0.8.0 (serve builders), `hyper` 1.11.1 (timeouts), `instant-acme` 0.8.5 (account credentials), `open` 5.4.3, `rpassword` 7.5.4, `ratatui` 0.30.2 (buffer filtering), `ed25519-dalek` 2.2.0 (key parsing) | — |

Not covered: `fuzz/` target bodies beyond confirming what they exercise; `tests/tui/*.py` beyond the four listed; the Verifpal model files themselves (their README and expectations were read); live behaviour of any deployed relay.

# Appendix C. Dependency audit output

```
$ cargo audit --file Cargo.lock
    Loaded 1239 security advisories (from /root/.cargo/advisory-db)
    Scanning Cargo.lock for vulnerabilities (619 crate dependencies)
Crate:     proc-macro-error2
Version:   2.0.1
Warning:   unmaintained
Title:     proc-macro-error2 is unmaintained
Date:      2026-06-07
ID:        RUSTSEC-2026-0173
URL:       https://rustsec.org/advisories/RUSTSEC-2026-0173

warning: 1 allowed warning found

$ cargo audit --file fuzz/Cargo.lock
(same single warning; no vulnerabilities)
```

Dependency path of the warning: `silver-client` → `openmls_rust_crypto` → `hpke-rs-rust-crypto` → `libcrux-*` → `hax-lib-macros` → `proc-macro-error2`. Build-time only.

Security-relevant crate versions in the tree: `ed25519-dalek` 2.2.0, `x25519-dalek` 2.0.1 (and 3.0.0 via `x-wing`), `curve25519-dalek` 4.1.3 and 5.0.0, `chacha20poly1305` 0.10.1, `hkdf` 0.12.4 / 0.13.0, `hmac` 0.12.1 / 0.13.0, `sha2` 0.10.9 / 0.11.0, `ml-kem` 0.3.2, `x-wing` 0.1.0, `argon2` 0.6.0, `openmls` 0.9.0, `openmls_rust_crypto` 0.6.0, `hpke-rs` 0.7.0, `rustls` 0.23.43, `rustls-webpki` 0.103.15, `webpki-roots` 1.0.9 (and 0.26.11), `tokio-tungstenite` 0.30.0 (and 0.29.0 via axum), `axum` 0.8.9, `hyper` 1.11.1, `redb` 4.2.0, `instant-acme` 0.8.5, `bs58` 0.5.1, `base64` 0.22.1 / 0.23.1, `zeroize` 1.9.0, `subtle` 2.6.1, `rand` 0.8.8 / 0.9.5 / 0.10.2, `getrandom` 0.2.17 / 0.3.4 / 0.4.3, `serde_json` 1.0.151, `arboard` 3.6.1, `open` 5.4.3, `rpassword` 7.5.4.

# Appendix D. Experiment: base58 decoding cost (SM-P-02)

A minimal Rust program was compiled against `bs58` 0.5.1 in release mode and timed `bs58::decode(s).into_vec()` for strings of the character `z` (digit value 57, which maximises carry propagation) at increasing lengths, on the audit machine (a single core of a cloud VM):

```
n=   1000 chars -> Ok(733) bytes decoded in 256.115µs
n=  10000 chars -> Ok(7323) bytes decoded in 25.661168ms
n=  50000 chars -> Ok(36613) bytes decoded in 651.387534ms
n= 131000 chars -> Ok(95925) bytes decoded in 4.446013924s
```

The growth is quadratic (10× the input, ~100× the time). 131,000 characters is just under the relay's 128 KiB frame limit, and the decode happens inside serde deserialisation of the first frame on every connection, before the rate limits and before authentication (`crates/silver-relay/src/lib.rs:1927`, `2292-2314`). The cost of the attacker's side is one 128 KiB WebSocket frame per ~4.5 s of relay CPU.

# Appendix E. Finding index by component

| Component | Critical | High | Medium | Low | Informational |
| --- | --- | --- | --- | --- | --- |
| Protocol and cryptography | — | SM-P-01, SM-P-02 | SM-P-03, SM-P-04, SM-P-05 | SM-P-06 to SM-P-09 | SM-P-10 to SM-P-14 |
| Relay | SM-R-01 | SM-R-02 to SM-R-05 | SM-R-06 to SM-R-09 | SM-R-10 to SM-R-13 | — |
| Client library and terminal client | — | SM-C-01, SM-C-02 | SM-C-03 to SM-C-12 | SM-C-13 to SM-C-26 | SM-C-27 |
| Groups, devices, linking | — | SM-G-01, SM-G-02 | SM-G-03 to SM-G-08 | SM-G-09 to SM-G-12 | SM-G-13 |
| Deployment, packaging, supply chain | — | — | SM-S-01 | SM-S-02 to SM-S-05 | SM-S-06 to SM-S-09 |
| **Total** | **1** | **10** | **24** | **30** | **11** |
