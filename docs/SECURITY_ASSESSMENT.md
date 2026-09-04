# Security assessment against OWASP ASVS Level 2

A walk through the [OWASP Application Security Verification Standard
4.0.3](https://owasp.org/www-project-application-security-verification-standard/),
Level 2, applied to the code on `main` at the end of Phase 6 (the 0.6.0
line). ASVS is written for web applications; Silver Messenger is a terminal
client and a relay that speak WebSocket, so a number of controls do not
apply and say so. Every other control gets a verdict:

- **Met**: the control is implemented and something (a test, a CI job, a
  review of the code) backs the claim.
- **Partly**: implemented with a known limitation, named.
- **Not met**: not implemented; the roadmap item or the reason follows.
- **N/A**: the control's subject does not exist in this program.

This is a self-assessment by the author, checked against the code, the
tests and the CI configuration, not an independent audit. An independent
review of `silver-protocol` and the relay is planned before 1.0
([ROADMAP.md](../ROADMAP.md) item 35) and has not happened. Controls
marked Level 3 only are left out. Where a control is met by a design
decision rather than code, the threat model
([THREAT_MODEL.md](THREAT_MODEL.md)) is the reference.

Summary: of the 14 chapters, six apply in full, six in part, and two
(V3 session management as ASVS means it, V13 web API shape) almost not at
all. The gaps that matter are listed at the end with what closes them.

## V1 Architecture, design and threat modelling

| Control | Verdict | Evidence |
| --- | --- | --- |
| 1.1.1 Secure development lifecycle | Partly | Every change runs `cargo test`, `clippy -D warnings`, `cargo fmt`, `cargo deny`, `cargo audit`, a minute of fuzzing per parser and the terminal tests in CI; there is no formal review step because there is one author. |
| 1.1.2 Threat modelling | Met | [THREAT_MODEL.md](THREAT_MODEL.md), kept in step with the code; every Phase 6 item updated it. |
| 1.1.3 Security in user stories | Met | ROADMAP items state the attacker and the property gained before the work; Phase 6 is entirely such items. |
| 1.1.4 Trust boundaries documented | Met | The threat model's actors and the protocol's "what the relay sees" sections. |
| 1.1.5 High-level architecture | Met | README (crates, data flow), PROTOCOL.md section 1 and 7. |
| 1.1.6 Centralised, reusable security controls | Met | All cryptography lives in `silver-protocol`; the relay and client contain none of their own. Limits and caps are constants in one place per crate. |
| 1.1.7 Secure coding checklist | Partly | Conventions are enforced by tooling (`forbid(unsafe_code)` in every crate but the terminal binary, which has one documented exception; clippy; deny), not written as a checklist. |
| 1.2.1 Low-privilege accounts per component | Met | The relay runs as its own system user under a hardened systemd unit (`deploy/silver-relay.service`: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `StateDirectoryMode=0700`). |
| 1.2.2 Component-to-component authentication | Partly | Relay behind Caddy on the same host talks plain HTTP on loopback; documented. Client to relay is authenticated (V2). |
| 1.2.3 One vetted authentication mechanism | Met | Challenge signature under a domain-separated prefix, one code path (`silver_protocol::wire::verify_auth`). |
| 1.2.4 Consistent strength across authentication paths | Met | There is one path. Anonymous submission is unauthenticated by design and gets its own, lower limits. |
| 1.4.x Access control architecture | Met | The only authorisation decision is "this connection proved this identity"; everything that follows (mailbox, bundle) is keyed on it on the relay. |
| 1.5.1 Input/output requirements defined | Met | PROTOCOL.md gives every field, size and cap. |
| 1.5.2 Serialisation not used with untrusted clients unless protected | Met | JSON only (serde), no native serialisation; every peer-controlled object is signed or AEAD-authenticated before its contents are used. |
| 1.5.3 Input validation in a trusted layer | Met | Relay validates frames before acting; the client validates bodies after decrypting, in `silver-client`, not the UI. |
| 1.5.4 Output encoding near the interpreter | Met | Text is sanitised for the terminal at the rendering layer, with a test that drives the real backend and asserts no escape reaches it. |
| 1.6.1 Key management policy | Met | PROTOCOL.md sections 1, 2, 5 and 8: what each key is, who signs it, how long it lives, when it rotates. |
| 1.6.2 Key consumers protected from key exposure | Partly | Secrets are `Zeroize`d on drop and kept out of `Debug` output; the running process holds them in memory (threat model: device thief with memory). |
| 1.6.3 Key replacement | Met | Prekeys rotate on a schedule; identity keys cannot be revoked, only replaced out of band (documented gap). |
| 1.6.4 Client-side secrets | Met | The data key is wrapped by the OS key store or a passphrase; nothing is embedded in the binary. |
| 1.7.1 Common logging format | Met | `tracing` in both binaries. |
| 1.7.2 Logs transmitted securely | N/A | Logs stay on the host (journal, or `silver.log` with 0600). |
| 1.8.1, 1.8.2 Data classified and protection levels | Met | The threat model's asset table. |
| 1.9.1 Encrypted communication between components | Met | Client to relay over TLS (`wss://`), enforced once seen; plain `ws://` only where the user configures it. |
| 1.9.2 Certificates verified | Met | rustls against the system store and Mozilla roots, optional key pins. |
| 1.10.1 Source control with change tracking | Met | Git, GitHub, commit messages that state the change and its reason. |
| 1.11.1 Business logic flows documented | Met | PROTOCOL.md section 8 (client behaviour), including crossed session starts. |
| 1.11.2 No unsynchronised shared state | Met | Shared client state is behind mutexes; the relay's store is a transactional database (redb). |
| 1.12.2 Uploaded files served safely | N/A | The relay stores ciphertext chunks by random id and never serves files as files. |
| 1.14.1 Segregation of components | Met | Separate crates; the relay has no client code and vice versa. |
| 1.14.2 Binary signatures, trusted pipeline | Met | Reproducible builds, SLSA provenance, minisign signature on `SHA256SUMS` (once the key is set up); README "Verifying a release". |
| 1.14.3 Pipeline warns on outdated or insecure components | Met | `cargo audit`, `cargo deny` on every push. |
| 1.14.4 Deployment automated and repeatable | Met | `deploy/install.sh`, the deploy workflow, pinned actions. |
| 1.14.6 No unsupported or insecure client technologies | Met | Native Rust binaries; no plugins, no embedded browser. |

## V2 Authentication

The relay authenticates a client by a signature over its random 32-byte
challenge and, from 0.6.0, the relay's own host name. There are no
passwords between client and relay. The only password-like secret is the
optional local passphrase that protects the data directory (V6) and the
optional invite token for registration.

| Control | Verdict | Evidence |
| --- | --- | --- |
| 2.1.x Password security | N/A for relay authentication | No passwords. The local passphrase has no composition rules (2.1.9), allows any length (2.1.2, up to what the terminal takes), and is never truncated (2.1.4); there is no strength meter or breach check (2.1.7, 2.1.8): the passphrase never leaves the device, and the threat model names a weak one as the remaining risk. |
| 2.2.1 Anti-automation on authentication | Met | Per-address connection limits (16), a 10-second authentication timeout, registrations per address per hour (20), invite tokens. |
| 2.2.2 Weak authenticators restricted | Met | Only Ed25519 signatures. |
| 2.2.3 Notification on authenticator change | Partly | A changed Diffie–Hellman key is announced to every contact (sessions dropped, safety numbers); there is no notification to the owner, who has no other channel. |
| 2.4.x Credential storage | N/A | The relay stores public keys only. |
| 2.5.x Credential recovery | N/A | There is nothing to recover; a lost identity is a new identity (documented). |
| 2.9.1 Verification keys stored securely | Met | The relay keeps public keys only; the client's private keys are in `identity.json` under the data key. |
| 2.9.2 Challenge nonce ≥64 bits, single use | Met | 32 random bytes per connection, used once. |
| 2.9.3 Approved algorithms | Met | Ed25519; domain-separated, host-bound. The older host-less login is accepted from older clients until the operator sets `--require-bound-auth` (documented downgrade window). |
| 2.10.1–2.10.4 Service authentication secrets | Met | The only shared secret is the invite token, given by flag or environment, compared in constant time, never logged. |

## V3 Session management

ASVS sessions are tokens that outlive a request. Here a "session" is an
authenticated WebSocket connection, which ends when the connection does;
the forward-secret messaging sessions are cryptographic state, covered in
V6 and the threat model.

| Control | Verdict | Evidence |
| --- | --- | --- |
| 3.1.1 No session tokens in URLs | Met | None exist. |
| 3.2.x Session binding | Met | Authentication is bound to the connection and to the relay's host name; nothing is transferable. |
| 3.3.1 Logout invalidates | N/A | Closing the connection is the logout. |
| 3.3.2 Idle timeout | Met | The relay closes a connection silent for 120 s; the client can lock itself after idle minutes (`lock_after_minutes`). |
| 3.4.x, 3.5.x Cookies and token-based sessions | N/A | |
| 3.7.1 Re-authentication for sensitive operations | Partly | `/lock` and the idle lock ask for the passphrase again; changing the relay or exporting a backup does not. |

## V4 Access control

| Control | Verdict | Evidence |
| --- | --- | --- |
| 4.1.1 Enforced on a trusted layer | Met | The relay decides on its side; the client's opinion of who it is carries no weight. |
| 4.1.2 Access controls not manipulable by users | Met | A published bundle must carry the authenticated user's id and a valid signature; a mailbox is read only over a connection that proved its identity. |
| 4.1.3 Least privilege | Met | A connection can read one mailbox and publish one bundle; anonymous connections can only submit and move blobs. |
| 4.1.5 Fail securely | Met | Every error path refuses; the relay's frame handler returns an error code and does nothing else. |
| 4.2.1 Insecure direct object reference | Met | Mailboxes are addressed by authenticated identity, never by a parameter; blobs by a random id that only the recipient's message reveals (a guess of it yields ciphertext). |
| 4.2.2 CSRF | N/A | No cookies, no browser. |
| 4.3.1 Administrative interfaces | Met (by absence) | The relay has no admin interface; operation is by flags, environment and the journal. Metrics and admin tooling are items 37 and 38, to be designed with this in mind. |
| 4.3.2 Directory browsing | N/A | The relay serves three fixed routes (`/`, `/healthz`, `/ws`). |

## V5 Validation, sanitisation and encoding

| Control | Verdict | Evidence |
| --- | --- | --- |
| 5.1.1 Parameter pollution | N/A | No query strings. |
| 5.1.3, 5.1.4 Input validated and structured data typed | Met | Every frame and body is a typed serde structure with caps: 128 KiB frames, 32 KiB bodies, 4000-character messages, 200 one-time prekeys (50 ML-KEM), 16 MiB files, chunk counts checked against sizes, futures of at most two minutes on timestamps. |
| 5.2.1 Untrusted HTML | N/A | |
| 5.2.2 Unstructured data sanitised | Met | Aliases are cut to 40 visible characters and stripped of controls and bidi overrides; file names are NFC-normalised, stripped of format characters, cut to 120 characters keeping the extension, made safe for Windows device names. Tests in `silver-client` pin each rule; the fuzzer found two edge cases that are now tests. |
| 5.2.4, 5.2.5 Dynamic code, templates | N/A | |
| 5.2.6 SSRF | Met | The client connects to the relay the user configured and, on request only, to a fixed releases URL; nothing peer-controlled is ever fetched as a URL. |
| 5.3.1, 5.3.3 Context-aware output encoding | Met | Everything shown is passed through the terminal-safety layer; a test renders peer-controlled text through the real crossterm backend and asserts no escape, control or bidi character reaches it. |
| 5.3.4 SQL injection | N/A | redb is a key-value store; no query language. |
| 5.3.6 JSON injection | Met | serde only; no string-built JSON. |
| 5.3.8 OS command injection | Met | The file opener passes the path as an argument to the platform opener, never through a shell; programs, scripts and installers are refused before that. |
| 5.3.9 Local/remote file inclusion | Met | File names cannot contain separators after sanitisation; saved files never overwrite (` (2)` suffix, exclusive create). |
| 5.4.1–5.4.3 Memory, string and integer safety | Met | Rust; `unsafe` forbidden (one documented exception in the terminal binary for scrubbing the environment); size arithmetic uses saturating or checked forms in the limits; release builds keep overflow checks on. |
| 5.5.1 Serialised objects integrity-checked | Met | Bundles and prekeys are signed; bodies are AEAD-authenticated and signed; ratchet messages authenticated. |
| 5.5.3 Deserialisation of untrusted data restricted | Met | serde_json into closed types with size caps; every parser is fuzzed in CI and by seeded tests on stable. |

## V6 Stored cryptography

| Control | Verdict | Evidence |
| --- | --- | --- |
| 6.1.1 Private data encrypted at rest | Met | The data directory is encrypted under a data key wrapped by the OS key store (Credential Manager, Keychain, Secret Service) or, with a passphrase, by Argon2id (64 MiB, 3 passes) and XChaCha20-Poly1305. `downloads/` is the documented exception (plain files for other programs). Where there is no key store and no passphrase, files are plain and the client says so. |
| 6.2.1 Cryptographic modules fail securely | Met | Every failure is a `Result`; a failed decryption leaves session state untouched (trial decrypt on a clone). |
| 6.2.2 Approved algorithms | Met | Ed25519, X25519, ML-KEM-768 (FIPS 203), XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, SHA-256, Argon2id; all from RustCrypto or dalek crates. |
| 6.2.3 No insecure modes or padding | Met | AEAD only; message padding is JSON whitespace under the AEAD, not a cryptographic padding scheme. |
| 6.2.4 Algorithms replaceable | Partly | Versioned domain strings and body versions (v1, v2, v3) let the handshake and body formats change; the envelope layer is v1 only. |
| 6.2.6 Nonces never reused | Met | Random 24-byte nonces for envelopes and files; ratchet message nonces are derived from single-use message keys. |
| 6.2.7 Encrypted data authenticated | Met | Everything encrypted is AEAD with associated data binding its context (recipient, ephemeral key, blob id and chunk position, session id and header). |
| 6.2.8 Constant-time operations | Met | dalek and RustCrypto primitives; the invite token compares with `subtle`. |
| 6.3.1 CSPRNG | Met | `OsRng` (`getrandom`) for every key, nonce, id and epoch. |
| 6.3.2 Identifiers from a CSPRNG | Met | Envelope ids, blob ids, prekey ids, sequence epochs. |
| 6.4.1 Secrets management | Met | OS key store or passphrase; relay invite token from flag or environment. |
| 6.4.2 Keys not exposed to application code | Partly | Keys are in process memory; core dumps are disabled and, on Linux, the process is not dumpable or traceable by other processes of the user; `SILVER_PASSPHRASE` is scrubbed from the environment before any thread exists. |

## V7 Error handling and logging

| Control | Verdict | Evidence |
| --- | --- | --- |
| 7.1.1 No credentials or secrets in logs | Met | Secrets implement `Debug` without their bytes; the invite token is never logged. |
| 7.1.2 No unnecessary sensitive data in logs | Met | The relay names clients by a per-run salted pseudonym unless `--log-ids` is set; the client's own log does not record its user id at the info level; aliases and message text are never logged. |
| 7.1.3 Security-relevant events logged | Partly | Refused registrations, connections and uploads are counted and reported hourly; rate-limit hits are logged; a failed login is answered with `bad_signature` but not counted per address (gap: item 37 metrics). |
| 7.1.4 Log entries have context | Met | Structured `tracing` fields. |
| 7.3.1 Log injection | Met | `tracing` escapes; no user-controlled text reaches the relay log; the client log gets sanitised aliases only. |
| 7.3.3 Logs protected from modification | Met | The relay logs to the journal; `silver.log` is created 0600. |
| 7.4.1 Generic error messages to users | Met | The relay answers with an error code and a fixed short message; internal errors say "storage error" and log the detail on the relay. |
| 7.4.2 Exception handling | Met | Rust `Result` throughout; the relay's per-connection task cannot take the process down. |
| 7.4.3 Last-resort handler | Not met | The terminal client installs no panic hook, so a panic can leave the terminal in raw mode until `reset`. Small; noted for the next TUI pass. |

## V8 Data protection

| Control | Verdict | Evidence |
| --- | --- | --- |
| 8.1.1, 8.1.2 No sensitive data cached on the server | Met | The relay holds ciphertext and public keys; nothing decryptable. |
| 8.1.3 Minimal parameters | Met | The envelope names only the recipient; the sender is inside the ciphertext. |
| 8.1.4 Anti-automation on bulk data | Met | Per-connection and per-address rate limits, one-time prekey hand-out cap (30 per user per hour). |
| 8.2.x Client-side (browser) data protection | N/A | |
| 8.3.1 Sensitive data not in URLs | Met | There are no URLs with data. |
| 8.3.2 Users can remove or export their data | Met | `--export-backup` (identity and contacts, under its own passphrase); deleting the data directory removes everything local; the relay drops mailboxes after 30 days and holds nothing else about a user but the bundle. There is no remote "delete my identity from the relay" yet. |
| 8.3.3 Users told what is collected | Met | The threat model, in the README's first paragraph. The client collects nothing; `--check-release` is opt-in and documented. |
| 8.3.4 Sensitive data identified and protected | Met | Asset table; encryption at rest; sealed sender. |
| 8.3.6 Sensitive data in memory wiped | Met | `Zeroize`/`ZeroizeOnDrop` on keys, session state, passphrases and plaintext buffers. |
| 8.3.7 Encrypted at rest | Met | As 6.1.1. |
| 8.3.8 Retention policy | Partly | Relay: 30-day mailbox TTL, caps on messages, bytes, blobs and identities. Client: history is kept until the user removes the contact or the directory; no automatic expiry. |

## V9 Communication

| Control | Verdict | Evidence |
| --- | --- | --- |
| 9.1.1 TLS for all client connectivity | Partly | `wss://` is the documented default and, once used for a host, cannot be downgraded; plain `ws://` remains possible when the user configures it (local relays, tests). |
| 9.1.2 Strong cipher suites | Met | rustls defaults (AEAD suites only). |
| 9.1.3 Latest TLS versions | Met | TLS 1.3 and 1.2 only. |
| 9.2.1 Server certificate validated | Met | rustls, system store plus Mozilla roots, `--ca-cert` for private roots, `--pin` for key pins. |
| 9.2.2 Encrypted connections between components | Partly | Relay behind Caddy: loopback plain HTTP on one host, documented. |
| 9.2.3 External connections authenticated | Met | The releases page over TLS with the same trust store. |
| 9.2.4 Certificate revocation checked | Not met | rustls performs no OCSP or CRL checks; pins are the offered mitigation. No item planned; documented here. |
| 9.2.5 TLS failures logged | Met | Connection errors are shown in the client's System pane and log. |

## V10 Malicious code

| Control | Verdict | Evidence |
| --- | --- | --- |
| 10.1.1 Code analysis | Partly | clippy, `cargo audit`, `cargo deny`, fuzzing, the OpenSSF Scorecard; no dedicated malicious-code analysis. |
| 10.2.1 No unauthorised phone-home | Met | The client contacts its relay and, only on `--check-release`, GitHub's releases API; nothing else, ever. Verified in tests that the client makes no other connections. |
| 10.2.2 No data collection | Met | None. |
| 10.2.3 No backdoors, undocumented modes | Met | Every flag is documented (`--help`, README); `--log-ids` and `--submit-authenticated` are the only "less private" modes and say so. |
| 10.3.1 Auto-update with signature checks | Met (by absence) | There is no auto-update; releases are signed and reproducible for manual verification. |
| 10.3.2 Integrity of third-party code | Met | `Cargo.lock`, `cargo deny` sources allowlist (crates.io only), `cargo auditable` embeds the tree, SBOM per binary. |
| 10.3.3 Subdomain takeover | N/A | |

## V11 Business logic

| Control | Verdict | Evidence |
| --- | --- | --- |
| 11.1.1 Steps in order | Met | Authentication before anything on an authenticated connection; a bundle before a lookup can find it; a file's upload completes before its message is sent. |
| 11.1.3, 11.1.5 Limits on actions and business limits | Met | Per-connection and per-address rate limits, mailbox and storage caps, prekey deposit caps, downloads quota on the client. |
| 11.1.4 Anti-automation | Met | As above plus invite tokens for registration. |
| 11.1.6 TOCTOU | Met | Files are created exclusively; ratchet decryption advances state only on success; one-time prekeys are taken in one database transaction. |
| 11.1.7 Monitoring for unusual activity | Partly | Hourly counters in the relay log; no metrics endpoint (item 37). |
| 11.1.8 Alerting | Not met | Item 36. |

## V12 Files and resources

| Control | Verdict | Evidence |
| --- | --- | --- |
| 12.1.1 File size limits | Met | 16 MiB per file, checked before a single chunk is fetched; a downloads quota (1 GiB by default). |
| 12.1.2 Compressed file bombs | N/A | Nothing is decompressed. |
| 12.1.3 Flooding | Met | Per-address upload caps (256 MiB per hour), relay storage cap, chunk rate limit. |
| 12.2.1 File type checked against content | Partly | Files are the recipient's data, saved as sent; what is refused is *opening* anything the system would run rather than show, by extension, with the mark of the web set on Windows. Content sniffing is deliberately not done. |
| 12.3.1, 12.3.2 File name and path validation | Met | As 5.2.2 and 5.3.9; tests and fuzzing cover the sanitiser. |
| 12.3.5 OS command injection through file names | Met | As 5.3.8. |
| 12.3.6 No code from untrusted sources | Met | Received files are never executed by the client. |
| 12.4.1 Files stored outside the served tree | N/A | The relay never serves files; the client saves to `downloads/` only. |
| 12.4.2 Antivirus scanning | Partly | Not done by the client; on Windows the mark of the web hands the file to Defender and SmartScreen when it is opened. |
| 12.5.x, 12.6.1 Web tier file serving, SSRF allowlist | N/A | |

## V13 API and web service

The relay's API is one WebSocket endpoint with typed frames plus two GET
routes (`/` with the source notice, `/healthz`).

| Control | Verdict | Evidence |
| --- | --- | --- |
| 13.1.1 Content types and parsing | Met | Text frames of typed JSON; anything else is an error and the frame is dropped; frames above 128 KiB are refused by the WebSocket layer. |
| 13.1.3 No sensitive information in URLs | Met | |
| 13.1.4 Authorisation per resource | Met | As V4. |
| 13.1.5 Unexpected content types rejected | Met | Unknown frame types are answered with an error. |
| 13.2.x RESTful, 13.3.x SOAP, 13.4.x GraphQL | N/A | |

## V14 Configuration

| Control | Verdict | Evidence |
| --- | --- | --- |
| 14.1.1 Build and deploy automated and repeatable | Met | Reproducible release builds checked in CI; pinned actions; installer script. |
| 14.1.2 Compiler flags | Met | Rust; `forbid(unsafe_code)`; `-D warnings`; overflow checks on in release. |
| 14.1.3 Server hardened | Met | systemd unit as in 1.2.1; relay data directory 0700 and database 0600; runs as an unprivileged user. |
| 14.1.4 Deployment automated | Met | `deploy/` and the deploy workflow. |
| 14.2.1 Components up to date | Partly | `cargo audit` and `cargo deny` on every push catch a vulnerable or yanked crate; routine version and action-pin updates are done by hand, so they lag. |
| 14.2.2 Unneeded features removed | Met | Minimal feature sets (rustls without defaults, ml-kem with zeroize and getrandom only). |
| 14.2.4 Trusted repositories only | Met | `cargo deny` allows crates.io only. |
| 14.2.5 SBOM | Met | CycloneDX per binary in every release; `cargo auditable` in the binaries. |
| 14.3.1 Debug modes off in production | Met | Release builds; `--log-ids` and `SILVER_LOG=debug` are explicit opt-ins. |
| 14.3.3 No stack traces to users | Met | Error codes and short messages; panics abort a relay connection task, not the process. |
| 14.4.x HTTP security headers | Partly | The relay's two GET routes serve plain text without security headers; behind Caddy in the documented deployment. Item 36 (built-in TLS) is where the relay grows an HTTP surface worth hardening. |
| 14.5.x HTTP request header validation | Partly | The WebSocket upgrade does not check `Origin`; there is no browser client, so the check would protect nothing today, and cookies are not involved. Noted for item 36. |

## Gaps, in order of weight

| Gap | Control | Closed by |
| --- | --- | --- |
| No independent review of the cryptography and the relay | 1.1.1 | Roadmap item 35: before 1.0. |
| No metrics, alerting or per-address failed-login counting | 7.1.3, 11.1.7, 11.1.8 | Roadmap item 37. |
| Plain `ws://` allowed when configured | 9.1.1 | By design for local relays; the no-downgrade rule covers the case that matters. |
| Certificate revocation not checked | 9.2.4 | Not planned; pins and short-lived Let's Encrypt certificates are the mitigation. |
| No panic hook in the terminal client | 7.4.3 | Next TUI pass. |
| Received files stored unencrypted | 6.1.1 | By design, documented; a per-file "keep encrypted" option could follow if asked for. |
| No client-side history expiry | 8.3.8 | Could follow as a setting if asked for. |
| No `Origin` check on the WebSocket upgrade, no HTTP headers | 14.4, 14.5 | Item 36, when the relay serves more than three routes. |
