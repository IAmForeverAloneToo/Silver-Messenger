# Silver Messenger — Comprehensive Adversarial Security Audit

> **Published copy.** This is the report as delivered, with one class of
> edit: identifiers belonging to the maintainer's own infrastructure and
> machine — relay hostnames, shell history, a process id, and the names
> of two key-store entries observed locally — are redacted from
> Appendix A and M-1. They are operator infrastructure rather than
> findings, and none of them carries any part of the report's argument;
> every finding, severity, citation and remediation is unedited. The
> convention of publishing reviews whole is in
> [SECURITY.md](../../SECURITY.md); this is the exception it does not
> yet name, and it is named here instead of made quietly.

**Date:** 2026-09-09 · **Revision 3** (post counter-review verification)
**Target:** `IAmForeverAloneToo/Silver-Messenger` (main branch, commit at clone time; workspace v0.14.0, ~64,300 lines of Rust across 4 crates)
**Auditor:** Independent adversarial review commissioned by the program's author, with full authorization.
**Method:** Four parallel specialist audits (`silver-protocol`, `silver-relay`, `silver-client`, `silver-tui` + supply chain), reconciled; a live runtime compromise of a Windows 0.14.0 instance (data-key recovery from process memory) supplies ground-truth evidence; an independent adversarial reaudit of the report was performed and its corrections incorporated (Rev 2); a second external counter-review (15 claims) was then verified claim-by-claim against the source and its corrections are incorporated here (Rev 3, Appendix C).
**Repo layout audited:** `crates/silver-protocol` (19 files, ~11.1 k LOC), `crates/silver-relay` (13 files, ~11.0 k LOC), `crates/silver-client` (42 files, ~27.0 k LOC), `crates/silver-tui` (18 files, ~15.2 k LOC), plus `formal/`, `fuzz/`, `tests/`, `packaging/`, `.github/`, `deploy/`, `Cargo.lock`, `deny.toml`, `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/PROTOCOL.md`, `docs/design/`.

---

## 1. Executive summary

**No Critical findings. No cryptographic breaks.** Every attack chain constructed against the core protocol — envelope readdressing, prekey substitution, ratchet-state poisoning, AAD-ambiguity forgery, key-compromise impersonation, UKS, replay, Ed25519 malleability, base58 decode DoS, small-order DH, capability-list re-serialization — failed against checks that exist in the code, most of them pinned by tests (§6).

The genuine weaknesses cluster in five places:

1. **Device linking without a confirmation guard (H-2).** `/devices link` issues a device certificate **signed by the identity key**, granting standing send-and-sync access until revoked — and it executes on a single pasted line with no `typed_it_themselves` guard and no confirm. The original audit materially understated this as a one-off history upload.
2. **Platform-hardening asymmetry (H-1).** `harden_process()` is Linux-only. On Windows, an unprivileged same-user process recovers the data key from an unlocked instance in seconds — **demonstrated live**, not theorized. `SECURITY.md` contains no platform memory-exposure statement at all.
3. **Key-lifecycle failure paths (M-1).** Keystore KEKs are deleted on exactly one code path with no GC; several realistic failure sequences permanently orphan `data-key-*` entries, silently breaking the threat model's rotation promise. Rated Medium after counter-review: exploitation additionally requires an old vault copy, the same access class as H-1.
4. **Reader-mode output path (M-6).** The full-screen render path is invariant-tested against terminal injection, and receive-side validation blocks control characters in group names — but two journal paths bypass `one_sentence()` so a peer can inject a **newline that forges a journal line reading as another person's or a system notice**, invisible/bidi characters survive filtering, and the compose prompt is written raw.
5. **Control-plane correctness in the relay (M-4, M-5) and the unsigned-build update contradiction (M-3).** None of these expose message content; they are enforcement/robustness gaps in availability, accounting, and distribution guarantees.

The project's security discipline is unusually high: `forbid(unsafe_code)` in protocol/relay/client (silver-tui is `deny(unsafe_code)` with a single reviewed exception), zeroization everywhere a secret lives, atomic writes with rollback, a prior 76-finding external audit whose relay-side fixes were re-verified as holding (§7), SLSA provenance, SHA-pinned CI, and formal models whose claims match the implementation. **The source tree emerges from all three review rounds looking stronger than any individual round credited** — several findings that survived two rounds fell to the third (Appendix C).

**Finding count (Rev 3):** 2 High, 7 Medium, 18 Low, 2 Informational (documentation-integrity).

---

## 2. Methodology and threat-model alignment

- **Attacker positions considered:** network adversary (relay operator, MITM), malicious peer (contact/group member), unprivileged same-user code on each OS, disk thief (powered-off machine), supply-chain actor (GitHub account compromise, malicious release, dependency compromise), operator error (relay misconfiguration).
- **Live evidence (Windows, 2026-09-09):** the 32-byte data key of an unlocked v0.14.0 instance was recovered via `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)` from an unprivileged same-user process; a full scan of 74 MB across 494 regions completed in 6 s using an SMV1 file body as the verification oracle (Appendix A). Two orphaned `data-key-*` KEKs were read from Windows Credential Manager via `CredRead` with zero privilege. No network checks were performed against any relay — all live work was local.
- **Documented-limit classification:** findings are marked **[genuine flaw]**, **[documented limit]** (behavior is in the threat model; recorded for precision), or **[live-verified]**.
- **Review chain:** Rev 1 = four parallel audits reconciled. Rev 2 = adversarial reaudit (two findings materially corrected, one retracted, citations fixed). Rev 3 = verification of a 15-claim external counter-review (two findings refuted and removed, two downgraded, one upgraded to High, two new findings accepted, three claims rejected with evidence, and the report's own H-2 remediation corrected as unsafe). Full logs in Appendices B and C.

---

## 3. Findings index (Rev 3)

| ID | Title | Component | Severity | Class |
|----|-------|-----------|----------|-------|
| H-1 | No process dump hardening on Windows/macOS; same-user unprivileged key recovery | tui/main, cross-platform | High | genuine flaw + live-verified |
| H-2 | `/devices link` issues an identity-signed standing device certificate with no paste-guard or confirm | tui app + client linking | High | genuine flaw |
| M-1 | Keystore KEKs orphan permanently on several failure paths; no GC/eviction; breaks the documented rotation promise | client store/keystore | Medium (downgraded from High, argued) | genuine flaw + live-verified |
| M-2 | Active bundle-stripping downgrade (PQ/caps removal); stale-bundle replay bounded to 21 days | protocol bundle | Medium | documented limit, enforcement gap |
| M-3 | Builds without `minisign.pub` install unsigned releases, contradicting `build.rs` documentation | client update | Medium | genuine flaw |
| M-4 | `per_hour(0)` admits one unit/hour — "zero = off" not honored for hourly limits | relay lib | Medium | genuine flaw |
| M-5 | `Store::expire` TOCTOU: double-decrements accounting **and can strand a re-enqueued message until TTL** | relay store | Medium | genuine flaw |
| M-6 | Reader-mode journal: newline injection forges lines read as another person's or the system's; invisible/bidi chars survive; prompt written raw | tui reader/journal | Medium | genuine flaw |
| M-7 | Paste-guard not applied to `/send` (one-paste local-file exfiltration) and other irreversible commands | tui app | Medium | genuine flaw |
| L-1..L-18 | see §5b | various | Low | mixed |
| I-1, I-2 | documentation-integrity findings | docs | Info | genuine |

---

## 4. High findings

### H-1 [High, live-verified] No process hardening on Windows; partial on macOS

**Where:** `crates/silver-tui/src/main.rs:311-320`:

```rust
fn harden_process() {
    #[cfg(unix)]
    { let _ = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0); }
    #[cfg(target_os = "linux")]
    { let _ = nix::sys::prctl::set_dumpable(false); }
}
```

There is no `#[cfg(windows)]` or `#[cfg(target_os = "macos")]` arm. The comment's stated goal — "keep the keys in memory out of core dumps and away from other processes of the same user" — is delivered only on Linux. (The frank `/proc/<pid>/environ` note is a **code comment** at `main.rs:225-226`; `SECURITY.md` mentions neither memory nor any platform — verified.)

**Windows.** Verified live: with the vault unlocked, a same-user, unprivileged process recovers the data key in seconds (`OpenProcess(PROCESS_VM_READ)` + region walk + 32-byte-window AEAD oracle; Appendix A). Key lifecycle hygiene is *not* the problem — `FileCipher.key` is `Zeroizing<[u8;32]>` and identity/prekey/session/PQ secrets are all zeroized on drop; the exposure is the live heap of the running process. Assessment of in-process options:

- There is **no Win32 equivalent of `PR_SET_DUMPABLE`** for ordinary processes. `SetProcessMitigationPolicy` options (`ProcessSignaturePolicy`, CFG, `ProcessExtensionPointDisablePolicy`) restrict code *injection*, not same-user handle opening for reads.
- **PPL is categorically unavailable**: protected-process-light requires an ELAM driver signed by Microsoft.
- `ProcessSideChannelIsolationPolicy` (Win 11) addresses speculative-execution isolation, not `PROCESS_VM_READ`.
- TPM/NCrypt sealing prevents *offline* export but the key must be unsealed into RAM to be used — same live exposure.

Conclusion: **within-process mitigation is impossible on Windows**; the honest remediation is (a) documentation parity in `SECURITY.md`, (b) exposure-window reduction: `lock_after_minutes` defaults to `0` (`store.rs:304`); a non-zero default for passphrase-protected directories directly shrinks the demonstrated attack window, (c) `VirtualLock` on key buffers (L-1), (d) optional `ProcessExtensionPointDisablePolicy` as cheap injection hardening.

**macOS.** With SIP on, same-user `task_for_pid` requires a signed debugger entitlement or developer mode; two weakenings exist: developer mode is common on dev machines, and **release builds are unsigned unless APPLE_* secrets are configured** (release.yml:105, 135-141) — unsigned means no hardened runtime, so DYLD/ptrace-based attach by non-entitled processes is not restricted. `RLIMIT_CORE=0` is honored (ReportCrash writes metadata-only `.ips` files), but swap/`sleepimage` remain root-readable secondary exposure (L-1). Fix: sign with hardened runtime (ad-hoc suffices for `CS_RESTRICT`) even when notarization secrets are absent; add the SECURITY.md line.

**Note on threat-model wording:** the "core dumps are off" claim reads as platform-neutral but is Unix-only; the assumption section ("operating system not compromised") does not obviously cover a *non-privileged same-user process*, which is precisely the actor the Linux arm defends against.

### H-2 [High, promoted from Medium after counter-review] `/devices link` issues an identity-signed standing device certificate with no paste-guard or confirm

**Where:** `crates/silver-tui/src/app.rs:2327-2339` (`typed_it_themselves` — the paste-guard mechanism, well-designed but not applied here); `devices.rs:223-323` (the `/devices link` command path — no confirm, no guard); `crates/silver-client/src/connection.rs:1576-1654` (`link_device`).

**The original audit materially understated the impact** (it described a history upload). Verified impact: `link_device` calls `self.identity.certify_device(&link.device, name, now_ms())` at connection.rs:1591 — **the identity key signs a standing device certificate**. The linked device then reads and writes as the user until the primary revokes it (THREAT_MODEL.md:490-495: "reads and writes as you... until the primary revokes it"), and every future message is sealed to it as well. This is *persistent account access*, not a one-off exfiltration.

The existing checks (`can_link`, same-relay registration, not-already-an-account, `supports_sessions` — connection.rs:1586-1609) do not hinder an attacker who induced the victim to paste a link — they all pass for a legitimately-formed attacker link on the same public relay. The exploit: any vector that gets one line into the victim's terminal without bracketed paste (clipboard-hijack via a web page copy button, social-engineering "paste this to fix the error", clipboard history tools) — `/devices link silver://link/… 365\r` and the attacker's device is a certified, syncing member of the account.

**Fix:** route `/devices link` through `typed_it_themselves` **plus** an explicit yes/no confirm naming the consequence ("this grants the linked device ongoing read/write access as you until revoked"); apply the same to `/send` (M-7) and the remaining irreversible commands (`/relay`, `/group join`, `/unblock`, and per L-18, `/alias`).

---

## 5. Medium findings

### M-1 [Medium, downgraded from High after counter-review — severity argued] Keystore KEKs are orphaned by several failure paths; nothing ever garbage-collects them

**Where:** `crates/silver-client/src/store.rs:1025-1055` (`set_passphrase_with`), `994-1015` (`protect_with_keystore`), `1060-1076` (`remove_passphrase`), `1091-1107` (`rotate_key`), `930-945` (`finish_rotation`), `keystore.rs` (full file — no enumeration API used anywhere).

Every protection transition mints a *fresh random* keystore name (`Kdf::keystore()` → `data-key-<hex>`, new salt each call, vault.rs:76-86, 93-96), and the old KEK is deleted on exactly one production path — `store.rs:1040` (with `?`) — plus a best-effort `let _ =` at `store.rs:1121`. `rotate_key` writes the rotating vault **first**, then re-encrypts all files, then writes the settled vault. Four failure sequences skip the deletion permanently (no code path ever names that KEK again): (1) `recrypt_all` fails partway (error propagates at 1099/1102 before 1040); (2) `keystore::delete` itself fails; retrying `set_passphrase` bails at 1028; (3) crash between `keystore::create` and the first `write_vault`; (4) `remove_protection`'s `let _ =`. No enumeration/GC of `data-key-*` exists in the crate.

**Why it matters:** `THREAT_MODEL.md:436-440` promises that moving between passphrase and key store "moves the files onto a fresh data key … somebody holding an old copy of `vault.json` and the passphrase reads nothing written after the change." The keystore→passphrase half of that guarantee silently depends on KEK deletion. On Windows, any same-user process can `CredRead` the entry with no prompt, so an orphaned KEK + an old copy of the data directory = complete decryption of pre-rotation data, no passphrase required.

**Severity argument (Rev 3):** the counter-review proposed Low; the reaudit oracle and this report settle on **Medium**. Exploitation requires both an old vault copy *and* key-store access — the same access class that recovers the live key outright (H-1), which caps marginal severity. Against Low: the failure is *silent and permanent* (nothing ever names the KEK again, nothing detects the orphan), it breaks a guarantee the threat model states verbatim, and — the sharpest edge — **this transition is precisely the mitigation action a user performs when they suspect key-store compromise**, so the remediation path for a suspected breach can itself leak the pre-breach key. Low is too low; High over-weights given the double access requirement.

**Live evidence and corrected provenance:** two orphaned entries (`data-key-<redacted>`, `data-key-<redacted>`) were observed on the audit machine; their `LastWritten` timestamps (2026-09-08 01:16, 01:52) predate the current data directory's creation (12:06) and `vault.json` has never been rewritten since — they stem from earlier experimental sessions and currently wrap no recoverable vault. The code mechanism is unaffected.

**Fix (Rev 3 — the original remediation was corrected as unsafe, see Appendix C):** the originally recommended "delete the old KEK immediately after the first successful `write_vault`" is **unsafe on POSIX**: `write_atomic` (store.rs:2164-2179) does `tmp + sync_all + rename` **without an fsync of the parent directory**, so a crash after the KEK deletion but before the rename is durable can revert `vault.json` to the keystore-wrapped version whose KEK is now deleted — permanently unrecoverable data. (The codebase already knows the fix and applies it in the update installer's `sync_dir`, install.rs:245-254, POSIX-only — NTFS journaling makes renames effectively durable.) Safe design: (1) add the directory fsync to `write_atomic` mirroring `install.rs`; (2) persist a `pending_kek_deletions` list in the new vault and drain it only after that vault has been successfully read at next unlock — a lost rename also loses the pending list, so the invariant holds; (3) startup sweep of `data-key-*` entries (`CredEnumerate` on Windows) deleting any not named by the current or pending-deletion vault; (4) compensating-delete on error paths after `keystore::create`.

### M-2 [Medium, documented limit with enforcement gap] Active bundle-stripping downgrade (PQ/caps removal)

**Where:** `silver-protocol/src/bundle.rs:109-153` (`KeyBundle::verify` — the signature does not cover field *presence*), `195-211` (caps advertising), `session.rs:288-290` (pq_ratchet decided from the bundle the initiator saw).

A malicious relay serves the initiator a *legitimately signed* bundle with `pq_signed`/`pq_one_time` stripped (both `Option`; `verify()` still passes) and `caps` stripped — the initiator then runs a classical, non-PQ handshake. **Scope narrowed in Rev 3:** stale-bundle replay is bounded to a 21-day window by the client's `SIGNED_PREKEY_RETENTION` check (sessions.rs:473-479, `SessionError::StalePrekeys`, test-pinned — see §6), and the v1 fallback step is blocked by client refusal (THREAT_MODEL.md:236-239, prior-audit SM-C-03). The transparency log distinguishes these bundles but is an opt-in relay feature with advisory gossip. The receive-side control checks that kill the analogous group-name injection do not help here: the bundle is well-formed, merely weaker than the peer's latest. Fix: user-visible "session with X is not post-quantum" when the peer's last-known bundle advertised more; consider a bundle freshness/floor mechanism at the next protocol bump.

### M-3 [Medium, genuine flaw] Unsigned-build update path contradicts its own documentation

**Where:** `crates/silver-client/src/update/mod.rs:598-601` (`verify`: empty `MINISIGN_PUB` → `Ok(false)`), `build.rs:8-10` (claims such a build "refuses to update"), `silver-tui/src/update.rs:152-164` (prints a parenthetical, installs anyway).

A binary built from a checkout missing `minisign.pub` (tarball, fork, crates.io mirror — the key ships in the repo, not the published crate) accepts any release whose API sha256 digest and `SHA256SUMS` match — both fetched from `github.com`/`objects.githubusercontent.com`. GitHub-account or repo compromise yields arbitrary code installed with only a warning line, while `build.rs` promises refusal. Official builds (key compiled in) are unaffected and genuinely layered (digest from different origin, sums cross-check, minisign, `--version` self-test, rollback). Fix: make `signature_checked == false` require explicit `--allow-unsigned` or interactive confirm; align the docs.

### M-4 [Medium, genuine flaw] `per_hour(0)` admits one unit per hour

**Where:** `silver-relay/src/lib.rs:356-361`, used at `lib.rs:439` (registrations), `440-442` (upload bytes), `783-785` (prekey handouts). `let burst = per_hour.max(1.0)` clamps 0 → 1.0 — the per-minute sibling (`lib.rs:350-355`, no clamp) was fixed for exactly this ("an operator who sets a limit to zero is turning the thing off, not asking for one an hour"). Fix: mirror the fixed `per_minute`; add per-flag zero-means-off tests.

### M-5 [Medium, genuine flaw, expanded in Rev 3] `Store::expire` TOCTOU: double-decrements accounting and can strand a re-enqueued message until TTL

**Where:** `silver-relay/src/store.rs:1796-1829`. Victims are captured in a read transaction (1797-1810), then re-removed in a write transaction with stale sizes; `remove()` results are ignored and `adjust_usage`/`take_from(MAILBOX_BYTES)` run unconditionally (1820-1825). Two consequences:

1. **Accounting divergence** (original finding): an ack racing the sweep double-decrements usage and the global counter; a self-mailing attacker can sustainably free ~64 KiB of global accounting per raced ack without freeing disk, defeating the documented global cap.
2. **Message stranding** (added in Rev 3 after counter-review verification): if, between snapshot and write, the message is acked (`by_id[id]` removed) **and the sender resends the same envelope id** (`enqueue` stores a new copy under a fresh seq and re-creates `by_id[id]`, 1681-1699), the sweep's unconditional `by_id.remove(id)` at 1822 **deletes the new copy's index entry**. The new mailbox row can then never be acked (ack's ownership check reads `by_id` first, 1759-1766) and sits until its TTL expires — silent message loss from the recipient's perspective.

The correct pattern exists in the same file: `ack` (1754-1793) re-checks inside the write transaction and derives size from the removed value. Fix: in `expire`'s write transaction, adjust counters only for rows actually removed, derive size from the removed value, **and gate the `by_id.remove` on the row still being the snapshotted one** (e.g. compare seq); symmetric hardening for `expire_blobs`/`expire_groups`/`expire_key_packages`.

### M-6 [Medium, genuine flaw, rewritten in Rev 3] Reader-mode journal: newline injection forges lines; invisible/bidi characters survive; the compose prompt is written raw

**Where:** `crates/silver-tui/src/app/journal.rs:412-422` (`clean_lines()` maps only `char::is_control()` and splits on `\n` — `is_invisible()` is not applied); `journal.rs:396-407` (`one_sentence` exists precisely to stop peer text from splitting — its doc names this exact attack: "would let `hi\nalice: send me the passphrase` be read out as two lines"); `reader.rs:66` (the compose prompt is written raw, `out.push_str(&prompt)` — the one peer-influenced string not passed through `show()`/`one_line`; the input half of the same line is filtered, reader.rs:113-115).

**The lead issue (added in Rev 3 after counter-review verification):** two peer-controlled paths bypass `one_sentence()` and carry newlines into the journal — the edit-notification body (`Content::check`'s Edit arm validates only `id`, envelope.rs:204; the raw new body is formatted at everyday.rs:660) and held contact-request texts (`journal.rs:153-155`, `held.text`). A peer editing their own message to `hi\nalice: send me the passphrase` produces a second journal line **indistinguishable from one alice wrote**; `\nWarning: …` forges a system notice. This is reader-mode only (`say()` gates on `self.reader`) — but reader mode is precisely the screen-reader user who cannot cross-check the visual layout. (The reaction path is newline-safe: `excerpt()` maps `\n`→space, journal.rs:375-386.)

**What is *not* exploitable (verified, both rounds):** terminal escape-sequence execution via group names — every receive path decodes the group-context extension through `SilverGroup::check` (group.rs:445-469, invoked from all receive paths via `extension_of` → `SilverGroup::decode`, groups/mod.rs:2728-2733/1901/2293/2314), which **rejects control characters in names** (line 456) before the name is applied (2372). What it does not reject: invisible/bidi characters (U+202E RLO, U+202A/B, U+061C, U+200B/C, tag characters — the check's own comment at 446-449 is precise about this), which survive `clean_lines()` and reorder what the reader hears relative to what full mode renders.

**Fix:** (1) route every peer-controlled `say()` argument through `one_sentence()` at the boundary (the single choke point) or extend `clean_lines()` to apply the invisible set and refuse splitting; (2) `let prompt = one_line(&app.reader_prompt());` in `Reader::flush()` (defense-in-depth; also covers the group-alias gap, L-18); (3) extend `is_invisible()` with U+115F/U+1160/U+3164/U+FFA0/U+E0080-E00FF; (4) add a reader-mode test mirroring the full-mode invariant test (`nothing_a_peer_sends_reaches_the_terminal_raw`, ui.rs:1243-1353) covering newline injection, invisibles, and the prompt.

### M-7 [Medium, genuine flaw] Paste-guard not applied to `/send` and the remaining irreversible commands

`crates/silver-tui/src/app.rs:2327-2339` (`typed_it_themselves`), guarded today: `/revoke` (app.rs:3192), `/rotate` (3257), `/devices leave confirm` (devices.rs:601). Beyond `/devices link` (now H-2): `/send <path>` (app.rs:4742-4797) uploads an arbitrary local file to the selected contact on a single line — `/send ~/.ssh/id_ed25519\r` in the attacker's chat, mitigated only by a transfer report the victim may not read in time. `/relay <url>`, `/group join <link>`, `/unblock` are lower-impact but the same one-shot character. Fix: one mechanism, all irreversible/external-effect commands.

---

## 5b. Low findings (consolidated, renumbered Rev 3)

| ID | Finding | Where | Note |
|----|---------|-------|------|
| L-1 | No `mlock`/`VirtualLock` anywhere; keys can reach swap/pagefile (Windows `pagefile.sys` persists post-exit, admin-readable; macOS `sleepimage`; Linux swap) | workspace-wide | Fix: lock the small fixed-size key buffers (`FileCipher::key`, `IdentitySecrets`, session roots) — well under `RLIMIT_MEMLOCK` defaults |
| L-2 | Windows update swap is two renames — power loss between them leaves no binary at the target path (Unix arm hard-links first, install.rs:180-189) | `update/install.rs:169-179` | Module doc (install.rs:6-8) says the swap "cannot half-happen"; on Windows it can |
| L-3 | Rate-limit rejections log at line rate incl. anonymous connections (lib.rs:2104-2113) | relay | Aggregate per connection, warn once per minute (pattern exists: `AuthFailures::note`) |
| L-4 | Metrics listener lacks the header-read timeout/connection accounting the main listener got | `metrics.rs:346-353`, `admin.rs:338` | One uncommented compose line from public exposure |
| L-5 | `--max-mailbox-mib` plain `u64` multiply can wrap (sibling uses `saturating_mul`, main.rs:691 vs 692); `--max-mailbox-messages 0` means "always full" silently (`count >= max`, store.rs:1688) | relay main | |
| L-6 | Transparency log growth uncapped per identity (~5.7 k entries/hour/address possible, append-only, forever) | relay `lib.rs:180-184`, `store.rs:1072-1078` | |
| L-7 | One-time prekey handout budget is global per victim — one attacker's lookups starve all correspondents into signed-prekey sessions that hour | relay `lib.rs:778-787, 2018-2034, 1452-1469` | **Counter-review proposed Medium; rejected** — THREAT_MODEL.md:277-282 documents exactly this including the 30/hour figure and the consequence; the fallback retains signed-prekey forward secrecy and the post-quantum secret; hourly-bounded; `/session` exposes the property to both parties |
| L-8 | `Session::respond` never checks `init.signed_prekey_id` against the supplied SPK — silent dead sessions instead of a clean error | protocol `session.rs:356-398` | |
| L-9 | Envelope id sits outside both AEAD AAD (envelope.rs:718) and signature (698-702); a hostile relay can rewrite ids on redelivery | protocol `envelope.rs`, client `sequence.rs` | **Counter-review proposed impact upgrade; rejected** — documented and defended in sequence.rs:1-19 ("what catches it is the number inside the body, which the sender signs or seals"); outbox removal is ack-driven (connection.rs:2820-2838), not id-driven; remaining effect cosmetic (receipts name the rewritten id). Also: no `is_valid_message_id` check on receive (bounded by 128 KiB frame cap) |
| L-10 | Session/identity/prekey secrets serialize as plaintext base64 JSON — footgun for clients that persist without the vault | protocol `session.rs:190-233` etc. | Offer a sealed serialize pair |
| L-11 | TLS trust = compiled-in Mozilla roots ∪ native roots (tls.rs:243-270); on Windows a current-user root entry (no admin) MITMs `wss://` silently — **and removing a compromised CA from the OS store does not remove it from the compiled-in set**, so OS-store incident response is ineffective against the built-in list | client `tls.rs` | Union is documented for corporate proxies (THREAT_MODEL.md:252-256); `--pin` is the real mitigation (correct incl. appended-cert trick); document the incident-response caveat |
| L-12 | `silver.log` plaintext metadata side-channel inside the encrypted data dir (social graph on disk theft with vault locked); wiped by `wipe()` (store.rs:1429) but not by lock | client `store.rs:46-48`, `main.rs:543-557` | No bodies/secrets verified; document or move under data key post-unlock |
| L-13 | Homoglyph/mixed-script names unmitigated (Cyrillic-а alias spoofing) | tui | Signal-style warning glyph suggestion |
| L-14 | Fuzz gaps: `update/mod.rs` hand-rolled HTTP parser, `transparency.rs` relay answers, `vault.rs` hostile-disk files, `linking.rs` snapshot, `Pin::parse` | `fuzz/` | Update parser is highest value (feeds self-update decision) |
| L-15 | v1 (unbound) relay-auth still accepted by default for pre-0.6.0 clients (`require_bound_auth: false`, lib.rs:298) | protocol `wire.rs:17-23`, relay `lib.rs:256-259, 2308-2313` | Modern clients refuse `bound: false` unless launched with explicit `--allow-unbound-login` (connection.rs:2081-2087; test `a_relay_that_offers_only_the_unbound_login_is_refused`, login.rs:74; THREAT_MODEL.md:189-192). Residual = relay-side sunset |
| L-16 | `Content::File` metadata unvalidated at the protocol layer (the `File` arm of `Content::check` validates only `reply_to`, envelope.rs:199-203, unlike `BlobRef::validate`, group.rs:186-201) | protocol `envelope.rs` | **Downgraded from Medium in Rev 3:** the client validates size/chunk consistency on every receive path before allocating (`FileInfo::check`, files.rs:103-119; `download_bytes` connection.rs:1722, `download_file` 1785, `assemble` files.rs:208; on receipt a `Content::File` is only rendered as a label, app.rs:3508/3784). Defense-in-depth gap; one nit: `FileInfo::check` does not validate blob-id format (the relay hex-validates it) |
| L-17 | Group-sequencer squatting of never-used ids | relay `lib.rs:1163-1202`, `store.rs:1495-1538` | **Downgraded to Low in Rev 3:** PROTOCOL.md 3.5 (1498-1572) documents unused ids as first-come-first-served by design ("the id is free again — as free as an id nobody has ever used", 1547-1548); GroupIds are random 32-byte values generated locally (groups/mod.rs:1040) so the id must leak in the generation→first-create window; no `group-reset` admin command exists (identity/ban/token only). `Exists` epoch disclosure (store.rs:1519-1520) remains trivial |
| L-18 | Group *alias* is never filtered (contact aliases are: `printable` at app.rs:3100, store.rs:462-467) — `cmd_alias` (app.rs:3081-3096) and `Groups::set_alias` (groups/mod.rs:699-703) store raw, `display_name()` (249-255) returns it first, so it reaches the raw reader prompt | tui + client groups | **New in Rev 3.** Not peer-controlled (self-set or synced from the user's own devices, groups/mod.rs:1977-1980, link.rs:164), so no injection from a peer; the realistic vector is paste-injection into the unguarded `/alias` (fold into M-7's guard list). Filtering it closes the raw-prompt gap |

**Informational (documentation integrity):**

- **I-1:** `docs/design/updates.md:221-224` claims the swap is tested "under a kill: a child is killed at a random moment during the swap... twenty rounds" — **no such test exists** (tests/update.rs and tests/update_download.rs cover check/digest/sums/rollback; tests/kill.rs targets store writes, not the update swap). Documented-claim-without-test; add the test or fix the doc.
- **I-2:** The prior audit's SM-C-27 line ("`silver.log` ... not wiped by `wipe()`") is stale — current code wipes it (store.rs:1429, chain LOG_FILE into removal) and `docs/design/audit-response.md:115` already records the fix in 0.11.0. Historical record published unedited by convention (SECURITY.md:40-44); noted for completeness only.

---

## 6. Verified-solid areas (attacked and held)

Condensed from the four component audits and both subsequent review rounds; spot-checks survived two adversarial passes without a single false "verified-solid" assertion.

**silver-protocol.** HKDF/HMAC domain separation complete and injective (signatures use `domain || 0x00 || msg`). Envelope layer: XChaCha20-Poly1305 with 192-bit random nonce, AAD binds `to || ephemeral`, signature binds `to || ephemeral || nonce || body`, contributory checks on both sides; readdress/reseal/nonce-flip/version-relabel attacks fail (the version-in-ciphertext trick means a relay flipping v4↔v1 breaks the AEAD before stripping any signature). X3DH matches Signal exactly (DH1-4, 0xFF… prefix, zero-salt, AD binds both ids and both DH keys — UKS-resistant). PQXDH: ML-KEM secret in IKM with distinct label; implicit rejection handled. The "copy the public bundle signature" impersonation fails (cannot compute DH1); KCI resistance via DH2. Double Ratchet: trial-clone decrypt with state advance only on AEAD success (garbage headers burn ≤2×MAX_SKIP HMACs then roll back); MAX_SKIP=1000/MAX_SKIPPED_KEYS=2000 bounded windows; replay consumes keys; `pn`/`n` in AAD; AAD ambiguity closed by `check_lengths` with a test proving colliding encodings exist and are refused. Deniability claim matches construction. Identity: `UserId` is the Ed25519 key, canonical-y enforced, `verify_strict` everywhere, base58 decode length-capped before the quadratic path. Caps lists: name grammar makes the `\n` join injective, re-serialization attack refused. Devices: certs bound to account+device+time, sorted/capped/verified, revocation account-bound. Transparency: fixed-width hash-covered entries, fork detection, one-time-prekey exclusion property-tested. Groups: constant-time join-proof verification, small-order leaf keys rejected via trial DH, `SilverGroup::check` control-character rejection on every receive path, GroupBody shape rules enforced both directions. RNG from OsRng throughout; zeroization audited; `garbage.rs` + proptest suites exercise random bytes, bit-flips, damaged ratchet messages with no panics and no state disturbance. `#![forbid(unsafe_code)]`, zero unsafe blocks.

**silver-client.** `#![forbid(unsafe_code)]`; no panic reachable from network input. Vault crypto as designed (Argon2id 64 MiB/3/1 + XChaCha20-Poly1305, filename AAD, atomic write with restore-on-fail, half-finished rotations detected and healed at unlock — the file layer of rotation is careful; M-1 is its one hole). **Stale-prekey freshness is enforced (verified in Rev 3 after the original audit claimed otherwise):** initiating rejects signed prekeys older than `SIGNED_PREKEY_RETENTION = 21 days` with `SessionError::StalePrekeys` (sessions.rs:473-479, 57; regression test `a_stale_signed_prekey_starts_no_session`, 1076-1091) and the receiver prunes private halves past the same window (704-709) — matching key retention. **Session-state discipline (verified in Rev 3):** a new handshake's state is persisted only *after* the first successful decrypt (decrypt at 574 precedes push/persist at 602-611; every error path returns before writing); stranger-minted state is bounded by `MAX_SESSIONS_PER_PEER = 5`, `MAX_SESSION_PEERS = 256`, and a 180-day retention + least-useful-eviction sweep preferring never-written-to peers (`make_room`, 639-662 — the SM-C-14 fix). Sequence/replay: 64-message late window, epoch carry-over kills pretend-reinstall, id-rewrite caught by in-body signed sequence numbers (documented defense, sequence.rs:1-19). Outbox: id-dedup, encrypted, atomic, ack-driven removal, relay-dedup-safe resend. Transparency client: answers held until catch-up, fork evidence preserved, two-checkpoint anchoring. TLS client: pinning correct including appended-leaf; anonymous connector disables resumption. Proxy: bounded CONNECT parse, per-connection SOCKS credentials for Tor isolation. Update chain (official builds): four independent verification layers, redirect confinement, self-test, atomic swap with rollback, package-manager ownership detection. Files: per-chunk AEAD with blob-id/index/count AAD, whole-file SHA-256, `FileInfo::check` size/chunk validation on every fetch path, `sanitize_name` fuzz-pinned and idempotent, no-overwrite downloads, MoTW with failure reported, `/open` allowlist, aggregate downloads quota multiply-enforced and test-pinned (`downloads_quota_mib`, default 1024 MiB). Linking/devices: sealed provisioning, account-confirmation callback, capped idempotent snapshots; the *linking* issuance itself is H-2's gap, not the crypto. `IDENTITY_FILES` registry is the right structural fix for the 0.10.1 plaintext-MLS class.

**silver-relay.** Prior 76-finding audit's relay-side fixes re-verified as holding (§7). Auth: 32-byte OsRng challenge, Ed25519 `verify_strict` with domain separation, `ct_eq` invite token, auth timeout; challenge host-binding checks the relay's configured names (SM-R-02 fix at lib.rs:2294-2306). Mailbox: `to` is a serde-parsed canonical `UserId`; ack double-verifies ownership inside one write transaction (store.rs:1768-1790); monotonic positions; `BY_ID` dedup makes resends idempotent. No unauthenticated deletion path. redb single-transaction check-and-write on every store operation (M-5's sweep is the one read-then-write exception). Registration/publish/revocation self-authenticating and budget-bound. DoS discipline: 128 KiB caps, header-read + auth + idle + write timeouts, bounded queues/windows, leak-free connection guard, chunk accounting `max(len, 1024)`. `#![forbid(unsafe_code)]`, no remotely reachable unwrap/expect on non-test paths, no SQL/no path construction from user input, blob ids hex-validated (path traversal refused, tested). Metadata hygiene: per-run salted pseudonymous logs, decode errors logged as class/line/column only, metrics address-free. TLS: safe-default rustls, ALPN correct, exact-name ACME challenge certs, renewal keeps last good cert. Deployment: `FROM scratch`, USER 1000, digest-pinned bases, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, systemd `ProtectSystem=strict` + syscall filter + 0700 state.

**silver-tui / supply chain.** Full-screen render: all peer text reaches the screen only through the ratatui cell buffer — **pinned by a test** (`nothing_a_peer_sends_reaches_the_terminal_raw`, ui.rs:1243-1353) covering OSC 2/52/8, CSI, CR, BS, ST, RLO, ZWSP on the real backend. Sanitizer architecture (`safe_text`/`one_line`/`printable`/`is_invisible`/`one_sentence`) applied at every boundary (toasts, reader input, export, both clipboard backends, update strings, device names, filenames) — the reader-mode journal paths of M-6 are the exceptions that prove the rule. Clipboard: no background monitoring exists; copy sanitized before OS and OSC 52; base64 kills terminator injection. Notifications constant-string, tmux ESC-doubling test-pinned. silver-tui is `#![deny(unsafe_code)]` with a single allowed `unsafe` block (pre-runtime, single-threaded `env::remove_var`, tui main.rs:270-282) carrying a correct safety argument. Supply chain: committed `Cargo.lock` + `--locked` everywhere; `cargo-deny` + `cargo audit` on both lockfiles in CI; exact toolchain pin; SHA-pinned actions; release job isolated behind `environment: release`; SLSA provenance, SBOM, reproducibility info; `signing-check.yml` proves the minisign keypair matches; dependency list mainstream with no typosquats; `rand 0.8` and `zbus 4.4` pins deliberate and documented. Formal models: no spec-to-code drift found; the README's stated exclusions match the code; the v2 replay partition (cryptography refuses forgery; client refuses replay) is implemented as specified.

---

## 7. Regression verification of the prior external audit

The relay component re-verified the relay-side findings from `docs/audits/2026-09-security-audit.md` (commit 05e1168): SM-R-01, SM-R-02 (fix at lib.rs:2294-2306), SM-R-03, SM-R-04 (store.rs:1690), SM-R-05/06/07, SM-R-09, SM-R-10, SM-R-11, SM-R-12, SM-P-02 (identity.rs:114-117), SM-R-13 — **all confirmed fixed in the current tree**, with one regression-class note: the `0-means-one` bug SM-R-13 fixed for `per_minute` survives in `per_hour` (M-4). Client-side SM-C-03 (no v1 fallback) and SM-C-14 (session eviction) were likewise re-confirmed. SM-C-27's line about `silver.log` is stale in the historical document (already answered in audit-response.md:115; see I-2).

---

## 8. Remediation roadmap (Rev 3 priority order)

1. **H-2 + M-7 (one mechanism):** route `/devices link`, `/send`, `/alias`, `/relay`, `/group join`, `/unblock` through `typed_it_themselves`; add an explicit consequence-naming confirm to `/devices link` (standing identity-signed device certificate). Highest value-per-line in this report.
2. **M-6:** `one_sentence()` at the `say()` boundary (or `clean_lines()` newline + invisible handling); `one_line()` on the reader prompt; reader-mode invariant test covering newline forgery.
3. **M-1:** safe KEK eviction — `pending_kek_deletions` list drained at next unlock **plus** directory fsync in `write_atomic` (mirror install.rs `sync_dir`); startup `data-key-*` sweep; compensating deletes. (Do **not** delete after the first vault write without the dir fsync — see M-1's fix discussion.)
4. **H-1:** SECURITY.md platform-parity statements; non-zero `lock_after_minutes` default for passphrase-protected dirs; macOS hardened-runtime signing without notarization secrets.
5. **M-3:** `--allow-unsigned` gate for missing-minisign builds; align `build.rs` docs. **I-1:** add the kill test or fix updates.md.
6. **M-5, M-4:** relay: expire write-transaction accounting + `by_id.remove` gating (both consequences); `per_hour(0)` semantics.
7. **M-2:** downgrade visibility to the user ("session with X is not post-quantum"); L-15 v1 sunset plan.
8. **L-1..L-18** — as scheduled work.

---

## Appendix A — Live runtime compromise (Windows, 2026-09-09, authorized)

- **Target:** unlocked `silver-v0.14.0.exe` (PID redacted), default data directory, passphrase-protected vault (Argon2id 64 MiB/t3/p1).
- **Method:** unprivileged same-user Python process; `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)`; `VirtualQueryEx` walk of 494 readable committed regions (74 MB); every 32-byte window tested as an XChaCha20-Poly1305 key against a known SMV1 file body (`config.json`, AAD = filename). Key recovered in **6 s**. (Methodological note: testing against `vault.json`'s `wrapped_key` fails by construction — that blob authenticates the *transient Argon2id KEK*, zeroized after unlock; the persistent secret is the data key inside it. File bodies, whose Poly1305 tags verify under the data key, are the correct oracle.)
- **Result:** full decryption of the data directory (identity seed, sessions, MLS state, 100% of history). Also recovered: two orphaned `data-key-*` KEKs from Credential Manager via `CredRead` (zero privilege, no prompt) — see M-1 for the corrected provenance analysis.
- **Also observed:** the decrypted `config.json` yielded the client's
  runtime configuration, including the relay it was in use with and that
  relay's negotiated feature map. Those values are per-user runtime
  configuration, stored only in the encrypted `config.json` — which is
  the point: they appear nowhere in the repository, and recovering them
  is what demonstrates the decryption succeeded. **The relay hostnames,
  the shell history that corroborated them, and the process and
  credential identifiers have been redacted from this published copy
  (see the note at the head of this file); they are operator
  infrastructure, not a finding.** Also from the decrypted config, and
  not sensitive: `lock_after_minutes: 0` (see H-1's remediation) and
  `downloads_quota_mib: 1024` (the default, corroborating the retraction
  in Appendix B.3). The decrypted copies were deleted after the live
  exercise at the requester's instruction. No network checks were
  performed against any relay during this audit — all live work was
  local (process memory, disk, credential store).

## Appendix B — Reaudit log (Rev 2)

A second, independent adversarial pass re-verified every High/Medium finding, a sample of Lows, and spot-checked the §6 verified-solid claims against the source. Corrections incorporated:

1. **Former H-3 (reader-mode terminal injection) downgraded and merged into M-6.** The claim that group names are "not re-validated on receipt" was wrong: `SilverGroup::check` rejects control characters in group names on every receive path, blocking every escape-sequence payload proposed. The surviving residual (invisible/bidi characters, raw-written prompt) is documented in M-6.
2. **Former M-1 (v1 relay-auth downgrade enabler) reclassified to L-15.** Clients refuse `bound: false` unless explicitly launched with `--allow-unbound-login` (connection.rs:2081-2087; test-pinned; documented).
3. **Former L-14 (no downloads aggregate quota) retracted and deleted.** The quota exists, defaults to 1024 MiB, is enforced at four layers, and is test-pinned. The audit machine's own decrypted `config.json` corroborates.
4. **Former M-2 corrected:** `KeyBundle::verify` is at bundle.rs:109-153; the v1-fallback step is blocked client-side (SM-C-03); the downgrade chain is PQ/caps-only (now M-2).
5. **Citation fixes:** the full-mode raw-terminal invariant test lives in ui.rs:1243-1353; the `/proc/<pid>/environ` note is a code comment at tui main.rs:225-226 (SECURITY.md has no platform statement — strengthening H-1); the reaction-emoji carrier in the reader journal is the excerpt target, not the emoji (protocol-validated at envelope.rs:212-225).
6. **Consistency fixes:** Low count aligned; the executive summary's `unsafe` wording corrected to name silver-tui's `deny` + single reviewed exception; finding overlap resolved by merges.

**Standing after Rev 2:** H-1, H-2 (then the KEK finding), M-2..M-8, 6 of 7 sampled Lows, all 13 sampled verified-solid claims, and the §7 regression table.

## Appendix C — Counter-review verification log (Rev 3)

A third review (by a second external reviewer, "Claude") produced 15 claims: two refutations of report findings, three severity-downgrade proposals, three severity-upgrade proposals, six new findings, and one method criticism. Each was adversarially verified against the source:

1. **"Stale prekey never enforced" — Claude right, finding refuted.** Client enforces `SIGNED_PREKEY_RETENTION = 21 days` on initiate (`StalePrekeys`, sessions.rs:473-479; test 1076-1091) and prunes receiver-side (704-709). Former L-11 deleted; §6 updated; M-2's stale-bundle scope narrowed accordingly.
2. **"Responder state persisted unauthenticated, never cleaned" — Claude right, finding refuted.** Persistence only after first successful decrypt (574 before 602-611); caps (5/peer, 256 peers) plus 180-day retention and least-useful eviction (SM-C-14). Former L-9 deleted; §6 updated.
3. **"KEK orphans should be Low" — rejected as Low, accepted as Medium (downgraded from High).** The double-access argument has merit; the silent-permanent-guarantee-break and mitigation-path arguments defeat Low. Argued in M-1.
4. **"`Content::File` is client-defended" — accepted, downgraded to L-16** (all receive paths validate; label-only rendering on receipt; blob-id nit noted).
5. **"Sequencer squatting documented" — accepted, downgraded to L-17** (PROTOCOL.md 3.5 records first-come-first-served; random GroupIds narrow the window).
6. **"`/devices link` is High" — accepted, promoted to H-2 and rewritten.** The impact is a standing identity-signed device certificate (connection.rs:1591) granting read/write-as-user until revocation — the original description ("history upload") was materially wrong.
7. **"Prekey drain is Medium" — rejected.** Documented including the 30/hour figure and consequence (THREAT_MODEL.md:277-282); fallback retains signed-prekey forward secrecy and post-quantum protection; hourly-bounded. Stays L-7.
8. **"Journal newline forgery" — accepted as the new lead of M-6.** `one_sentence`'s own doc names the attack; the edit-body and held-text paths bypass it.
9. **"Group alias unfiltered" — accepted as L-18** (self-set/own-device-synced only, so not peer injection; paste vector folded into M-7).
10. **"Expiry race strands re-enqueued messages" — accepted, folded into M-5** with the `by_id.remove` gating added to the fix.
11. **"updates.md kill test doesn't exist" — accepted as I-1.**
12. **"Prior audit's log-wipe line stale" — accepted as I-2 (footnote; audit-response.md already answers it).**
13. **"Envelope-id rewrite matters" — mechanism confirmed, impact upgrade rejected.** Id is outside AAD and signature (envelope.rs:698-702, 718-727), but the documented sequence-number defense (sequence.rs:1-19) and ack-driven outbox removal close every consequential path found. Stays L-9.
14. **"Trust-store union blocks OS-store incident response" — accepted into L-11.**
15. **"The report's H-2 remediation is unsafe" — accepted, and it is the most important correction of the round.** `write_atomic` does not fsync the parent directory (store.rs:2164-2179), so delete-after-first-write can orphan the vault on POSIX. M-1's fix rewritten around the pending-list design plus a directory fsync (mirroring install.rs:245-254).

**Note on the review chain:** three independent review passes (initial audit, reaudit, counter-review verification) each found material errors in the previous round — including in this report's own remediation advice. The findings in this revision are the residue that survived all three; the remediation roadmap above reflects every accepted correction.

---

*End of report (Revision 3).*
