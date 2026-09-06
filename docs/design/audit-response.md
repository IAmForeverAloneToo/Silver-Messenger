# Design note: the response to the 2026 security audit

Roadmap item 55. An independent adversarial review of the 0.10.0 line
(commit `05e1168`) reported 76 findings; the report is published as
[docs/audits/2026-09-security-audit.md](../audits/2026-09-security-audit.md).
This note records, for every finding, what the code was found to do when
the finding was checked against it, what is done about it, and in which
release. It was written before the fixes and held back from the
repository, with the report, until the patch release carrying the
Critical and High fixes was cut, as [SECURITY.md](../../SECURITY.md)
asks of everyone else. Where this note and the code later disagree, the
code wins and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| How the findings were checked | Every finding was traced in the source at `05e1168` before anything was changed: the cited lines, the callers, the tests that enshrine the behaviour, and the vendored crates where a claim rested on one (rustls and webpki for the pin, hyper and axum-server for the missing timer, OpenMLS for the commit builder and the sender ratchet, bs58 for the decoder, which was also timed). The verdicts are in section 3: 70 findings confirmed as written, 6 confirmed in part with the difference stated, none refuted. Three findings turned out worse than reported and one new problem was found on the way; both are recorded. |
| What ships first | The Critical and the ten Highs, with the Mediums that share their code paths, as the patch release 0.10.1: the report's section 13.1 as verified. A patch release changes no wire format: every fix in it is a stricter reader, a stricter relay, or a client that refuses what the specification already said it refuses. A 0.10.1 client works with a 0.10.0 relay and the other way round, with the exceptions section 5 lists. |
| What ships next | The remaining Mediums and the Lows as 0.11.0, the report's section 13.2 as verified, each with its own tests; where one looks like it needs a wire change it goes in as an optional field or a rule that honest 0.10.x peers never trip. In the event the sequencer fix needed neither (SM-R-08): the values a client already sends to re-create a lost entry are exactly the ones a headstone asks for. |
| What waits for 1.0 | The report's section 13.3: message ids inside the authenticated body, rollback protection for the key-bearing files, the identity-key binding of the v4 handshake, device counter-signatures, HMAC-named history files. Each is a protocol or on-disk format change that deserves its own design note; the roadmap lists them under Phase 11. |
| Where a fix the report suggests is not taken | The note says so and why (section 3). Three matter: refusing at `publish` a device list that names an id with a plain bundle would refuse every 0.9.0 and 0.10.0 primary, whose linking flow publishes the list before the device claims the account; a first-frame size cap on the relay would refuse legitimate anonymous first frames; a transcript signature in the v4 handshake is not deniable, contrary to the report's aside. |
| How the relay is protected meanwhile | The test relay runs the fixed relay from the day the relay fixes land on `main`, upgraded by hand over the maintainer's own connection to it, before the release is cut. Other operators upgrade with the release; the changelog's `Security` section says why. |
| Disclosure | The findings are the maintainer's to publish. The report goes into the repository whole with the patch release, this note beside it, and the changelog's `Security` section says what each finding was and what was done about it. No separate security advisories: section 6 says why, and carries the affected-version table an advisory would have held. |

## 2. What the audit got right about the code, in one paragraph

The cryptographic core holds: nothing in `silver-protocol` was found to
let a relay, an observer or a stranger read a message or forge one. The
findings sit where a signed statement was trusted one step too far (a
device list names an id the relay never checked is nobody else's; a
revocation is applied without asking whose device it revokes; a Welcome's
own extension is taken as proof of who is an admin), where the relay's
word was taken for a security downgrade (the unbound login, the feature
list, a stripped bundle), and where a bound was missing (identifiers
decoded before their length is checked, connections uncounted before the
upgrade, mailboxes for recipients that do not exist, parked group messages
of any size). That is the shape of the fixes: check the binding, remember
the promise, add the bound.

## 3. Verdicts and decisions

Verdicts: **C** confirmed as reported, **P** confirmed in part (the
difference is stated), **W** worse than reported. Release: **0.10.1**,
**0.11.0**, **1.0** (design note first), **doc** (a documentation change
closes it), **kept** (a design choice the note defends).

### 3.1 Protocol (`silver-protocol`)

| ID | Sev. | Verdict | Decision | Release |
| --- | --- | --- | --- | --- |
| SM-P-01 | High | P: the relay-served path is narrower than stated (a lookup of contact A drops a statement naming another account; it passes only on a lookup of the device itself), and the effect is not a permanent severance but a repeatable loss: every session with the device dropped, so its messages in flight fail, and one of its one-time prekeys burned per repeat. | `DeviceRevocation::verify_for(account)`; the client applies a pushed statement only when it knows the device under that account, and a served one only when the account matches; §14.2 reworded. | 0.10.1 |
| SM-P-02 | High | W: the client is exposed too, through a hostile relay's `lookup_result` and `deliver`, with tungstenite's 64 MiB default in place of the relay's 128 KiB. | Length cap of 44 characters before decoding in `UserId` and `GroupId`, 22 for link secrets; a client-side frame cap (SM-C-17). The report's first-frame cap is not taken: an anonymous connection's first frame is legitimately a `send` or a `blob_put`. | 0.10.1 |
| SM-P-03 | Medium | C. Hiding `devices` has little effect (fan-out reads the signed list); the v3 downgrade and the missing `groups` are the impact. | `KeyBundle::verify` refuses a capability name outside `[a-z0-9_]`, which makes the join injective without a wire change; §2 states the rule. The length-prefixed form waits for a domain bump at 1.0 (every 0.10.x peer would fail to verify bundles otherwise). | 0.11.0 |
| SM-P-04 | Medium | C. v4 only, towards `pq_ratchet` peers. | Documentation now: the X25519 key is an impersonation key from v4 on, said in the threat model's assets table and its compromised-key section, and in §4.2.1. A protocol fix is a design note for 1.0; the report's transcript signature would not be deniable. | doc, 1.0 |
| SM-P-05 | Medium | W: the same ordering bug (merge, then frame, then seal) fires on any sealing failure, and one is attacker-chosen: a member whose leaf carries a low-order X25519 seal key, which every reader accepts and which makes `seal_bytes_to` fail for everyone. | Sender threshold set to what encodes for every kind (24 360 bytes), the reader's limit unchanged; envelopes framed and sealed before the commit is merged and before the sequencer is asked; low-order seal keys refused at leaf verification. | 0.11.0 |
| SM-P-06 | Low | C, and the "unable to encapsulate" consequence is not reachable (the trial state is discarded). | Lengths of `kem` and `kem_ct` checked before the AAD is built. | 0.11.0 |
| SM-P-07 | Low | C. | A re-certification carries a later `created_at_ms`, so the list signature and the leaf change with a rename; §14.1 says what the signature covers. | 0.11.0 |
| SM-P-08 | Low | C. | The invisible set refused in group and device names at creation; not in the decoders, which would make existing names unverifiable. | 0.11.0 |
| SM-P-09 | Low | P: edits, deletions and reactions already check their ids through `Content::check`; only a message's own id is unchecked. | `GroupPlaintext` applies the same rule; §13.3 aligned with §14.4. | 0.11.0 |
| SM-P-10 | Info | C. | Canonical encoding required in `UserId::from_bytes`. | 0.11.0 |
| SM-P-11 | Info | W: `sync devices` carries the same unbounded list on every list change. | The sender bounds both lists to the newest 16 revocations; the caps stated honestly. | 0.11.0 |
| SM-P-12 | Info | C. | `encode` checks the name. | 0.11.0 |
| SM-P-13 | Info | C; no fuzz target reaches decapsulation, which a stranger's handshake does. | A `pq` fuzz target; the audit status recorded in the assessment and the threat model. | 0.11.0 |
| SM-P-14 | Info | C; where a body carries an `id` it wins over the envelope's, so only bodies without one are exposed to renaming. | §12.1 says which id is the authenticated one; binding waits for 1.0. | doc, 1.0 |

### 3.2 Relay (`silver-relay`)

| ID | Sev. | Verdict | Decision | Release |
| --- | --- | --- | --- | --- |
| SM-R-01 | Critical | W: the revocation is logged under the victim's subject, so every 0.10.0 contact's lookup of the victim is refused as a withheld revocation and nothing is sent; an admin cannot undo it; a listed-but-unregistered id is also squatted for good. | A revocation is taken only for a device whose bundle claims the account, or one on the list that has no bundle of its own; its effects (refused login, publish and delivery) apply only to an id whose bundle carries the account's certificate, so a poisoned row in an existing database goes inert; `publish` refuses a list naming a device whose bundle claims another account; `silver-relay admin unrevoke-device`. The report's publish-time rule against plain bundles is not taken: it would refuse every 0.9.0 and 0.10.0 primary's linking flow. | 0.10.1 |
| SM-R-02 | High | C; the specification prescribed the flawed check. | `--host` (and the ACME domains and the certificate's names by default): a bound login is accepted only for a host in that set, the request header no longer counts; a relay with no names configured keeps today's check and says so at start. §7.1 reworded. | 0.10.1 |
| SM-R-03 | High | C. | Both listeners served through the same builder with a timer and a ten-second header-read timeout; a per-address slot taken at accept time. | 0.10.1 |
| SM-R-04 | High | C. | An envelope to an id without a bundle is refused `not_found`; a relay-wide mailbox cap (`--mailbox-storage-mib`) tracked like the blob cap. | 0.10.1 |
| SM-R-05 | High | C. | A per-connection `publish` bucket sized for linking (six a minute) and a per-identity cap on logged bundle changes per hour. | 0.10.1 |
| SM-R-06 | Medium | C. | `ack` checks the id in a read transaction and writes only on a hit; a bucket sized for a mailbox drain. Moving store work off the runtime workers is 0.11.0. | 0.10.1 |
| SM-R-07 | Medium | C. | Done in 0.11.0. A sixteen-envelope delivery window per connection, refilled from the mailbox in order as acknowledgements arrive; a bounded outbound queue holding only what the relay pushes, with replies written straight to the socket; a thirty-second write timeout, counted as `silver_relay_slow_closed_total`. The registry holds the only sender, so an eviction ends the connection even when the queue is full. Blob chunks are not streamed: a chunk is 64 KiB and one is sent per `blob_get`, so it is already the page. | 0.11.0 |
| SM-R-08 | Medium | P: the race before the creator's first `group_create` is not real (the id is random and registered first) and the epoch disclosure is specified; the 180-day expiry and a restore from an older backup are the real openings. | Done in 0.11.0, and without the wire field the decision first called for. An idle entry is retired rather than dropped, leaving a headstone with the epoch and token hash the group died at; it is raised only by a `group_create` for exactly those values or by a `group_commit` carrying that epoch's token, both of which need the group's exporter at that epoch. That is what a client already sends to re-create an entry the relay lost, so no field and no version gate: a 0.10.x client recovers as it always did, and only somebody outside the group at that epoch is refused. The headstone goes after a further 180 days. A restore from before a group's creation still reopens the id; the operator's guide says so. | 0.11.0 |
| SM-R-09 | Medium | C. | `checked_add`; `epoch: u64::MAX` refused at creation; a drop guard runs `unregister` on any unwind. | 0.11.0 |
| SM-R-10 | Low | C. | A revoked identity is refused at login, its mailbox dropped, delivery to it refused. | 0.11.0 |
| SM-R-11 | Low | C; the shipped deployments bind IPv4 and are unaffected. | Addresses canonicalised before every comparison. | 0.11.0 |
| SM-R-12 | Low | C, and one line per frame inside a session, not per connection. | The log gets the error's kind and position, not its text; the rate-limit warning once per connection. | 0.11.0 |
| SM-R-13 | Low | C, every bullet. | Minimum chunk size and a per-chunk charge; envelope ids validated on `send` and `ack`; the startup line reads the effective invite policy; `--message-ttl-days` and `--lookups-per-minute` bounded; the data directory's mode set only when the relay created it; `at_ms` in the log named in the threat model. | 0.11.0 |

### 3.3 Client library and terminal client (`silver-client`, `silver-tui`)

| ID | Sev. | Verdict | Decision | Release |
| --- | --- | --- | --- | --- |
| SM-C-01 | High | C, and `--print-pin` itself invited pinning an issuer key. | A pin must match the leaf, which is what `--print-pin` prints first and what the README's recipe computes; the extra certificates are no longer listed as pinnable. Anyone who pinned an issuer key must re-pin. | 0.10.1 |
| SM-C-02 | High | W: encrypted downloads are a fourth omission, and the toast that says `/open` still reads them is wrong after unprotecting. | One list of the store's files, shared with `wipe`, with the three files and a pass over `downloads/`; a test that protects and unprotects a directory holding every file. | 0.10.1 |
| SM-C-03 | Medium | C. | `seal_for` refuses a peer without prekeys, as §8 says; a contact whose prekeys vanish from a served bundle is reported like a key change and not re-pinned. | 0.10.1 |
| SM-C-04 | Medium | C; the payoff is the sealed mailbox (metadata, acknowledgement, denial), not content. | The client refuses a challenge without `bound` unless `--allow-unbound-login`; §7.1's client rule changes. | 0.10.1 |
| SM-C-05 | Medium | C. | Done in 0.11.0: the features a host has ever offered are remembered in the settings, and anything withdrawn is said plainly, with what it costs, on every connection until the relay offers it again. Refusing lookups until an explicit `/relay accept` was dropped: it would leave a client that cannot look anyone up with no way out but a command it has to be told about, where the warning already says what is wrong and repeats. |  0.11.0 |
| SM-C-06 | Medium | C. | A transparency refusal aborts the send; lifecycle statements that verify are raised even from a refused answer. | 0.10.1 |
| SM-C-07 | Medium | P: replies are not readable by a holder of the identity key alone (the outer layer is sealed to the pinned X25519 key); the impact is unflagged impersonation towards the recipient and lost replies for the real contact. | Done in 0.11.0: the inbound handshake's `identity_dh` comes up with the session event, the front end compares it with the pinned bundle, and a mismatch drops the session and says the message may not be from the contact. |  0.11.0 |
| SM-C-08 | Medium | W: any error inside the re-encryption (a corrupt file, a full disk) has the same effect as a crash, deterministically. | The vault written first, then the files; a self-heal on unlock re-encrypts any store file found plain in a protected directory. | 0.10.1 |
| SM-C-09 | Medium | C. | Done in 0.11.0. The check reads the remembered proxy and extra roots when the command line names none, so it goes the way the relay connection goes. A protected directory asks for its passphrase, since the settings are under the data key; `--proxy` answers the question without it. | 0.11.0 |
| SM-C-10 | Medium | C. | Done in 0.11.0. The directory 0700 and tightened on the way if an older version left it wider (only when it is ours: `--data-dir` could name a home directory), every store file through the private writer, downloads, exports and backups 0600 in a 0700 directory, and the outbox and transparency writes synced like the rest. | 0.11.0 |
| SM-C-11 | Medium | P: the Windows, macOS and macro-document omissions are real; the Linux additions are not (no executable bit; nothing opens `.service`); the mark-of-the-web gap is Windows-only. | Done in 0.11.0, and the denylist is gone rather than kept as a second gate: an allowlist makes it redundant, and two lists to keep in step is one more than the bug needs. Pictures, PDFs and e-books, macro-free documents, text, sound, video and archives go to the opener; everything else, extension or none, does not. The `.open/` copy carries the mark of the web and a copy that could not be marked is reported. | 0.11.0 |
| SM-C-12 | Medium | C; a crafted line also hides a real pending fetch. | A parsed path is taken only when it lies in the downloads directory, and `/open` and `/files decrypt` refuse anything outside it; the saved name is stored as data from now on, the text parser kept for old lines. | 0.10.1 |
| SM-C-13 | Low | C. | Done in 0.11.0. The hint is carried only when the failure came from a session this client holds — a session id nobody else can know — and is `None` otherwise, so no contact is named and the blocked list has nothing to bypass; the notices are gathered into one line a minute. |  0.11.0 |
| SM-C-14 | Low | C. | Done in 0.11.0: at most 256 peers with session state, the least useful evicted first (a stranger heard from but never written to, then the longest unused), and a peer unused for six months dropped. Not persisting a stranger's session until the user accepts them needs the contact list, which the client core does not hold; the cap does the same work without moving that decision. |  0.11.0 |
| SM-C-15 | Low | C. | Done in 0.11.0: a sixty-four-message window below the highest sequence, so a late message is shown once; the previous epoch's end remembered, so numbering cannot go back into an epoch already finished with; at most six deposits of fresh one-time keys an hour and four deposits' worth of handed-out private halves kept. |  0.11.0 |
| SM-C-16 | Low | C. | Done in 0.11.0: an `AnonymousSubmission` event, `sender seen` in the status line while sends are not anonymous, and `--require-anonymous`, which disconnects rather than fall back. |  0.11.0 |
| SM-C-17 | Low | C; the cap must exceed one frame, since a lookup answer carries up to nine bundles. | A WebSocket message cap of ten frames' worth; chunks over the chunk size refused. | 0.10.1 |
| SM-C-18 | Low | C. | Done in 0.11.0: the head and checkpoints that disagreed are kept as evidence (up to eight breaks) and `/log` shows each. Refusing lookups until the user acknowledges is not taken: the warning repeats and says what it means, and a messenger that stops working is one people stop using — the same call as SM-C-05. |  0.11.0 |
| SM-C-19 | Low | C. | Done in 0.11.0: a `delete` body's ids go through the history file in one pass, and an id the file does not hold leaves nothing on disk, being held in the bounded in-memory list instead. A per-conversation size ceiling with compaction is not added: with the unbounded writes gone, what is left grows with what the user actually receives. |  0.11.0 |
| SM-C-20 | Low | C. | Done in 0.11.0: one filter in `files` (`safe_text` keeping line breaks, `one_line` collapsing them) applied to the text export, the release check's own output and the status line it may carry, the clipboard, the reader's journal and the reader's compose echo. |  0.11.0 |
| SM-C-21 | Low | C. | Done in 0.11.0: at most 1 GiB, 16 passes and 8 lanes, checked in the one place that stretches a passphrase, so the vault and the backup reader are both covered. | 0.11.0 |
| SM-C-22 | Low | C. | Done in 0.11.0. Passphrases from the terminal and from the environment are held in zeroising strings; the environment one is spent on the first unlock, so a lock asks again, and `--keep-passphrase` is the opt-in for a run nobody is sitting at. What `/proc/<pid>/environ` keeps is not this program's to erase, and the threat model says so. | 0.11.0 |
| SM-C-23 | Low | P: without a key store the key does rotate, through a plaintext hop on disk. | Done in 0.11.0. Every protection change moves the files onto a fresh key with no plaintext state: the vault names both keys while the rewrite runs, so a crash leaves a directory that still opens, and the next unlock finishes the move and drops the old key. | 0.11.0 |
| SM-C-24 | Low | C. | A sealed manifest of the key-bearing files checked at unlock; history binding with it. | 1.0 |
| SM-C-25 | Low | C. | Documented now; HMAC-named files and padded lines at 1.0. | doc, 1.0 |
| SM-C-26 | Low | C. | Done in 0.11.0: an explicit `note` flag on history lines, set by the note writers alone, with the old guess kept only for lines written before it; and a paste rule on `/revoke`, `/rotate` and `/devices leave`, which refuse a confirmation that arrived faster than anyone types. |  0.11.0 |
| SM-C-27 | Info | C, with two corrections: the false-fork trigger is a peer head ahead of ours while the log is more than 4 096 entries behind, which a relay can arrange; `silver.log` records full ids at `warn`, not only at `debug`. | Each bullet fixed: the fork check verifies instead of accusing; the log gets short ids and filtered relay strings and is wiped with the directory; an instance lock; link relays validated; the reader screen cleared on lock; relay strings filtered; `/add` aliases sanitised. | 0.11.0 |

### 3.4 Groups, devices and linking

| ID | Sev. | Verdict | Decision | Release |
| --- | --- | --- | --- | --- |
| SM-G-01 | High | W: no membership is needed (the sealed sender is a hint), the parked body is fetched before the client checks it is in the group, and the figures multiply by every group id the attacker knows. | Only inline-sized messages are held and the bytes held per group are capped; the client fetches a parked body once per blob, and only for a group it lists or as a Welcome, which is how a group first arrives; a per-kind cap on parked sizes in `validate` (handshakes and Welcomes 1 MiB, application messages 64 KiB), which honest senders never reach. | 0.10.1 |
| SM-G-02 | High | C. | An expected group's Welcome is taken without asking only from the account's own identity, as §14.7 already says; from anyone else it is an ordinary invitation, shown under its own author's name, and what the primary promised stays unspent. A second Welcome for a group already joined or already inviting is refused rather than replacing it (reading one means throwing the first away), and declining makes room. | 0.10.1 |
| SM-G-03 | Medium | P for its third case (the admins get `MissingProposal`, nobody is blamed; the desynchronisation is real). | A member's own Remove may be referenced by any committer; a non-admin's commit does not consume the proposal store; an admin's leave takes it out of the admin list in the same commit and a reader tolerates an admin whose every leaf left by its own proposal. | 0.11.0 |
| SM-G-04 | Medium | C; Update proposals are unreachable today, so the update-path leaf is the whole of it. | The committer's new leaf verified and required to keep its account and device; a failure after the merge marks the group broken by the committer instead of returning an error. | 0.11.0 |
| SM-G-05 | Medium | C; OpenMLS exposes no way to verify the other leaves before `into_group`. | Any failure after `into_group` deletes the group's storage; invitations capped; the credential check that is possible done before. | 0.11.0 |
| SM-G-06 | Medium | C, at the low end: the amplifier needs a contact. | Rate limits on rejoins per device and on joins per group, not confirmations, which would break the documented link-join flow for every appointed admin. | 0.11.0 |
| SM-G-07 | Medium | C. | The new device shows the account it is about to belong to and asks before adopting the link; `--link --account <id>` for scripts. The AAD is not changed (it would break 0.10.0 primaries). | 0.11.0 |
| SM-G-08 | Medium | C. | At most nine leaves per identity and a total leaf cap, refused by readers and by `stage_add`. | 0.11.0 |
| SM-G-09 | Low | C. | The two recovery paths wired into the terminal client. | 0.11.0 |
| SM-G-10 | Low | C. | The old state dropped only after the Welcome is verified. | 0.11.0 |
| SM-G-11 | Low | C. | Request packages kept out of the deposit and pruned after a day. | 0.11.0 |
| SM-G-12 | Low | C. | The record persisted after every mutation, success or not. | 0.11.0 |
| SM-G-13 | Info | C, all four; the `Head` bullet was traced to the fork alarm. | The sender ratchet set to the documented 64; `Head` carries its group and is skipped for unlisted groups and blocked members; invite links checked at the identity level per §13.7; the device-pinning bullet kept as designed. | 0.11.0 |

### 3.5 Deployment, packaging, CI and supply chain

| ID | Sev. | Verdict | Decision | Release |
| --- | --- | --- | --- | --- |
| SM-S-01 | Medium | C; the unhedged sentences are the README's and SECURITY.md's, not the threat model's. | The signing key lives on a maintainer machine, under a passphrase, and signs `SHA256SUMS` out of band after the release is published; the workflow's signing step goes; the README, SECURITY.md and the threat model say what is signed and by what until then. | 0.11.0 |
| SM-S-02 | Low | C; the release was built with 1.98.1, not the 1.94.1 the report suggests. | The toolchain pinned in `rust-toolchain.toml`, every workflow and the Dockerfile; the compiler named in the release notes. | 0.11.0 |
| SM-S-03 | Low | C; the README documents the plaintext outcome outright rather than treating `wss://` as the default. | The installer shipped as a release asset under `SHA256SUMS`; rustup's installer checked against its published hash; a non-loopback plaintext listener refused without `SILVER_PLAIN=1`; the address lookup dropped; the token risk documented; the `sed` escaped. | 0.11.0 |
| SM-S-04 | Low | C. | The server's host key in a repository variable. | 0.11.0 |
| SM-S-05 | Low | C, plus the BuildKit frontend. | Images pinned by digest. | 0.11.0 |
| SM-S-06 | Info | C; the admin-socket remark is overstated (the runtime directory is 0700). | The directives added and checked live. | 0.11.0 |
| SM-S-07 | Info | C. | Duplicate versions denied with a documented skip list; the fuzz lock audited too. | 0.11.0 |
| SM-S-08 | Info | C; a corpus cannot live in a branch under this repository's rules. | The corpus cached per target; a scheduled longer run. | 0.11.0 |
| SM-S-09 | Info | C; the pull-request exposure is theoretical here. | A `release` environment restricted to `main` and `v*`; `update.sh` verifies the signature once the key exists. | 0.11.0 |

The rows of the report's section 12 with no finding id are all
confirmed. The stale panic-hook row of the assessment went with the
0.10.1 fixes it sat among; the other four — the "4000 characters"
sentence, the metrics `login` reason, `auth.host` normalisation and the
body cap — are corrected in 0.11.0's documentation pass, which is where
this note said 0.10.1 would carry them and was wrong.

## 4. Order of work

1. 0.10.1, in this order, each with its tests and its documentation:
   SM-R-01 with SM-P-01; SM-R-02 with SM-C-04; SM-P-02 with SM-C-17;
   SM-C-01; SM-C-02 with SM-C-08; SM-R-03, SM-R-04, SM-R-05, SM-R-06;
   SM-C-12; SM-G-01; SM-G-02; SM-C-06 with SM-C-03. Then the
   documentation rows, the changelog's `Security` section, the report
   and this note, the release, the deployed relay.
2. 0.11.0: section 13.2 as verified, grouped by crate.
3. Phase 11 roadmap entries for the 1.0 items.

## 5. What changes for users and operators

* A pin on an issuer key stops matching; re-pin the relay's own
  certificate (`--print-pin` prints it first).
* A relay older than 0.6.0 offers only the unbound login and is refused
  unless the client is started with `--allow-unbound-login`.
* A relay operator whose relay is reached under a name that is neither
  its ACME domain nor in its certificate (a Caddy front, an onion name,
  a bare address) must list it with `--host`, or bound logins fail with
  `bad_signature`.
* A message to a contact who publishes no prekeys is refused, as the
  specification said 0.10.0 would do.
* An envelope to an identity the relay holds no bundle for is refused
  `not_found` rather than queued.
* A directory unprotected by 0.10.0 or earlier with `--no-keystore` or
  `--remove-passphrase` had its `groups.json`, `groups.mls` and
  `revocation.json` left encrypted under a key that no longer exists;
  those three cannot be recovered. From 0.10.1 all files move together.
* `/open` and `/files decrypt` act on the downloads directory and
  nothing else. A file moved out of it after being received is no longer
  opened from the chat line.
* A Welcome for a group a newly linked device was told to expect is
  taken without asking only from the account's own identity; from anyone
  else it waits in the Requests pane like any other invitation.

## 6. Status

| Release | What it carries | State |
| --- | --- | --- |
| 0.10.1 | The Critical finding, the ten Highs, and the Mediums sharing their code: SM-R-01, SM-P-01, SM-R-02, SM-C-04, SM-P-02, SM-C-17, SM-C-01, SM-C-02, SM-C-08, SM-R-03 to SM-R-06, SM-C-06, SM-C-03, SM-C-12, SM-G-01, SM-G-02 | Released 6 September 2026, with this note and the report |
| 0.11.0 | The rest of the Mediums and the Lows, and the documentation rows of the report's section 12 | Next |
| 1.0 | The report's section 13.3, each with a design note; the roadmap lists them under Phase 11 | Planned |

No separate security advisories were filed for these. The project has
one user, its own maintainer, and the report, this note and the
changelog's `Security` section already say what each finding was and
what was done about it; an advisory would be a fourth copy addressed to
nobody. What an advisory would have carried and these did not is the
range each finding affects, so that is here instead. A report from
someone else is still handled as [SECURITY.md](../../SECURITY.md) says.

| Finding | Severity | Affected | Fixed in |
| --- | --- | --- | --- |
| SM-R-01 | Critical | 0.9.0 to 0.10.0 (device revocations arrived in 0.9.0) | 0.10.1 |
| SM-P-01 | High | 0.9.0 to 0.10.0 | 0.10.1 |
| SM-P-02 | High | every version to 0.10.0 | 0.10.1 |
| SM-R-02 | High | 0.6.0 to 0.10.0 (the bound login arrived in 0.6.0) | 0.10.1 |
| SM-R-03 | High | every version to 0.10.0 | 0.10.1 |
| SM-R-04 | High | every version to 0.10.0 | 0.10.1 |
| SM-R-05 | High | 0.8.0 to 0.10.0 (the transparency log arrived in 0.8.0) | 0.10.1 |
| SM-C-01 | High | 0.6.0 to 0.10.0 (`--pin` arrived in 0.6.0) | 0.10.1 |
| SM-C-02 | High | 0.8.0 to 0.10.0 (`revocation.json` from 0.8.0, the group files from 0.9.0) | 0.10.1 |
| SM-G-01 | High | 0.9.0 to 0.10.0 (groups arrived in 0.9.0) | 0.10.1 |
| SM-G-02 | High | 0.9.0 to 0.10.0 (device linking arrived in 0.9.0) | 0.10.1 |

Two of these leave something behind that upgrading does not undo. A data
directory unprotected by 0.10.0 or earlier has `groups.json`,
`groups.mls` and `revocation.json` still encrypted under a key that is
gone (SM-C-02); and a relay that stored a device revocation under the
old rule keeps the record, inert, until an operator drops it with
`silver-relay admin unrevoke-device` (SM-R-01).
