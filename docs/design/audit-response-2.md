# Design note: the response to the second security review

Roadmap item 62. A second independent adversarial review, of the 0.14.0
line, reported 2 High, 7 Medium, 18 Low and 2 Informational findings
after three review rounds; the report is published as
[docs/audits/2026-09-second-security-audit.md](../audits/2026-09-second-security-audit.md).
This note records, for every finding, what the code was found to do, what
is done about it, and where. It follows
[the first one](audit-response.md), and the same rule holds: where this
note and the code disagree, the code wins and this note is corrected.

There is no Critical and no cryptographic break. The two Highs and every
Medium are fixed in 0.16.0, as are eleven of the eighteen Lows and the
one Informational that was a real defect. Of the rest, three Lows the
report itself withdrew, one is declined, and the others are remainders of
findings otherwise closed — two scheduled, three declined with the
argument written down. This note says which is which rather than rounding
up.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What ships in 0.16.0 | Both Highs, all seven Mediums, eleven of the eighteen Lows in full, three more in part, and the one Informational that is a real defect (I-1). No patch release was cut ahead of it: neither High is reachable without either a line the user pastes without reading (H-2) or the access class that already reads an unlocked client outright (H-1, M-1), so nothing here is a race against disclosure. |
| What is scheduled | One remainder, under roadmap item 63: verifying on a real Mac that the ad-hoc hardened runtime H-1 asked for actually restricts an attach. The signing is in; the claim is not made until somebody has watched it hold. Section 4 says what that leaves. |
| What is declined | L-1 and the M-1 remainder, on one decision about `forbid(unsafe_code)`; the L-11 and L-12 remainders, each on its own argument; and the review's suggested non-zero `lock_after_minutes` default. All five are argued in section 4 rather than left open. |
| Where a suggested fix was not taken | Section 5. Five cases, each argued. |
| Disclosure | The report goes in whole, this note beside it, as [SECURITY.md](../../SECURITY.md) says of every review. |

## 2. What the review got right about the code, in one paragraph

The pattern is not missing checks; it is checks that exist and sit one
layer too far in, or on one platform and not the one beside it, or that
were written down and never coded. `RatchetHeader::check_lengths` ran
inside the decrypt path, so a body that never reached decryption was
never checked. The header-read timeout that stops a silent connection
holding a socket was installed on the relay's main listener and not on
its metrics listener, by a helper written for the purpose. `one_sentence`
was applied at four call sites and missed by two, and its own doc comment
names the attack that got through. `build.rs` said a build with no
signing key refuses to update; the code installed the release anyway.
Most of the fixes below move an existing rule to the one door everything
passes through rather than adding a rule.

## 3. Findings and what was done

Verdict: **C** confirmed as reported, **P** confirmed in part.

| ID | Sev | Verdict | What was done, and where |
| --- | --- | --- | --- |
| H-1 | High | C | Windows gained a restricted process access list, so opening the process for reading is refused; macOS has neither protection and is now said to. The threat model gained "Program running as you" as an actor with a per-platform table, the README says the same, and SECURITY.md gained the platform statement the report noted was missing entirely. Not done: macOS hardened-runtime signing (§4). The review's other suggestion here, a non-zero `lock_after_minutes` default, is decided against (§4). |
| H-2 | High | C | `/devices link` is two steps. The first parses, checks and says what the device would be given — the identity signs a standing certificate, the device is thereafter you, its full id to compare against the other computer's, and the contacts, groups and messages that go with it — then stops. `/devices link confirm` proceeds, and the paste guard sits on that line. See §5 for why the guard is not on the first line, contrary to the report's wording. |
| M-1 | Medium | C | Exactly the report's Rev 3 design: the directory fsync added to `write_atomic` mirroring `install.rs`, a `vault.pending` list written before any step that can orphan a key and drained by the next `Store::open`, and compensating deletes on the error paths. Removing the protection and wiping had the same gap on the other side and are covered too. One correction of our own: the predicate read an *unreadable* vault as one that did not name the key and deleted it, which would take every file in the directory with it; it now keeps the key when it cannot tell. Not done: the `data-key-*` enumeration sweep (§4). |
| M-2 | Medium | C | The strongest post-quantum level a session with each contact has reached is kept with the contact; a session below it is reported when it starts and by `/session` while it lasts. Only a fall is reported. The client cannot tell a stripped bundle from a peer on an older client — the two arrive as the same bytes — so it gives both readings and asks the user to check on another channel. |
| M-3 | Medium | C | Refused outright, before a byte is fetched, and again inside the verify path so no route through it ends without a signature. Stricter than the report's suggested `--allow-unsigned` gate; §5 says why. `signature_checked` could then only ever be true and is gone, with the parenthetical it fed. |
| M-4 | Medium | C | `per_hour` no longer clamps its rate to 1.0, so zero is off as it already was for `per_minute`, with tests for both. |
| M-5 | Medium | C | Both consequences. The sweep runs in a single write transaction, which removes the window rather than coping with it; within it, the accounting is charged only for rows actually removed with the size taken from the removed value, and `by_id.remove` is gated on the index still pointing at the row just removed — which is the stranding half. Pinned by a test that runs an acknowledging thread against the sweep and checks the accounting describes exactly the mail still queued. |
| M-6 | Medium | C | All four of the report's parts: `one_sentence` moved to the `say()` boundary so one call is one line always, `one_line` on the compose prompt, `is_invisible` extended with U+115F/U+1160/U+3164/U+FFA0/U+E0080–E00FF, and a reader-mode invariant test mirroring the full mode's. A pty test walks the same forgery through a real terminal. |
| M-7 | Medium | P | `/send`, `/relay` and `/group join` go through the guard. `/unblock` and `/alias` do not: §5. |
| L-2 | Low | C | The window cannot be closed — Windows offers no atomic replace for a running image — so what can fail happens before the two renames, the recovery falls back to copying when a rename will not go, and when neither goes the error names the file to rename back by hand. `rollback` had the same window on every platform and now shares that recovery. Writing the test found a third thing: the backup was checked with `exists()`, so a *directory* could have been renamed onto the binary's name. |
| L-3 | Low | C | The first refusal of a run is logged and the rest counted, with a line a minute carrying the total. What is refused is unchanged. |
| L-4 | Low | C | The metrics listener calls the same `set_http_timeouts` the main listener has used since 0.7.0, serves sixteen connections at once and gives each a deadline. |
| L-5 | Low | C | Both halves. `--max-mailbox-messages 0` gave a relay that answered "mailbox full" to everyone, since `count >= 0` holds of every mailbox; zero is no cap now, agreeing with `--mailbox-storage-mib` and `--max-identities`, which already documented it that way. `--max-mailbox-mib` multiplied to bytes without saturating where the line below it did, so a large enough value wrapped to a small cap; it saturates, as do the additions compared against it. |
| L-6 | Low | C | An identity may write `--log-entries-per-user-per-hour` entries (12 by default, 0 for no cap). The log is append-only and hash-chained — that is what lets a client prove the relay served everyone the same keys — so growth cannot be answered by pruning, only by refusing to append. Republishing an unchanged bundle appends nothing and is never refused, which is what every client does on connecting. |
| L-8 | Low | C | `Session::respond` checks `init.signed_prekey_id` against the prekey it was handed. The one-time and post-quantum keys were already matched; the signed one, which every handshake uses, was not, so a caller that looked up the wrong id built a session deriving a different root and failing every AEAD with nothing to say why. |
| L-10 | Low | C | `Session`, `IdentitySecrets` and `PrekeySecret` say at the type what serializing them yields: plaintext keys. They are public API, and "serializable so a client can persist it" read as an invitation to persist it as it comes. |
| L-13 | Low | C | `/whois` marks a name that mixes alphabets whose letters look alike. Only the mixture: a name written wholly in Cyrillic is somebody's actual name, and a Latin name with a digit in it is nobody's attack. A prompt to compare safety numbers, not a refusal — an alias is the user's own to set. |
| L-16 | Low | C | `Content::check` validates a file's blob id, size cap and chunk count where the body is parsed, alongside the ratchet-body validation added for M-6's neighbours. One deliberate difference from `BlobRef::validate`: an empty file has one chunk and zero bytes, which `upload_file` really produces and the group half really refuses. Noted rather than settled here. |
| L-11 | Low | P | A system trust store that yields nothing now warns and says what it costs, instead of a `debug` line nothing runs at. The report's sharper half — that removing a compromised CA from the OS store does not remove it from the compiled-in Mozilla set, so OS-store incident response is ineffective against the built-in list — is **documented but not changed** (§4). |
| L-12 | Low | P | `silver.log` is bounded: it rolls at 8 MiB keeping one previous file, and `/wipe` takes the rolled half too, it being the same record. The side-channel itself — plaintext metadata beside an encrypted directory, readable with the vault locked — is unchanged (§4). |
| L-14 | Low | C | All of them. The release description and the checksum list came first, being parsed before any signature has been checked; the five the report also named — the hand-rolled HTTP response head (with the redirect check beside it), `transparency.rs`, `vault.rs`, `linking.rs` and `Pin::parse` — followed, each with the property it exists for asserted rather than merely exercised. Writing the first of those found a defect: `split_https_url` took `evil.test@api.github.com` as a host, which ends with `.github.com` and so passed the redirect check while reading as another name entirely. Refused now. |
| L-15 | Low | C | The bound login is required by default; `--allow-unbound-auth` takes it back for a relay that still has clients older than 0.6.0, and says in the log what that costs. |
| L-18 | Low | C | The group alias is filtered on the way in — including copies synced from the user's own devices — and on the way out, since a directory written by an earlier version already holds whatever was typed then. With the prompt filtered too (M-6), the raw-prompt gap is closed twice. |
| L-7, L-9, L-17 | Low | — | The report itself rejects or downgrades these to documented behaviour after counter-review. Nothing done, nothing owed. |
| I-1 | Info | C | The claim in `docs/design/updates.md` that the swap is tested under a kill was false, in the document about the path that replaces the running binary. The test exists, and writing it corrected the claim too: a kill lands in a window microseconds wide about never, so a second test watches the path from another thread across four hundred swaps and requires that the name never resolve to nothing. Both are Unix-only, and so is the guarantee — Windows cannot replace a running image, so its swap has a window `install.rs` makes small and recoverable rather than closing. The old claim covered neither. |
| I-2 | Info | — | A stale line in the *first* report, already answered in that report's response note. The historical record is published unedited by convention. |

Every finding is now in the table except **L-1**, which is declined, and
the partial remainders of **H-1**, **M-1**, **L-11** and **L-12**.
Section 4 says what each of those is and what leaving it costs.

## 4. What is not done, and what it costs

Two of these are *declined* and two more are *decided*: settled below,
not coming back. Only the last stands under roadmap item 63. Nothing here
is a way for someone else to read a message or forge one; every item is
either a bound that should be tighter, a defence in depth, or a
documentation defect.

* **L-1 — no `mlock`/`VirtualLock` on key buffers.** *Declined.* Keys can
  reach swap or a hibernation image. The threat model says so; locking
  the small fixed-size buffers would narrow it. See the decision below.
* **L-11 remainder — the compiled-in Mozilla roots are added to the
  system store, not used instead of it.** *Decided, not scheduled.* So
  removing a compromised CA from the operating system's store does not
  stop this client accepting it: `webpki-roots` is loaded first and the
  native certificates are added on top. The alternative — the system
  store alone whenever it yields anything — honours a local distrust
  decision, and costs a client that will not connect at all on a machine
  whose store is partial, unreadable or absent, which is every container
  and a fair number of servers. **The floor stays**, because the answer
  for somebody who cares which authorities can vouch for their relay is
  not a shorter list of them: it is `--pin`, which takes every authority
  out of the question for the one host this program talks to. That is
  what the README recommends and what the finding's own scenario wants.
* **L-12 remainder — `silver.log` is plaintext beside an encrypted
  directory.** *Decided, not scheduled.* It is bounded now and `/wipe`
  takes it, but what it holds — envelope ids, contact ids, the relay —
  is readable while the vault is locked. It is not encrypted because a
  log that needs the data key is no use for the case it exists for: a
  client that will not start, or will not unlock. It is off unless
  `SILVER_LOG` is set, it is written 0600, and the threat model says
  what it is. Turning it on is a deliberate trade, and the client should
  not quietly make the diagnostic unreadable in exchange.
* **H-1 remainder — macOS release builds carry no Developer ID
  signature** unless the notarization secrets are set. *Half done, and
  the half that is done is unverified.* A build without those secrets is
  now signed **ad hoc with the hardened runtime asked for**, which is
  what should make macOS refuse a same-user attach, and the release job
  fails if the flag is missing from the signature it just made. What
  nobody has done is watch it refuse one on a real Mac, so the threat
  model and SECURITY.md go on counting macOS as unprotected and say why.
  A claim about what a platform enforces is not one to make from a
  manual page — this program has been caught once already by a document
  describing a check the code did not do (I-1), and the answer to that
  was a test, not better prose. Until somebody runs it: Gatekeeper is
  unchanged either way, since an unnotarised download is refused signed
  or not.
* **M-1 remainder — no enumeration sweep of `data-key-*` entries.**
  *Declined.* The pending list covers every key orphaned from 0.16.0 on;
  keys orphaned by *earlier* versions stay until removed by hand. Same
  decision as L-1.

### The one decision those two are declined on

Both want a system call — `mlock`/`VirtualLock` for L-1, `CredEnumerate`
and its equivalents for the sweep, which `keyring` exposes on no backend
— and `silver-client`, the crate holding the keys, is
`#![forbid(unsafe_code)]`. The review counted that among the reasons the
tree reads as it does. So the choice was: drop the property in the crate
that most wants it, or take a dependency whose whole job is to hold the
unsafe (`region`, `memsec`, `secmem-alloc` — the last from the author of
the `secmem-proc` already linked on Windows for the process access
list).

**Neither. Both findings are declined**, and the decision is one, not
two. `forbid(unsafe_code)` on the crate that touches every secret is
worth more than what either finding buys: L-1 narrows a swap exposure
that full-disk encryption already answers and that pinning the key alone
would not close anyway — the decrypted messages beside it stay pageable —
and the M-1 remainder is a key left behind by a version older than
0.16.0, removable by hand, on a machine whose key store the attacker
would have to hold already. A dependency is not a way around the same
trade: it moves the unsafe out of view without removing it from the
process, and the reviewer's point was about what runs, not about which
crate declares it.

What stands instead: the threat model says plainly that an unlocked
client's pages can reach swap and that full-disk encryption is the answer
to it, and the FAQ now says what the key store holds, why the client will
not sweep it, and how to clear a stray entry by hand without having to
work out which one is live. Neither is a silent gap. If the trade is ever
reopened it will be for something that wants unsafe on its own account,
not for these two.

### The idle lock stays off by default

The review recommends a non-zero `lock_after_minutes` for
passphrase-protected directories, on the ground that it shrinks the
window the live exercise used. **Decided against.** It would also lock
people out of a program they deliberately left running, and the choice
between those costs belongs to the person using it, not to a default.
The setting exists, `/lock` exists, and the threat model says what an
unlocked client is worth; what it does not do is decide for the user
which risk they would rather carry.

## 5. Where a suggested fix was not taken

* **The paste guard on `/devices link` itself** (H-2, and §8.1 of the
  report). Its remedy is "type it out", and a device link carries a user
  id and a secret nobody types. A guard that cannot be satisfied is not a
  control — it is a wall with the door removed. The confirmation step is
  where a guard works: typing three words is a fair thing to ask, and
  refusing a *pasted confirmation* leaves the question standing, so the
  advice can actually be followed. The checks run again on the second
  line.
* **`--allow-unsigned` for a build with no signing key** (M-3). Taken
  further: such a build refuses. The two checks that would remain are the
  digest on the releases page and the digest in `SHA256SUMS`, both
  answers from the host serving the bytes, so they agree with each other
  for anything that host cares to hand out. A flag that turns "one origin
  decides what code runs" back on is not worth having.
* **The guard on `/unblock`** (M-7). Its argument must be a prefix of an
  id already on your own blocked list, so a pasted line cannot name
  anyone you have not already blocked yourself, and the effect is
  reversible by re-blocking.
* **The guard on `/alias`** (M-7, L-18). The alias is filtered on the way
  in and out, which closes the injection the report is actually worried
  about; the command has no effect outside this computer and is undone by
  running it again.

## 6. On the review chain

Three rounds each found material errors in the one before, including in
the report's own remediation advice — the second round's "delete the old
key-encryption key right after the first vault write" would have orphaned
the vault on POSIX, because `write_atomic` did not fsync the parent
directory. That correction is the reason M-1's fix has the shape it does,
and the directory fsync it asks for turned out to be a durability hole
worth closing on its own account. It is a good argument for reviewing
review output as adversarially as the code.
