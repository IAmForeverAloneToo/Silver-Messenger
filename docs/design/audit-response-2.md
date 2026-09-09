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
Medium are fixed in 0.15.0; the Lows are partly fixed and partly
scheduled, and this note says which is which rather than rounding up.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What ships in 0.15.0 | Both Highs, all seven Mediums, and eight of the eighteen Lows. No patch release was cut ahead of it: neither High is reachable without either a line the user pastes without reading (H-2) or the access class that already reads an unlocked client outright (H-1, M-1), so nothing here is a race against disclosure. |
| What is scheduled | The remaining Lows and the one Informational that is a real defect (I-1), under roadmap item 63. Section 4 lists them individually with what each costs to leave. |
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
| L-11 | Low | P | A system trust store that yields nothing now warns and says what it costs, instead of a `debug` line nothing runs at. The report's sharper half — that removing a compromised CA from the OS store does not remove it from the compiled-in Mozilla set, so OS-store incident response is ineffective against the built-in list — is **documented but not changed** (§4). |
| L-12 | Low | P | `silver.log` is bounded: it rolls at 8 MiB keeping one previous file, and `/wipe` takes the rolled half too, it being the same record. The side-channel itself — plaintext metadata beside an encrypted directory, readable with the vault locked — is unchanged (§4). |
| L-14 | Low | P | The release description and the checksum list get a fuzz target, both being parsed before any signature has been checked. The hand-rolled HTTP response parser, `transparency.rs`, `vault.rs`, `linking.rs` and `Pin::parse` do not (§4). |
| L-15 | Low | C | The bound login is required by default; `--allow-unbound-auth` takes it back for a relay that still has clients older than 0.6.0, and says in the log what that costs. |
| L-18 | Low | C | The group alias is filtered on the way in — including copies synced from the user's own devices — and on the way out, since a directory written by an earlier version already holds whatever was typed then. With the prompt filtered too (M-6), the raw-prompt gap is closed twice. |
| L-7, L-9, L-17 | Low | — | The report itself rejects or downgrades these to documented behaviour after counter-review. Nothing done, nothing owed. |
| I-2 | Info | — | A stale line in the *first* report, already answered in that report's response note. The historical record is published unedited by convention. |

Findings not in the table — **L-1, L-5, L-6, L-8, L-10, L-13, L-16** and
**I-1** — are not done. Section 4 says what each is and what leaving it
costs.

## 4. What is not done, and what it costs

Scheduled under roadmap item 63. Nothing here is a way for someone else
to read a message or forge one; every item is either a bound that should
be tighter, a defence in depth, or a documentation defect.

* **I-1 — `docs/design/updates.md` claims a kill test that does not
  exist.** The worst of the eight, because it is a false statement about
  what is tested, in a document about the update path. Either the test
  gets written or the claim goes; it should not survive another release.
* **L-1 — no `mlock`/`VirtualLock` on key buffers.** Keys can reach swap
  or a hibernation image. The threat model says so; locking the small
  fixed-size buffers would narrow it. Blocked on the decision below.
* **L-5 — `--max-mailbox-mib` can wrap on multiply, and
  `--max-mailbox-messages 0` silently means "always full".** Both are
  operator footguns of the same family as M-4, which was fixed; these
  were missed and should follow it.
* **L-6 — transparency log growth is uncapped per identity.** Append-only
  and never pruned.
* **L-8 — `Session::respond` never checks `init.signed_prekey_id`
  against the supplied prekey**, giving a silent dead session instead of
  a clean error.
* **L-10 — session, identity and prekey secrets serialize as plaintext
  base64 JSON.** A footgun for anything that persists them outside the
  vault; this program does not, but the type invites it.
* **L-13 — homoglyph and mixed-script names are unmitigated.**
* **L-16 — `Content::File` metadata is not validated at the protocol
  layer.** The client validates on every receive path before allocating,
  which is why the report downgraded it; the boundary check is still the
  right place, alongside the ratchet-body validation added for M-6's
  neighbours.
* **H-1 remainder — macOS release builds are unsigned** unless
  notarization secrets are set, so the hardened runtime that would
  restrict same-user attach is absent. Ad-hoc signing would get
  `CS_RESTRICT` without notarization.
* **M-1 remainder — no enumeration sweep of `data-key-*` entries.** The
  pending list covers every key orphaned from 0.15.0 on; keys orphaned by
  *earlier* versions stay until removed by hand. Blocked on the same
  decision as L-1.

### The one decision those two wait on

Both want a system call — `mlock`/`VirtualLock` for L-1, `CredEnumerate`
and its equivalents for the sweep, which `keyring` exposes on no backend
— and `silver-client`, the crate holding the keys, is
`#![forbid(unsafe_code)]`. The review counted that among the reasons the
tree reads as it does. So the choice is: drop the property in the crate
that most wants it, or take a dependency whose whole job is to hold the
unsafe (`region`, `memsec`, `secmem-alloc` — the last from the author of
the `secmem-proc` already linked on Windows for the process access
list).

One decision, covering both, and not one to make quietly. A Low finding
about swap and a leftover key from before 0.15.0 are not obviously worth
either an audited-away invariant or a new dependency in the crate that
handles every secret. Recorded here so the trade is visible rather than
resolved by whoever touches it next.

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
