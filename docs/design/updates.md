# Design note: updating in place

Roadmap item 58. Written before the code, as the record of the decisions;
what ships is described in README.md when the code lands. Where this note
and the code later disagree, the code wins and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What the feature is | `silver update`: one command that finds the newest release, downloads the client for this platform, checks it, and puts it in place of the running one. `silver update --check` says what is available and changes nothing. `silver update --rollback` puts back the binary the last update replaced. Nothing else in the client downloads anything, ever. |
| Whether it is automatic | No, by default. A check on a timer tells the release host this computer's address, that it runs Silver Messenger, and when it is used — a usage pattern, which is the kind of thing the rest of the client works to withhold. `update-check` is a setting, off unless the user turns it on; on, the client asks once at start and at most once a day, through the same proxy the relay connection uses, and prints one line if something newer exists. It never downloads on its own even then. |
| What an update proves | That the bytes match the SHA-256 the release API gave for that asset, that they match the `SHA256SUMS` entry published with the release, that the project's signature over `SHA256SUMS` checks out against the key compiled into this client, and that the downloaded binary reports the version that was expected. It does not prove the maintainer approved the release from a machine an attacker does not hold: see section 8. |
| Where the checksum comes from | The release API (`api.github.com`), which returns a `sha256:` digest for every asset; the bytes come from the asset store, a different origin. A tampered artifact must therefore be matched by a tampered API answer. `SHA256SUMS` is checked too, so the automated path and the by-hand path in README's "Verifying a release" agree on the same number. |
| Signing | The project's own minisign key over `SHA256SUMS`, in the release workflow, from `MINISIGN_SECRET_KEY`. The workflow checks its own signature against the repository's `minisign.pub` before publishing, so a secret that is not the published key fails the release rather than shipping something nobody can check. Signing from a secret is weaker than signing on a machine the maintainer holds and stronger than not signing: the secret store and the release assets are separate systems. Moving the key offline later changes that one step and nothing here, because both are checked against the same `minisign.pub`. |
| What the client verifies of the signature | All of it, in the client. `minisign.pub` is read at build time by `build.rs` and compiled in, so the key that decides whether a binary may replace the running one comes from the source and not from the network. Verification is Ed25519 over BLAKE2b through `minisign-verify`, which has no dependencies of its own and is small enough to read in one sitting. A client built from a checkout with no `minisign.pub` refuses to update at all rather than accept whatever the release host serves -- in the code from 0.16.0, though this note and the constant's own comment had said so since 0.12.0: before that it skipped the signature, installed the binary, and printed a line afterwards saying no signature had been checked. The other two checks are no substitute, both being answers from the host serving the bytes. The refusal now happens before anything is fetched. |
| A package-managed install | Refused, with that manager's own command printed instead. A binary a package manager put there belongs to it: replacing it breaks that manager's verification and is undone by its next upgrade. The project publishes a Debian package and a Homebrew formula; the other managers are still detected, because a binary somebody else packaged is even less this client's to replace. Detection is by where the binary sits and what sits beside it (section 4). |
| Replacing the running binary | Write beside it, sync, then rename over it. On Unix the running process keeps its inode and is unaffected; on Windows the running image cannot be deleted but can be renamed, so the old one is moved aside and removed at the next start. Both leave the previous binary in place for `--rollback`. |
| Going backwards | Refused unless asked for by version and confirmed. A silent downgrade is how a stale release is re-served to someone who already has the fix, and an older client can meet a newer on-disk format. `--to <version>` names one explicitly. |
| Restarting | Never on its own. `silver update` runs without the TUI, so nothing is open when the file changes. Inside the TUI, `/update` checks and prints what to do; it does not download, because a client with an unlocked data directory and live sessions is the wrong place to be swapping the file under itself. |
| What is downloaded | The client alone, not the release archive. The archive carries the relay, two SBOMs, the changelog and the licence — 11.2 MiB where the client is about half that compressed. The release workflow gains a per-target `silver` asset (and `silver-relay`, for the relay's own updates) listed in `SHA256SUMS` beside the archives, which stay as they are. |
| Delta updates | No. A binary patcher is a parser for attacker-supplied input that writes an executable, which is a great deal of new surface to audit for a few megabytes; the per-binary asset above gets most of the saving for none of the risk. |

## 2. Goals and non-goals

Goals:

* Someone running an old client gets the current one with one command,
  without finding the releases page, choosing an archive, or knowing what
  `SHA256SUMS` is for.
* An update that is tampered with in flight fails, and says so, and
  leaves the working client in place.
* An update that turns out badly is undone with one command.
* A client installed by a package manager says so and does not fight it.
* Nothing contacts the release host unless the person asked, or turned
  the daily check on themselves.

Non-goals:

* Updating the relay. `deploy/install.sh` already replaces the relay
  binary and restarts the service, and an operator upgrading a service
  wants the service's own conventions, not the client's. The per-target
  `silver-relay` asset is published so that script can stop unpacking a
  whole archive; the client does not manage it.
* Updating while the TUI runs. See section 6.
* Defending against the release host itself, or against the maintainer's
  account being taken. Section 8 says what that means.
* Automatic installation of anything, under any setting.

## 3. What happens, in order

1. **Find out where this binary is** — `current_exe()`, resolved through
   symlinks. Everything else depends on it.
2. **Decide whether it is ours to replace** (section 4). If not: print
   that manager's command and stop, exit code 0 — this is an answer, not
   a failure.
3. **Ask the release API** for the newest release, through the proxy and
   extra roots the data directory remembers, exactly as `--check-release`
   does today, and for the same reason: reaching the release host
   directly from a machine whose relay traffic goes over Tor would
   announce that this address runs Silver Messenger.
4. **Compare versions.** Equal or newer than the release: say so and
   stop. Older: continue, unless `--check`.
5. **Pick the asset** for this target triple. Missing: say which target
   was looked for and stop.
6. **Download** it and `SHA256SUMS`, both bounded (section 7), to a
   temporary file in the target directory — the same filesystem, so the
   rename in step 9 is atomic.
7. **Check** the SHA-256 of what arrived against the digest the API gave
   and against the `SHA256SUMS` line. Either disagreeing: delete the
   download, report both numbers, stop. Nothing has been touched.
8. **Sanity-check the file**: right size class, executable format for
   this platform, and — the real test — run the downloaded binary with
   `--version` in a subprocess and require it to print the version that
   was expected. A binary that cannot say its own name does not replace
   a working one.
9. **Swap** (section 5).
10. **Say what happened**: the version before, the version now, where the
    old binary is, and how to undo it.

## 4. Whose binary is it

The check is what is on disk, not a remembered install method: someone
who unpacked an archive over a packaged install should still be told the
truth.

| Sign | Read as |
| --- | --- |
| The path is under `/usr/lib`, `/usr/bin`, or any prefix owned by `dpkg -S` / `rpm -qf` when those exist and name a package | Debian or RPM package |
| The path is inside a Homebrew Cellar, or `brew --prefix` is a parent | Homebrew |
| A `.PKGINFO`-owning path, or `pacman -Qo` names a package | Arch |
| On Windows, a path under the winget packages directory or a `.winget` marker beside it | winget |
| The path is under a Cargo home's `bin` | `cargo install` |
| Anything else | ours |

Package managers are asked only when their tool exists and the path looks
like theirs; the client never shells out speculatively. When a manager
owns the file, the message names the manager and its command
(`brew upgrade silver-messenger`, `sudo apt install --only-upgrade
silver-messenger`, and so on).

`cargo install` is ours in the sense that we could replace the file, but
the honest answer is `cargo install silver-messenger --force`, so it is
reported like a package manager.

## 5. The swap, and undoing it

Unix:

1. Write to `silver.new-<random>` in the target's directory, `fsync`, set
   the mode of the existing binary (not a fixed 0755: a file installed
   0750 in a shared directory keeps its group).
2. Hard-link or copy the current binary to `silver.old`.
3. `rename()` the new file over the target. The directory entry changes
   in one step; a process already running keeps the old inode and does
   not notice.
4. `fsync` the directory.

Windows: the running image cannot be deleted, but it can be renamed. Move
the target to `silver.exe.old`, move the new file into place, and if the
move fails, move the old one back. The next start deletes any
`silver.exe.old` it finds beside itself.

`silver update --rollback` reverses it with the same dance, and refuses
when there is no `silver.old`, when it is not a Silver Messenger binary
(the `--version` test again), or when it is the same version as the
running one.

Failure at any step leaves either the old binary or the new one in place,
never neither: the rename is the only moment the target changes, and the
old file is kept until it succeeds.

## 6. The TUI's part

`/update` in the client checks and prints, in the System pane: the
running version, the newest, and — when they differ — `quit and run
silver update`. It does not download. The client holds an unlocked data
directory, ratchet state in memory and open sessions; replacing the file
under it buys nothing (the running process keeps its inode anyway) and
adds a way for a half-finished update to coincide with a write.

The status line shows nothing about updates. A permanent nag in a
messenger's chrome is how people learn to ignore chrome.

With `update-check` on, one line appears in the System pane at start when
a newer release exists, at most once a day, remembered in the config as a
date so a client started ten times a day asks once. Off by default,
turned on with `/set update-check on`, and documented in README beside
the proxy settings as a thing that talks to the network.

## 7. Bounds

* The release API answer: 256 KiB, as today.
* `SHA256SUMS`: 1 MiB.
* The binary: 128 MiB, and the download stops at the byte after.
* Every request: the existing 20-second connect and read timeouts, and a
  five-minute cap on the whole download.
* Redirects: followed to a depth of five, HTTPS only, and the host must
  remain one of the release host's own. A redirect to anywhere else ends
  the update.
* Disk: not checked before the download. Nothing in the standard library
  reports free space and the client takes no crate for it; a full disk
  fails the write, which is reported as such, and the part-written
  download is removed. Since the rename happens only after the download
  is complete and synced, a full disk cannot leave a half-written binary
  in place of a working one.

## 8. What this does not defend against

An update is code that runs as the person who ran it, so it is worth
being exact.

* **The release host.** Whoever serves the release API and the asset
  store can serve a signed, checksummed, consistent lie. The transparency
  log makes a signing event public, so the lie is on the record, but it
  is not prevented.
* **The maintainer's account.** Anything the workflow can do, whoever
  holds the account can do, including cutting a release. No automated
  scheme changes this: a signature a build can make is a signature an
  attacker with the build can make. This is the same position as every
  self-updating tool that signs in CI, and it is why the threat model
  lists it under what is not addressed rather than claiming otherwise.
  What it would take to change: a key on a machine the maintainer holds,
  used by hand for each release, its public half compiled into the
  client — a real improvement, and one that costs a manual step per
  release. It is recorded here as the option it is, not scheduled.
* **A compromised build.** The provenance attestation is honestly issued
  for whatever the runner built; a reproducible-build check by someone
  else is the answer, as the threat model already says.

What it does defend against: a tampered asset store on its own, a
tampered download in flight, a stale or replayed older release, a
truncated or corrupted download, and — the everyday case that motivates
the feature — a security fix that never reaches someone because updating
by hand is a chore.

## 9. Open, for later

* A Sigstore verifier in the client, so the signature is checked where
  the binary is installed rather than by hand. Wanted; a dependency
  decision of its own.
* An offline maintainer key, per section 8.
* Updating the relay from the client. No: the relay is administered over
  its own socket by an operator who knows what a restart costs.

## 10. Tests

In `silver-client`, against a local HTTP server standing in for the
release host, as `tests/update.rs` already does for the check:

* the happy path replaces the binary and reports both versions;
* a digest that disagrees with the API is refused, and the target is
  untouched;
* a `SHA256SUMS` line that disagrees with the API digest is refused;
* a truncated download is refused;
* a redirect off the release host is refused;
* an older version is refused without `--to`, and taken with it;
* a downloaded file that cannot print its own `--version` is refused;
* `--rollback` restores, and refuses when there is nothing to restore;
* a path that looks package-managed is refused with that command;
* the swap under a kill, on Unix, two ways. A child is killed at a
  random moment during a swap and the target is afterwards one of the
  two binaries, never a piece of one — twenty rounds, as the robustness
  note's kill test does for the store. And, because a kill lands inside a
  window microseconds wide about never, a second test watches the path
  from another thread while four hundred swaps run and requires that the
  name never once resolves to nothing.

  Both are Unix-only, and so is the guarantee. There the old binary is
  hard-linked aside and the new one renamed over it, so the name always
  resolves to a whole file. Windows cannot replace a running image at
  all: its swap renames the target away and renames the replacement in,
  and between those two the name is genuinely absent. That window cannot
  be closed — see `install.rs`, which makes it as small and as
  recoverable as it can be instead. Until 0.16.0 this section claimed the
  kill test existed and it did not; the September 2026 review found that
  (I-1), and the claim now describes tests that are there.

In `tests/tui`: `/update` prints the three lines and downloads nothing.

On Windows, in CI: the rename-aside path, and the deletion of a leftover
`silver.exe.old` at the next start.
