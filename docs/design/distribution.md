# Design note: distribution

Roadmap item 53. Written before the code, as the record of the decisions;
what ships is described in README.md when the code lands. Where this note
and the code later disagree, the code wins and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What every channel installs | The binaries the release workflow already builds, verifies and attests, by checksum. No channel builds its own. A package is a wrapper around bytes that `SHA256SUMS` and the provenance attestation already cover, so what `brew` or `apt` installs is what a person taking the file from the release page by hand would get. |
| Windows | Authenticode over both executables, in the build job, with `signtool` and a certificate from the repository's secrets (`AUTHENTICODE_PFX`, base64 of the PKCS#12, and `AUTHENTICODE_PASSWORD`), timestamped. Without the secrets the step says so and the release is published unsigned; nothing else changes. The certificate is the maintainer's to obtain (a code-signing certificate from a CA, or a free one for open-source projects from SignPath). |
| macOS | `codesign` with a Developer ID Application identity from the secrets (`APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`), hardened runtime and a timestamp, then `notarytool submit --wait` under `APPLE_ID`, `APPLE_TEAM_ID` and `APPLE_APP_PASSWORD`. A bare executable takes a signature but not a stapled ticket (stapling is for bundles, disk images and installer packages), so Gatekeeper checks the ticket online the first time; that is how every command-line tool distributed outside the App Store behaves. Without the secrets the step says so and README keeps the `xattr -d com.apple.quarantine` instruction. The Apple Developer Program membership is the maintainer's to take out. |
| Reproducibility and signatures | A signature is bytes added to the executable, so a signed release differs from a rebuild by exactly the signature. The archives stay the reproducible artefact: CI compares unsigned builds as before, and README says how to compare a signed download (strip the signature with `osslsigncode remove-signature` or `codesign --remove-signature`, then compare). The Linux archives, the Debian packages and the container image carry no embedded signature and reproduce byte for byte. |
| Removed | The AUR package and the winget manifests were both written, linted and regenerated at every release, and neither was ever installable: each needed a push to somebody else's index that was never made (section 6). Removed in 0.12.2. An Arch or Windows user takes the one file for their platform from the release page. |
| Homebrew | A tap in this repository: `HomebrewFormula/silver-messenger.rb`, which Homebrew finds when the repository is tapped by URL (`brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger`). The formula points at the release binaries for macOS (Apple Silicon and Intel) and Linux (x86_64 and aarch64) with their checksums -- the client as its download, the relay as a resource beside it, since a release carries the two programs as two files -- and tests `silver --version`. A separate `homebrew-silver` repository would be the usual shape; one repository is enough for a tap, keeps the formula next to the code it installs, and needs no second set of permissions. |
| Debian and Ubuntu | A `.deb` per architecture (`amd64`, `arm64`) built in the release workflow from the Linux binaries with `dpkg-deb`, attached to the release beside them, in `SHA256SUMS` and attested like everything else. It installs `/usr/bin/silver`, `/usr/bin/silver-relay`, the relay's unit in `/lib/systemd/system/` with its path rewritten (installed, not enabled), the documents and the copyright file; its `postinst` creates the relay's system user and runs `systemctl daemon-reload` where systemd is present; `prerm` stops and disables the unit. The package depends on nothing: the binaries are static. No repository is run; the file is installed with `apt install ./silver-messenger_<version>_<arch>.deb`, which resolves nothing and checks nothing beyond the file, so the checksum and the attestation are the person's check, as for the archives. |
| Keeping the packaging current | The checksums change with every release, so `packaging/update.sh <version>` reads the release's `SHA256SUMS`, checks its signature, and rewrites the formula; the result is committed after the release, by hand, as the packaging commit for that version. Nothing in the workflows commits to the repository. |
| Checking the packaging in CI | The Debian build script runs on every push against a static debug build (the musl target, stripped, so lintian sees the shape the release has), the package is linted with errors fatal and installed in a Debian container where both binaries run; the formula is checked with `brew audit --strict` and `brew style` on the macOS runner, with this checkout tapped as a person would tap it, then installed from the release it names and tested. The signing and notarising steps cannot be checked without the secrets and are marked unchecked until the first signed release. (Corrected when the code landed: the formula is checked against the release rather than against the run's artefacts.) |

## 2. Goals and non-goals

Goals:

* A person on each platform installs the client (and the relay, which
  ships beside it) with the tool they already use, and gets the bytes the
  release page carries.
* Every artefact on every channel is covered by `SHA256SUMS`, its
  signature and the provenance attestation, so the channel adds
  convenience and no trust.
* Nothing in the workflows needs credentials that the repository does not
  hold: the maintainer's accounts (Apple, a certificate authority) are
  used by the maintainer, and every step that needs one says clearly when
  it is missing. A channel that needs an account and a push to somebody
  else's index at every release is not one this project keeps: 0.12.2
  removed the two that did.

Non-goals:

* Running a package repository (an apt or a Homebrew core submission):
  each of those is a commitment to a cadence and a review process that
  this project has not made yet.
* A Windows installer (`.msi`) or a macOS `.pkg`: the client is a
  terminal program and both platforms run it from a folder. On macOS
  Homebrew gives the command-line install; on Windows the release page's
  one file is the install.
* Flatpak, Snap, Nix: none is asked for yet; the Linux archive and the
  `.deb` cover the current users.

## 3. The signing steps

In `release.yml`'s build job, after the build and before the SBOM:

* Windows: decode the PKCS#12 into `$RUNNER_TEMP`, `signtool sign /fd
  SHA256 /td SHA256 /tr http://timestamp.digicert.com /f <pfx> /p <pw>
  silver.exe silver-relay.exe`, `signtool verify /pa`, delete the file.
* macOS: create a temporary keychain, import the certificate, `codesign
  --sign "<identity>" --options runtime --timestamp` both binaries, zip
  them, `xcrun notarytool submit --wait --apple-id --team-id --password`,
  and check `codesign --verify --deep --strict` and `spctl --assess
  --type execute`, then delete the keychain.

Each step runs only when its secrets are all present; with none, one
notice names them and the README section on signing; with some but not
all, the step fails, since a half-configured secret is a mistake rather
than a choice.

**What the minisign step is worth** (SM-S-01). The `SHA256SUMS`
signature is designed to be made by the workflow from
`MINISIGN_SECRET_KEY`, which means the key lives where the build lives:
anyone who can run a workflow with secrets, and anyone holding the
maintainer's GitHub account, can sign with it, and it therefore says
what the provenance attestation already says. It is convenient — a
download can be checked with `minisign` alone, no call to GitHub's
attestation API — and it is a separate store from the release assets, so
tampering with the published files alone does not survive it. The
independent root is the same key generated and kept on a maintainer's
machine, `SHA256SUMS` downloaded after each release, signed there, and
`SHA256SUMS.minisig` attached by hand. The first is set up as of 0.12.0:
`minisign.pub` is at the repository root and `MINISIGN_SECRET_KEY` is in
the repository's secrets, so the workflow signs each release and checks
its own signature against the published key before publishing.
`packaging/new-signing-key.sh`, and `.ps1` for Windows, make a key either
way; the second way changes that one workflow step and nothing a
verifier does, since both are checked against the same `minisign.pub`.

**How a release is published** (SM-S-09). `workflow_dispatch` with a
`tag` input creates the tag on the selected branch and publishes from
it, so anyone who may run workflows here may publish a release from any
commit: standard GitHub behaviour, worth narrowing with an environment
protection rule on the release job if this ever has more than one
maintainer. The notes are the tag's `CHANGELOG.md` section alone;
GitHub's generated notes are off, because they list pull request titles
written by whoever opened them and those would reach every reader
unreviewed. `packaging/update.sh` reads `SHA256SUMS` to decide what the
Homebrew formula installs, so when the release is signed and the checkout
has `minisign.pub` it checks the signature before reading the file. The Homebrew CI job installs the
formula from the *live* release it names, so that job depends on GitHub
serving the previous release's archives — deliberate, since it tests
what a person actually gets.

## 4. The Debian package

`packaging/deb/build.sh <version> <amd64|arm64> <dir with the binaries>
<out dir>` lays out the package root, writes `DEBIAN/control` (`Package:
silver-messenger`, the version without its `v`, the architecture,
`Section: net`, `Priority: optional`, no dependencies, the homepage and
the description), `postinst` and `prerm`, the copyright file (AGPL-3.0,
pointing at the licence text on the system where the package is
installed), the unit with `/usr/bin/silver-relay`, and builds with
`dpkg-deb --root-owner-group -Zxz` under `SOURCE_DATE_EPOCH` with every
file's mtime clamped to it, so the same input gives the same package. The
release job runs it for both architectures on the archives it has just
downloaded; CI runs it on the debug build and installs the result.

Lintian shaped it further when the code landed: a Debian changelog
(one entry, the release, pointing at CHANGELOG.md), `Depends: adduser`
for the `postinst`, `deb-systemd-invoke` rather than `systemctl` to stop
a running relay in `prerm`, an override for `statically-linked-binary`,
which is the point of the musl builds, and a copyright notice with a
year. The two binaries have no manual pages, which lintian notes as a
warning; the `--help` of each is the reference for now.

## 5. Tests

* CI (`packaging` job): the Debian package built from the debug binaries
  and installed in `debian:stable-slim` with both binaries run and the
  unit present; `lintian` on the package with errors fatal. The formula
  has its own job on `macos-latest`: this checkout tapped as a person
  would tap it, `brew audit --strict` and `brew style`, then installed
  from the release it names and tested.
* Release: the same Debian build on the release binaries, the packages
  in `SHA256SUMS` and attested; a `packaging` step that runs `update.sh`
  against the new `SHA256SUMS` and attaches the resulting formula to the
  workflow run, so the packaging commit that follows is a copy, not a
  computation.
* By hand, recorded in section 6: the tap installed on a Mac, the `.deb`
  on a Debian machine.

## 6. Status

As of 0.13.0:

| Channel | State |
| --- | --- |
| Debian package | `silver-messenger_0.13.0_amd64.deb` and `_arm64.deb` are on the release page, built by the release workflow from the Linux archives. The amd64 package was downloaded here for 0.10.0, matched `SHA256SUMS`, installed with `dpkg` on this machine (both binaries reported the release), and purged cleanly; `lintian` reports no errors. Not yet installed on a Debian machine with systemd running. |
| Homebrew tap | Live for 0.13.0: the formula in this repository names the 0.13.0 binaries -- the client as its download, the relay as a resource -- and CI taps the repository on macOS, audits the formula, installs it from the release and runs its test on every push. Not yet tried by hand on a Mac. |
| Release page | Fourteen files from 0.12.2: the client and the relay for each of the five targets, the two Debian packages, and `SHA256SUMS` with its signature. The notes lead with which file to take. Checked against the published 0.13.0: fourteen assets, every one of them in the notes' table. The notes' checking section still named a `BUILD-INFO.txt` the page has not carried since 0.12.2 -- it is inside each target's archive among the workflow run's artifacts -- which the template and the README now say. |
| AUR and winget | Removed in 0.12.2. Both were written, linted in CI and regenerated at every release, and neither was ever installable: the AUR needs a push to `aur.archlinux.org` from the maintainer's account, and winget needs a pull request to `microsoft/winget-pkgs` per release. Neither had been done, so both were upkeep producing nothing. An Arch or Windows user takes the one file for their platform from the release page, which is the whole client. If either is ever wanted, the release page carries what a manifest would point at, and writing one again is an afternoon. |
| Authenticode | No certificate in the secrets; the 0.12.1 run printed the notice and the Windows executables went out unsigned. |
| Notarisation | No Apple membership in the secrets; the 0.12.1 run printed the notice and the macOS executables went out unsigned. |
| minisign | Set up as of 0.12.0, and every release since is signed: `minisign.pub` is at the repository root, `MINISIGN_SECRET_KEY` is in the repository's secrets, and the "Signing key check" workflow has confirmed the secret signs and that the published key verifies what it signed. Releases up to 0.11.0 carry `SHA256SUMS` unsigned. `packaging/update.sh` checks the signature before it reads a checksum, so the packages cannot be built from a list nobody signed. Section 3 says what this way is worth against the offline one. |
| Installer | `deploy/install.sh` is in the repository and read before it is run; from 0.12.2 it is not a release asset, because a release page carries the program and nothing else. What replaced it as the checkable path is better: the relay is one file on the page, covered by a `SHA256SUMS` the project signs, so an operator verifies a signature and a checksum rather than reading a script (README, "Running a relay"). |

From 0.12.2 the packaging archive rides on the release workflow run
rather than the release page: it holds the formula `packaging/update.sh`
wrote from that release's checksums, which is what the packaging commit
after a release copies in. It is a maintainer's working file, and a
reader of the release page has no use for it.

## 7. Implementation order

1. The Debian package: the script, the CI job, the release step.
2. The formula, `update.sh`, and their CI checks. A PKGBUILD, its
   `.SRCINFO` and winget manifests were written here too, and removed
   again in 0.12.2: see the row in section 1.
3. The signing and notarising steps, gated on the secrets.
4. README (installing per platform; verifying a signed download),
   OPERATING.md (the relay from the package), CHANGELOG, ROADMAP; this
   note's corrections and section 6.
