# Design note: distribution

Roadmap item 53. Written before the code, as the record of the decisions;
what ships is described in README.md when the code lands. Where this note
and the code later disagree, the code wins and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What every channel installs | The binaries the release workflow already builds, verifies and attests: the same archives, by checksum, on every channel. No channel builds its own. A package is a wrapper around bytes that `SHA256SUMS` and the provenance attestation already cover, so what `brew`, `winget`, `pacman` or `apt` install is what a person downloading the archive by hand would get. |
| Windows | Authenticode over both executables, in the build job, with `signtool` and a certificate from the repository's secrets (`AUTHENTICODE_PFX`, base64 of the PKCS#12, and `AUTHENTICODE_PASSWORD`), timestamped. Without the secrets the step says so and the release is published unsigned, as the minisign step does; nothing else changes. The certificate is the maintainer's to obtain (a code-signing certificate from a CA, or a free one for open-source projects from SignPath). |
| macOS | `codesign` with a Developer ID Application identity from the secrets (`APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`), hardened runtime and a timestamp, then `notarytool submit --wait` under `APPLE_ID`, `APPLE_TEAM_ID` and `APPLE_APP_PASSWORD`. A bare executable takes a signature but not a stapled ticket (stapling is for bundles, disk images and installer packages), so Gatekeeper checks the ticket online the first time; that is how every command-line tool distributed outside the App Store behaves. Without the secrets the step says so and README keeps the `xattr -d com.apple.quarantine` instruction. The Apple Developer Program membership is the maintainer's to take out. |
| Reproducibility and signatures | A signature is bytes added to the executable, so a signed release differs from a rebuild by exactly the signature. The archives stay the reproducible artefact: CI compares unsigned builds as before, and README says how to compare a signed download (strip the signature with `osslsigncode remove-signature` or `codesign --remove-signature`, then compare). The Linux archives, the Debian packages and the container image carry no embedded signature and reproduce byte for byte. |
| Homebrew | A tap in this repository: `HomebrewFormula/silver-messenger.rb`, which Homebrew finds when the repository is tapped by URL (`brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger`). The formula points at the release archives for macOS (Apple Silicon and Intel) and Linux (x86_64 and aarch64) with their checksums, installs both binaries and the documents, and tests `silver --version`. A separate `homebrew-silver` repository would be the usual shape; one repository is enough for a tap, keeps the formula next to the code it installs, and needs no second set of permissions. |
| winget | Manifests in `packaging/winget/` in the shape the `microsoft/winget-pkgs` repository takes (a portable installer inside the release zip, both executables with their command aliases), generated with the checksums of each release. Publishing is a pull request to that repository, made by the maintainer with `wingetcreate` or by hand; the note records the version last submitted. |
| Arch | `packaging/aur/PKGBUILD` and `.SRCINFO` for `silver-messenger-bin`: the release archive for `x86_64` and `aarch64` by checksum, both binaries, the documents, the licence, and the relay's unit with its path rewritten. Publishing is a push to the AUR under the maintainer's account; the note records the version last pushed. A source package (`silver-messenger`, building with `cargo` from the tag) would not install the same bytes and is not made. |
| Debian and Ubuntu | A `.deb` per architecture (`amd64`, `arm64`) built in the release workflow from the Linux archives with `dpkg-deb`, attached to the release beside the archives, in `SHA256SUMS` and attested like everything else. It installs `/usr/bin/silver`, `/usr/bin/silver-relay`, the relay's unit in `/lib/systemd/system/` with its path rewritten (installed, not enabled), the documents and the copyright file; its `postinst` creates the relay's system user and runs `systemctl daemon-reload` where systemd is present; `prerm` stops and disables the unit. The package depends on nothing: the binaries are static. No repository is run; the file is installed with `apt install ./silver-messenger_<version>_<arch>.deb`, which resolves nothing and checks nothing beyond the file, so the checksum and the attestation are the person's check, as for the archives. |
| Keeping the packaging current | The checksums change with every release, so `packaging/update.sh <version>` reads the release's `SHA256SUMS` and rewrites the formula, the PKGBUILD, the `.SRCINFO` and the winget manifests; the result is committed after the release, by hand, as the packaging commit for that version. Nothing in the workflows commits to the repository. |
| Checking the packaging in CI | The Debian build script runs on every push against the debug binaries, and the package is installed in a Debian container and both binaries run; the formula is checked with `brew audit --strict` and `brew style` on the macOS runner where Homebrew is present, against a copy of the formula that points at the artefacts of that run, so the audit sees a real download; the PKGBUILD is checked with `namcap` in an Arch container, and `makepkg --printsrcinfo` must reproduce the committed `.SRCINFO`; the winget manifests are checked against their schema with `winget validate` on the Windows runner. The signing and notarising steps cannot be checked without the secrets and are marked unchecked until the first signed release. |

## 2. Goals and non-goals

Goals:

* A person on each platform installs the client (and the relay, which
  ships beside it) with the tool they already use, and gets the bytes the
  release page carries.
* Every artefact on every channel is covered by `SHA256SUMS`, its
  signature and the provenance attestation, so the channel adds
  convenience and no trust.
* Nothing in the workflows needs credentials that the repository does not
  hold: the maintainer's accounts (Apple, a certificate authority, the
  AUR, a winget pull request) are used by the maintainer, and every step
  that needs one says clearly when it is missing.

Non-goals:

* Running a package repository (an apt or a Homebrew core submission):
  each of those is a commitment to a cadence and a review process that
  this project has not made yet.
* A Windows installer (`.msi`) or a macOS `.pkg`: the client is a
  terminal program and both platforms run it from a folder; winget and
  Homebrew give the command-line install.
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

## 5. Tests

* CI (`packaging` job): the Debian package built from the debug binaries
  and installed in `debian:stable-slim` with both binaries run and the
  unit present; `lintian` on the package with errors fatal; `namcap` on
  the PKGBUILD and `makepkg --printsrcinfo` against `.SRCINFO` in
  `archlinux:base-devel`; `brew audit --strict --formula` and `brew
  style` on `macos-latest`; `winget validate` on `windows-latest`.
* Release: the same Debian build on the release archives, the packages
  in `SHA256SUMS` and attested; a `packaging` step that runs `update.sh`
  against the new `SHA256SUMS` and uploads the resulting formula,
  PKGBUILD, `.SRCINFO` and manifests as release assets, so the packaging
  commit that follows is a copy, not a computation.
* By hand, recorded in section 6: the tap installed on a Mac, the `.deb`
  on a Debian machine, the PKGBUILD with `makepkg -si` on Arch, the
  winget manifest with `winget install --manifest`.

## 6. Status

To be filled in as the channels go live: which release each carries,
which signing secrets exist, and what was checked by hand.

## 7. Implementation order

1. The Debian package: the script, the CI job, the release step.
2. The formula, the PKGBUILD and `.SRCINFO`, the winget manifests,
   `update.sh`; their CI checks.
3. The signing and notarising steps, gated on the secrets.
4. README (installing per platform; verifying a signed download),
   OPERATING.md (the relay from the package), CHANGELOG, ROADMAP; this
   note's corrections and section 6.
