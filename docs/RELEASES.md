# Releases

What a release of Silver Messenger carries, how to check a download
before running it, how to rebuild a release and compare, and how a
release is made and signed. Installing is in the README; running a
relay from a release is in [OPERATING.md](OPERATING.md); what the
signature and the attestation defend against, and what they do not, is
the threat model's *Supply chain* section
([THREAT_MODEL.md](THREAT_MODEL.md)).

## What a release carries

The [releases page](https://github.com/IAmForeverAloneToo/Silver-Messenger/releases)
carries fourteen files:

| File | What it is |
| --- | --- |
| `silver-v<version>-<target>` | The client, one file, for each of five targets |
| `silver-relay-v<version>-<target>` | The relay, likewise |
| `silver-messenger_<version>_amd64.deb`, `_arm64.deb` | The Debian packages, built from the Linux binaries |
| `SHA256SUMS`, `SHA256SUMS.minisig` | The hashes of every file above, and the project's signature over them |

The targets are `x86_64-pc-windows-msvc` (`.exe`), `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`; the Linux binaries are static and run on
any distribution. Every file carries a build provenance attestation
from GitHub. The notes lead with which file to take and are the
release's section of [CHANGELOG.md](../CHANGELOG.md), nothing more.

The workflow run that built the release keeps an archive per target
among its artifacts, `silver-messenger-v<version>-<target>`, holding
the client and the relay with a CycloneDX SBOM per binary, a
`BUILD-INFO.txt` naming the compiler and the flags, the changelog and
the licence (`tar xzf <archive> --wildcards '*/sbom/*'` gets the SBOMs).
Each release also publishes the relay's container image,
`ghcr.io/iamforeveralonetoo/silver-relay`, for amd64 and arm64.

Releases before 0.12.0 carry no signature; the attestation is what
those are checked against.

## Verifying a download

With the file, `SHA256SUMS` and `SHA256SUMS.minisig` from the release
page, and `minisign.pub` from the repository root:

```sh
minisign -Vm SHA256SUMS -p minisign.pub           # the list is the project's
sha256sum -c SHA256SUMS --ignore-missing          # the file is what was published
gh attestation verify silver-v* --owner IAmForeverAloneToo   # built by the release workflow, from the tagged commit
cargo audit bin silver                            # the dependencies inside the binary, against the advisory database
```

The signature says the list came from this project's key, and it asks
GitHub nothing. The attestation says the file was built by the release
workflow from the tagged commit, and GitHub's transparency log holds
that record. The two are separate roots of trust; the `SHA256SUMS` the
first command verified covers every file in the release, so the second
command checks any of them. For the container image:

```sh
gh attestation verify oci://ghcr.io/iamforeveralonetoo/silver-relay:<version> --owner IAmForeverAloneToo
```

`silver update` runs the first three checks itself, against the key
compiled into the client, before it replaces the running binary; the
README's *Updating* section says what it does.

## Reproducing a build

The binaries are reproducible: build the tagged commit and the bytes
match. CI does this twice on every push for Linux and fails when they
differ. The compiler is part of that, so it is pinned in
`rust-toolchain.toml` at the tag and named in the `BUILD-INFO.txt` the
run's archives carry; rustup picks it up from the file on its own. From
a fresh clone at the tag, on Linux:

```sh
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$HOME/.cargo=/cargo" \
cargo auditable build --release --locked --workspace --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/silver-relay   # compare with SHA256SUMS
```

A signed Windows or macOS executable (the release notes say whether a
release is signed) differs from a rebuild by its signature alone: strip
it and compare (`osslsigncode remove-signature -in silver.exe -out
plain.exe` on any platform, `codesign --remove-signature silver` on a
Mac). The Linux binaries, the Debian packages and the container image
carry no embedded signature and reproduce byte for byte;
`deploy/Dockerfile` builds the image from source with the release's
flags, so it matches.

## How a release is made

Pushing a `v*` tag, or running the release workflow with a tag, builds
the two programs for every target with `cargo auditable`, writes the
SBOM and the `BUILD-INFO.txt` per target into the archive the run
keeps, builds the Debian packages from the Linux binaries, publishes
the binaries, the packages and `SHA256SUMS` with its signature on the
release page, and attests the provenance of every file there. Running
the workflow by hand creates the tag on the chosen branch, so anyone
who may run workflows here may publish a release from any commit,
which is standard GitHub behaviour and a reason the account itself is
what to protect.

After the release, `packaging/update.sh <version>` reads the release's
`SHA256SUMS`, checks its signature against `minisign.pub`, and rewrites
the Homebrew formula with the new checksums; the result is committed
by hand as the packaging commit for that version. Nothing in the
workflows commits to the repository.
[design/distribution.md](design/distribution.md) says where each
channel stands.

## Signing

**`SHA256SUMS`** is signed with the project's minisign key. Its public
half is `minisign.pub` at the repository root, and it is compiled into
the client, which is what `silver update` checks against. The secret
half is the repository secret `MINISIGN_SECRET_KEY`; the release
workflow signs with it and verifies its own signature against the
published key before publishing, so a secret that is not the published
key fails the release rather than shipping something nobody can check.
*Actions → Signing key check* runs those two steps on their own, for
after the secret is set or the key rotated.

Signing from a secret is weaker than signing on a machine the
maintainer holds, since whoever can run a workflow with secrets can
sign, and stronger than not signing, since the secret store and the
release assets are separate systems and tampering with the published
files alone does not survive it. Moving the key offline changes one
workflow step and nothing a verifier does: `packaging/new-signing-key.sh
--by-hand` (`new-signing-key.ps1 -ByHand` on Windows) makes such a key,
the release is then signed with

```sh
minisign -Sm SHA256SUMS -t "Silver Messenger v0.0.0"
```

and `SHA256SUMS.minisig` is attached to the release by hand.

**The executables** are signed in the workflow when the platform's
secrets exist. A code-signing certificate lets the platform's own
checker name the signer, which is a different claim from the one above
and useful only where the platform makes it: on Windows with
Authenticode from `AUTHENTICODE_PFX` (the PKCS#12 file, base64) and
`AUTHENTICODE_PASSWORD`; on macOS with a Developer ID Application
certificate from `APPLE_CERTIFICATE_P12` (base64) and
`APPLE_CERTIFICATE_PASSWORD`, then notarised under `APPLE_ID`,
`APPLE_TEAM_ID` and `APPLE_APP_PASSWORD` (an app-specific password).
With none of a platform's secrets the workflow says so and publishes
that platform unsigned; with some but not all it fails, since a half-set
secret is a mistake. A bare executable takes a signature but no stapled
notarisation ticket, so Gatekeeper asks Apple about it the first time.
A macOS build made without the Apple secrets is signed ad hoc with the
hardened runtime requested; whether macOS then refuses a same-user
attach has not been watched on a real Mac, and the threat model counts
macOS as unprotected until it has.
