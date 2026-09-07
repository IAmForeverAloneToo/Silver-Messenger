#!/usr/bin/env bash
# Write the packaging for a release (docs/design/distribution.md): the
# Homebrew formula, the PKGBUILD and its .SRCINFO, and the winget
# manifests, each pointing at that release's archives by the checksums in
# its SHA256SUMS. The files in the repository are this script's output for
# the release they name; after a release, run it and commit what changed.
#
#   packaging/update.sh <version>                   # v0.10.0 or 0.10.0; SHA256SUMS is fetched
#   packaging/update.sh <version> <SHA256SUMS file>  # one already downloaded
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <version> [SHA256SUMS file]" >&2
  exit 2
fi
version="${1#v}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
url="https://github.com/IAmForeverAloneToo/Silver-Messenger"
download="$url/releases/download/v$version"

sums="${2:-}"
if [ -z "$sums" ]; then
  sums="$(mktemp)"
  sig="$sums.minisig"
  trap 'rm -f "$sums" "$sig"' EXIT
  curl -fsSL "$download/SHA256SUMS" > "$sums"
  # Every checksum below comes out of this file, so it decides what the
  # packages install. When the release is signed and this checkout carries
  # the public key, check the signature before reading it; the list is
  # fetched over HTTPS from GitHub either way, and a signature is the only
  # thing that does not rest on GitHub (SM-S-09).
  if [ -f "$repo/minisign.pub" ] && command -v minisign >/dev/null; then
    curl -fsSL "$download/SHA256SUMS.minisig" > "$sig" ||
      { echo "release v$version publishes no SHA256SUMS.minisig, though this checkout has minisign.pub" >&2; exit 1; }
    minisign -Vm "$sums" -x "$sig" -p "$repo/minisign.pub" >/dev/null ||
      { echo "SHA256SUMS does not verify against minisign.pub" >&2; exit 1; }
    echo "SHA256SUMS verified against minisign.pub"
  elif [ -f "$repo/minisign.pub" ]; then
    echo "note: minisign is not installed, so SHA256SUMS is used unverified" >&2
  fi
fi

# The checksum of a release file, from SHA256SUMS.
sum_of() {
  local found
  found="$(awk -v f="$1" '$2 == f { print $1 }' "$sums")"
  if [ -z "$found" ]; then
    echo "SHA256SUMS has no line for $1" >&2
    exit 1
  fi
  printf '%s' "$found"
}
# A release carries the two programs, one file per target, and nothing
# that is not the program (docs/design/distribution.md). Every package
# below installs those files rather than unpacking an archive.
client() { printf 'silver-v%s-%s' "$version" "$1"; }
relay() { printf 'silver-relay-v%s-%s' "$version" "$1"; }

mac_arm="$(sum_of "$(client aarch64-apple-darwin)")"
mac_arm_relay="$(sum_of "$(relay aarch64-apple-darwin)")"
mac_intel="$(sum_of "$(client x86_64-apple-darwin)")"
mac_intel_relay="$(sum_of "$(relay x86_64-apple-darwin)")"
linux_arm="$(sum_of "$(client aarch64-unknown-linux-musl)")"
linux_arm_relay="$(sum_of "$(relay aarch64-unknown-linux-musl)")"
linux_intel="$(sum_of "$(client x86_64-unknown-linux-musl)")"
linux_intel_relay="$(sum_of "$(relay x86_64-unknown-linux-musl)")"
windows="$(sum_of "$(client x86_64-pc-windows-msvc).exe")"
# The relay's unit as it is at the tag, which the Arch package installs:
# the tag's copy from the repository, or, while the tag does not exist yet
# (the release workflow makes it last), the checkout's, which is the
# tagged commit then.
unit="$(mktemp)"
if curl -fsSL "$url/raw/v$version/deploy/silver-relay.service" -o "$unit" 2>/dev/null; then
  service="$(sha256sum "$unit" | cut -d' ' -f1)"
elif [ -f "$repo/deploy/silver-relay.service" ]; then
  service="$(sha256sum "$repo/deploy/silver-relay.service" | cut -d' ' -f1)"
else
  echo "no tag v$version in the repository and no deploy/silver-relay.service in this checkout" >&2
  exit 1
fi
rm -f "$unit"

# The readme and the licence, which the Arch package used to take out of
# the archive. A release carries the programs and nothing else now, so
# these come from the tag the same way the unit does.
from_tag() {
  local f="$(mktemp)" sum
  if curl -fsSL "$url/raw/v$version/$1" -o "$f" 2>/dev/null; then
    sum="$(sha256sum "$f" | cut -d' ' -f1)"
  elif [ -f "$repo/$1" ]; then
    sum="$(sha256sum "$repo/$1" | cut -d' ' -f1)"
  else
    echo "no tag v$version in the repository and no $1 in this checkout" >&2
    rm -f "$f"
    exit 1
  fi
  rm -f "$f"
  printf '%s' "$sum"
}
readme="$(from_tag README.md)"
license="$(from_tag LICENSE)"

sysusers="$(sha256sum "$here/aur/silver-messenger.sysusers" | cut -d' ' -f1)"

# --- Homebrew ---------------------------------------------------------------

mkdir -p "$repo/HomebrewFormula"
cat > "$repo/HomebrewFormula/silver-messenger.rb" <<EOF
# frozen_string_literal: true

# The Homebrew tap of Silver Messenger lives in its repository:
#   brew tap iamforeveralonetoo/silver $url
#   brew install silver-messenger
# It installs the release archives by checksum. packaging/update.sh writes
# this file for a release; edit it there.
class SilverMessenger < Formula
  desc "End-to-end encrypted messaging in your terminal: the client and the relay"
  homepage "$url"
  license "AGPL-3.0-only"

  # A release carries the two programs as two files, so the client is the
  # download and the relay is a resource beside it.
  on_macos do
    on_arm do
      url "$download/$(client aarch64-apple-darwin)"
      sha256 "$mac_arm"
      resource "relay" do
        url "$download/$(relay aarch64-apple-darwin)"
        sha256 "$mac_arm_relay"
      end
    end
    on_intel do
      url "$download/$(client x86_64-apple-darwin)"
      sha256 "$mac_intel"
      resource "relay" do
        url "$download/$(relay x86_64-apple-darwin)"
        sha256 "$mac_intel_relay"
      end
    end
  end

  on_linux do
    on_arm do
      url "$download/$(client aarch64-unknown-linux-musl)"
      sha256 "$linux_arm"
      resource "relay" do
        url "$download/$(relay aarch64-unknown-linux-musl)"
        sha256 "$linux_arm_relay"
      end
    end
    on_intel do
      url "$download/$(client x86_64-unknown-linux-musl)"
      sha256 "$linux_intel"
      resource "relay" do
        url "$download/$(relay x86_64-unknown-linux-musl)"
        sha256 "$linux_intel_relay"
      end
    end
  end

  def install
    # The downloads keep their release names, which carry the version and
    # the target; both are installed under the names people type.
    bin.install Dir["silver-v*"].first => "silver"
    resource("relay").stage do
      bin.install Dir["silver-relay-v*"].first => "silver-relay"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/silver --version")
  end
end
EOF

# --- Arch (AUR) ---------------------------------------------------------------

cat > "$here/aur/PKGBUILD" <<EOF
# Maintainer: IAmForeverAloneToo <16734439+IAmForeverAloneToo@users.noreply.github.com>
# The release archives by checksum. packaging/update.sh writes this file
# and .SRCINFO for a release; edit it there.
pkgname=silver-messenger-bin
pkgver=$version
pkgrel=1
pkgdesc="End-to-end encrypted messaging in your terminal: the client and the relay"
arch=('x86_64' 'aarch64')
url="$url"
license=('AGPL-3.0-only')
provides=('silver-messenger')
conflicts=('silver-messenger')
# The release binaries are stripped and reproducible; their bytes stay.
options=('!strip')
# A release carries the two programs as two files; the licence and the
# readme come from the tag, as the unit already does.
source=("silver-relay-\$pkgver.service::\$url/raw/v\$pkgver/deploy/silver-relay.service"
        "silver-messenger-\$pkgver.README.md::\$url/raw/v\$pkgver/README.md"
        "silver-messenger-\$pkgver.LICENSE::\$url/raw/v\$pkgver/LICENSE"
        'silver-messenger.sysusers')
source_x86_64=("\$url/releases/download/v\$pkgver/silver-v\$pkgver-x86_64-unknown-linux-musl"
               "\$url/releases/download/v\$pkgver/silver-relay-v\$pkgver-x86_64-unknown-linux-musl")
source_aarch64=("\$url/releases/download/v\$pkgver/silver-v\$pkgver-aarch64-unknown-linux-musl"
                "\$url/releases/download/v\$pkgver/silver-relay-v\$pkgver-aarch64-unknown-linux-musl")
sha256sums=('$service'
            '$readme'
            '$license'
            '$sysusers')
sha256sums_x86_64=('$linux_intel'
                   '$linux_intel_relay')
sha256sums_aarch64=('$linux_arm'
                    '$linux_arm_relay')

package() {
  install -Dm755 "\$srcdir/silver-v\$pkgver-\$CARCH-unknown-linux-musl" "\$pkgdir/usr/bin/silver"
  install -Dm755 "\$srcdir/silver-relay-v\$pkgver-\$CARCH-unknown-linux-musl" "\$pkgdir/usr/bin/silver-relay"
  install -Dm644 "\$srcdir/silver-messenger-\$pkgver.README.md" "\$pkgdir/usr/share/doc/silver-messenger/README.md"
  install -Dm644 "\$srcdir/silver-messenger-\$pkgver.LICENSE" "\$pkgdir/usr/share/licenses/\$pkgname/LICENSE"
  sed 's|/usr/local/bin/silver-relay|/usr/bin/silver-relay|' "\$srcdir/silver-relay-\$pkgver.service" |
    install -Dm644 /dev/stdin "\$pkgdir/usr/lib/systemd/system/silver-relay.service"
  install -Dm644 "\$srcdir/silver-messenger.sysusers" "\$pkgdir/usr/lib/sysusers.d/silver-messenger.conf"
}
EOF

cat > "$here/aur/.SRCINFO" <<EOF
pkgbase = silver-messenger-bin
	pkgdesc = End-to-end encrypted messaging in your terminal: the client and the relay
	pkgver = $version
	pkgrel = 1
	url = $url
	arch = x86_64
	arch = aarch64
	license = AGPL-3.0-only
	provides = silver-messenger
	conflicts = silver-messenger
	options = !strip
	source = silver-relay-$version.service::$url/raw/v$version/deploy/silver-relay.service
	source = silver-messenger-$version.README.md::$url/raw/v$version/README.md
	source = silver-messenger-$version.LICENSE::$url/raw/v$version/LICENSE
	source = silver-messenger.sysusers
	sha256sums = $service
	sha256sums = $readme
	sha256sums = $license
	sha256sums = $sysusers
	source_x86_64 = $download/$(client x86_64-unknown-linux-musl)
	source_x86_64 = $download/$(relay x86_64-unknown-linux-musl)
	sha256sums_x86_64 = $linux_intel
	sha256sums_x86_64 = $linux_intel_relay
	source_aarch64 = $download/$(client aarch64-unknown-linux-musl)
	source_aarch64 = $download/$(relay aarch64-unknown-linux-musl)
	sha256sums_aarch64 = $linux_arm
	sha256sums_aarch64 = $linux_arm_relay

pkgname = silver-messenger-bin
EOF

# --- winget -------------------------------------------------------------------

mkdir -p "$here/winget"
id="IAmForeverAloneToo.SilverMessenger"
cat > "$here/winget/$id.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
# packaging/update.sh writes the manifests for a release; edit it there.
PackageIdentifier: $id
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
EOF

cat > "$here/winget/$id.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: $id
PackageVersion: $version
# The client is the executable itself now, not an archive holding one, so
# winget installs it as a portable command under the name people type.
# The relay is not a thing anyone installs on Windows with a package
# manager; it is on the release page for whoever wants it.
InstallerType: portable
Commands:
  - silver
Installers:
  - Architecture: x64
    InstallerUrl: $download/$(client x86_64-pc-windows-msvc).exe
    InstallerSha256: $(printf '%s' "$windows" | tr 'a-f' 'A-F')
ManifestType: installer
ManifestVersion: 1.6.0
EOF

cat > "$here/winget/$id.locale.en-US.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: $id
PackageVersion: $version
PackageLocale: en-US
Publisher: IAmForeverAloneToo
PublisherUrl: https://github.com/IAmForeverAloneToo
PublisherSupportUrl: $url/issues
PackageName: Silver Messenger
PackageUrl: $url
License: AGPL-3.0-only
LicenseUrl: $url/blob/main/LICENSE
ShortDescription: End-to-end encrypted messaging in your terminal
Description: The client (silver) and the relay (silver-relay) of Silver Messenger, a terminal messenger with forward-secret, post-quantum encryption, groups on MLS and several devices per identity.
Tags:
  - encryption
  - messenger
  - terminal
ReleaseNotesUrl: $url/releases/tag/v$version
ManifestType: defaultLocale
ManifestVersion: 1.6.0
EOF

echo "packaging written for $version"
