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
  trap 'rm -f "$sums"' EXIT
  curl -fsSL "$download/SHA256SUMS" > "$sums"
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
archive() { printf 'silver-messenger-v%s-%s' "$version" "$1"; }

mac_arm="$(sum_of "$(archive aarch64-apple-darwin).tar.gz")"
mac_intel="$(sum_of "$(archive x86_64-apple-darwin).tar.gz")"
linux_arm="$(sum_of "$(archive aarch64-unknown-linux-musl).tar.gz")"
linux_intel="$(sum_of "$(archive x86_64-unknown-linux-musl).tar.gz")"
windows="$(sum_of "$(archive x86_64-pc-windows-msvc).zip")"
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
sysusers="$(sha256sum "$here/aur/silver-messenger.sysusers" | cut -d' ' -f1)"

# --- Homebrew ---------------------------------------------------------------

mkdir -p "$repo/HomebrewFormula"
cat > "$repo/HomebrewFormula/silver-messenger.rb" <<EOF
# The Homebrew tap of Silver Messenger lives in its repository:
#   brew tap iamforeveralonetoo/silver $url
#   brew install silver-messenger
# It installs the release archives by checksum. packaging/update.sh writes
# this file for a release; edit it there.
class SilverMessenger < Formula
  desc "End-to-end encrypted messaging in your terminal: the client and the relay"
  homepage "$url"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "$download/$(archive aarch64-apple-darwin).tar.gz"
      sha256 "$mac_arm"
    end
    on_intel do
      url "$download/$(archive x86_64-apple-darwin).tar.gz"
      sha256 "$mac_intel"
    end
  end

  on_linux do
    on_arm do
      url "$download/$(archive aarch64-unknown-linux-musl).tar.gz"
      sha256 "$linux_arm"
    end
    on_intel do
      url "$download/$(archive x86_64-unknown-linux-musl).tar.gz"
      sha256 "$linux_intel"
    end
  end

  def install
    bin.install "silver", "silver-relay"
    doc.install "README.md", "CHANGELOG.md"
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
source=("silver-relay-\$pkgver.service::\$url/raw/v\$pkgver/deploy/silver-relay.service"
        'silver-messenger.sysusers')
source_x86_64=("\$url/releases/download/v\$pkgver/silver-messenger-v\$pkgver-x86_64-unknown-linux-musl.tar.gz")
source_aarch64=("\$url/releases/download/v\$pkgver/silver-messenger-v\$pkgver-aarch64-unknown-linux-musl.tar.gz")
sha256sums=('$service'
            '$sysusers')
sha256sums_x86_64=('$linux_intel')
sha256sums_aarch64=('$linux_arm')

package() {
  cd "silver-messenger-v\$pkgver-\$CARCH-unknown-linux-musl"
  install -Dm755 silver "\$pkgdir/usr/bin/silver"
  install -Dm755 silver-relay "\$pkgdir/usr/bin/silver-relay"
  install -Dm644 README.md CHANGELOG.md -t "\$pkgdir/usr/share/doc/silver-messenger"
  install -Dm644 LICENSE "\$pkgdir/usr/share/licenses/\$pkgname/LICENSE"
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
	source = silver-messenger.sysusers
	sha256sums = $service
	sha256sums = $sysusers
	source_x86_64 = $download/$(archive x86_64-unknown-linux-musl).tar.gz
	sha256sums_x86_64 = $linux_intel
	source_aarch64 = $download/$(archive aarch64-unknown-linux-musl).tar.gz
	sha256sums_aarch64 = $linux_arm

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
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: $(archive x86_64-pc-windows-msvc)\\silver.exe
    PortableCommandAlias: silver
  - RelativeFilePath: $(archive x86_64-pc-windows-msvc)\\silver-relay.exe
    PortableCommandAlias: silver-relay
Installers:
  - Architecture: x64
    InstallerUrl: $download/$(archive x86_64-pc-windows-msvc).zip
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
