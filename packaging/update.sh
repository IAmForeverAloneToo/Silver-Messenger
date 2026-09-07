#!/usr/bin/env bash
# Write the Homebrew formula for a release (docs/design/distribution.md),
# pointing at that release's binaries by the checksums in its SHA256SUMS.
# The formula in the repository is this script's output for the release it
# names; after a release, run it and commit what changed.
#
# The tap is this repository, so the formula works the moment it is
# committed and needs nothing published anywhere else:
#
#   brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger
#   brew install silver-messenger
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

echo "packaging written for $version"
