# frozen_string_literal: true

# The Homebrew tap of Silver Messenger lives in its repository:
#   brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger
#   brew install silver-messenger
# It installs the release archives by checksum. packaging/update.sh writes
# this file for a release; edit it there.
class SilverMessenger < Formula
  desc "End-to-end encrypted messaging in your terminal: the client and the relay"
  homepage "https://github.com/IAmForeverAloneToo/Silver-Messenger"
  license "AGPL-3.0-only"

  # A release carries the two programs as two files, so the client is the
  # download and the relay is a resource beside it.
  on_macos do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-v0.14.0-aarch64-apple-darwin"
      sha256 "8794bbf906d2942767ce752d64c88c63583676ae529c2a77a15c960ea7667592"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-relay-v0.14.0-aarch64-apple-darwin"
        sha256 "a5878dd4b886b457e0d5090dbf6967cc53a5ca46edbc81a60b28262cf6c3d2fd"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-v0.14.0-x86_64-apple-darwin"
      sha256 "41ae58aa0169713608dc0597ba7cc24f432f21710aeb67a25e75f97c7641b140"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-relay-v0.14.0-x86_64-apple-darwin"
        sha256 "c9454095a1333da224c6d15b1199109f107744f604e1e47e6e82a80d82dbb568"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-v0.14.0-aarch64-unknown-linux-musl"
      sha256 "106016759ac9fcf57c27f401e7eaeff4a72fdf8667c6ca1014d03f6573f21a59"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-relay-v0.14.0-aarch64-unknown-linux-musl"
        sha256 "1aaad37424e562fe0833a083963b11c410347564f5c7c986dea4a21ed0cd940a"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-v0.14.0-x86_64-unknown-linux-musl"
      sha256 "0b6ccfe2752ae08102080b1687e122b68e636367552bdb46f42c07ee939b0e97"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.14.0/silver-relay-v0.14.0-x86_64-unknown-linux-musl"
        sha256 "c4e16fb1967bdea6d3b43b4bc7709e94f4c5f0b2f55a8739cdc8b2e99d942471"
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
