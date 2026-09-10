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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-v0.17.0-aarch64-apple-darwin"
      sha256 "6d3bd76e57886248bde9f5322bc59a4de67ea31df94b4d3a3561572ba3383997"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-relay-v0.17.0-aarch64-apple-darwin"
        sha256 "860bd634941e579d2488de71c6902d0c1173db4ba72a9bd0ddbbee28d7c3b7a9"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-v0.17.0-x86_64-apple-darwin"
      sha256 "abc34e0e3a6d4be3872c88841e1c2b941a3a8586f23b918bc180a3c5353a55e4"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-relay-v0.17.0-x86_64-apple-darwin"
        sha256 "9c7eeffd663297547e4fa70f8f077df14f6e80dfa96dcff4d7c094ae737c7b8f"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-v0.17.0-aarch64-unknown-linux-musl"
      sha256 "dde7a8cae61bc46fb14a7b7c5adf0aa4696ca5eaa1144ad1ae5d7a1f379cf80f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-relay-v0.17.0-aarch64-unknown-linux-musl"
        sha256 "88b9013acb4f7b1197c667430d0fdad48d96365474e94b9fde904dd5adc1ea72"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-v0.17.0-x86_64-unknown-linux-musl"
      sha256 "d239e98108f777018693405c220ddb22d55c4b66cbd830eb5b920b616d5d8dbf"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.17.0/silver-relay-v0.17.0-x86_64-unknown-linux-musl"
        sha256 "e074bda7a12bf048246060c4493962bb9117042af1a69805589d19ac176eef26"
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
