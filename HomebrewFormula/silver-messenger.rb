# frozen_string_literal: true

# The Homebrew tap of Silver Messenger lives in its repository:
#   brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger
#   brew trust iamforeveralonetoo/silver
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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-v0.21.0-aarch64-apple-darwin"
      sha256 "65a332d5cf4f047463c3039b914485ae0555692b9be8fa85bbc6e458d78d6c79"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-relay-v0.21.0-aarch64-apple-darwin"
        sha256 "a65ba9f3024d4ef5e8a2b042b92ed5c8c55095e6151eab18ce66dc4e381009c9"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-v0.21.0-x86_64-apple-darwin"
      sha256 "5e803ae77cdb7b17d81a877373a8299ac9f943f0a4965b2d470ad899967f4e49"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-relay-v0.21.0-x86_64-apple-darwin"
        sha256 "1754a04f76a8c0d0dbbf0bd7350261553b13a4037ab44aad4bbc82a90e44cb58"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-v0.21.0-aarch64-unknown-linux-musl"
      sha256 "7f56e504797be09707caedfffe8d4f6801b2774f20ce536d2421dd7914ddd9d0"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-relay-v0.21.0-aarch64-unknown-linux-musl"
        sha256 "c2020fec42c43f0d7a9913157332909af3863e0cadfd013acbf25c6998d7bb17"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-v0.21.0-x86_64-unknown-linux-musl"
      sha256 "729709970cb892575cd811730f1e771de16a36b30f1d8cf2652daa6d84847506"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.21.0/silver-relay-v0.21.0-x86_64-unknown-linux-musl"
        sha256 "350c20d6f6d5cfc5fed69e79116d8430d165bf2f27831a3912c009b04d92faa0"
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
