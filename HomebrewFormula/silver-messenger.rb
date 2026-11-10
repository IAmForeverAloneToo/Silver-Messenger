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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-v0.23.1-aarch64-apple-darwin"
      sha256 "033032f0e675c0cf6ea6a2f678338a5afc34f9774ae6c62e3326535055c9120b"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-relay-v0.23.1-aarch64-apple-darwin"
        sha256 "472efa6ac8a270a0b50fc2b774b19613c117d038def14158b821b0101375dcde"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-v0.23.1-x86_64-apple-darwin"
      sha256 "34eca028f749ad72034dd999cc57a6589c40f8dd1e3d8dd1f33bfb2a0c94a040"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-relay-v0.23.1-x86_64-apple-darwin"
        sha256 "fe26e2251470b47d681e684aa1f38b9240ec598ec9781949f7288768fafc17e0"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-v0.23.1-aarch64-unknown-linux-musl"
      sha256 "b4757fbcf30c62e162baf3516156856e6a82ab5860c69598213752cb7a3e1d3b"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-relay-v0.23.1-aarch64-unknown-linux-musl"
        sha256 "2cfc423e16323addcb26318b64f7e870ea0da9e0fc9d9f6989c7e90f614c3da9"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-v0.23.1-x86_64-unknown-linux-musl"
      sha256 "6f4f53c6a29ecdd762d46e1259454549c9a1ebe2a8b4aebfdca8c49346156883"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.1/silver-relay-v0.23.1-x86_64-unknown-linux-musl"
        sha256 "e24f57bb55059b3f47f6d4fb7adfcd6ff7fe8a6e7d40936904b4e39e974abc40"
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
