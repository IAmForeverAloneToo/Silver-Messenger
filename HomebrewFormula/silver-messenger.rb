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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-v0.25.0-aarch64-apple-darwin"
      sha256 "eb942e049375cb13560310b274018d6ecc593b6e9c7ae5e377a3df0b47d5640c"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-relay-v0.25.0-aarch64-apple-darwin"
        sha256 "844613ff5fdd0d54c227042f73e67ca6730696aecef8b2023b3d85c575470a07"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-v0.25.0-x86_64-apple-darwin"
      sha256 "d7887bd52b18c377f0be21d0219ba92f20df9758592fad6bfbf6b453b31102df"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-relay-v0.25.0-x86_64-apple-darwin"
        sha256 "a28bd9a7f7f2cbb8ac286d91c6c50f675e5af27175ad2467239f34dc36b0cbfa"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-v0.25.0-aarch64-unknown-linux-musl"
      sha256 "2531dbefbd6a41d7c8629a0f7d3ff81fadd07a4529bb61a243f8616ce7add58d"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-relay-v0.25.0-aarch64-unknown-linux-musl"
        sha256 "4ca81f1243906c057e8c5bc96ddefb0ce693a0266cb1d4cc9c8f3043933a5b0d"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-v0.25.0-x86_64-unknown-linux-musl"
      sha256 "7532d3e3faa677ac854e482cf6e77ef90066be46156cb1a1d0816c349c338842"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.25.0/silver-relay-v0.25.0-x86_64-unknown-linux-musl"
        sha256 "b6f4b4a4d482a86e7a3929d5bcfdef086bd8b66867712de635f2327abf4f644e"
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
