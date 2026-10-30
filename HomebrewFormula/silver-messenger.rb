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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-v0.20.0-aarch64-apple-darwin"
      sha256 "7e6e38765275bc7e1029ce89bf6ddba05bb77c6d441c7a8609dc35a239d9248f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-relay-v0.20.0-aarch64-apple-darwin"
        sha256 "6a60b8b8ea0a084380d378b349bfb57b31058514d67b4e9c4e5e38dbad8c24d5"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-v0.20.0-x86_64-apple-darwin"
      sha256 "8e5c8d757d924623ca1c77ca8fc3b5245112991f346c82cdebe5a74a6fb52fd6"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-relay-v0.20.0-x86_64-apple-darwin"
        sha256 "0a0abb014c1ce9f7caeced4afbbbd95753361437a5c748880a21658c6c66e04f"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-v0.20.0-aarch64-unknown-linux-musl"
      sha256 "7ca95c40b8bd8653d1da94e5bf55227b8c3ce0218f1cfac2659db55c5204f2b9"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-relay-v0.20.0-aarch64-unknown-linux-musl"
        sha256 "ff4253d6e4095ec506cfe6762d8cbc7ab868486d2654df6e2a6bc39e81313c0f"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-v0.20.0-x86_64-unknown-linux-musl"
      sha256 "240410fd4767408a67f4ed16f1e1919a329bbcb62f2e6c0558fc7e27a2baee10"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.20.0/silver-relay-v0.20.0-x86_64-unknown-linux-musl"
        sha256 "55d97e3c3a741a70b0d4062555cc790ff54479b01758c56869b2859317eb7ec4"
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
