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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-v0.13.0-aarch64-apple-darwin"
      sha256 "1aae230a7f139f699031aaff00079a3cd5d05a4d3d290a93c809187c715d4924"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-relay-v0.13.0-aarch64-apple-darwin"
        sha256 "9b4d27c61af25369aa3fd4e9c24ef248c31c97b61521af44f1472afd9f713241"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-v0.13.0-x86_64-apple-darwin"
      sha256 "c371ed39e0b8d6b8ad0cc6c96833c52059d204e2b3f0dbb70efbb8c62fd9b4b9"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-relay-v0.13.0-x86_64-apple-darwin"
        sha256 "ed2d0099382ee9aa8d905ce15e7837657099c41ef2f7b32d7eef362b5c22a507"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-v0.13.0-aarch64-unknown-linux-musl"
      sha256 "337a21a7777999ba744f08c23b33106a6759e28e31ee0303fe4d0c02dc858d2f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-relay-v0.13.0-aarch64-unknown-linux-musl"
        sha256 "dd7f311807aacd57319337b5889f8667ccce5b7815b2d5aab08777d733c12d53"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-v0.13.0-x86_64-unknown-linux-musl"
      sha256 "01ac165c07110440608a6f9aa29bf8cf46cbb6fb0d31f75a73ab045f156dd5ff"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.13.0/silver-relay-v0.13.0-x86_64-unknown-linux-musl"
        sha256 "9219f68c63f6150d82e2c29b9db06fbc03bba1ee8a4a570e2f574a7265e3ec44"
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
