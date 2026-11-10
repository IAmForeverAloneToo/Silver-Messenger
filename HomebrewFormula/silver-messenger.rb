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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-v0.22.0-aarch64-apple-darwin"
      sha256 "2b80337bd35494f5ba4b42417c83c82c404342ea0c8d643a58898d71027c770f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-relay-v0.22.0-aarch64-apple-darwin"
        sha256 "f970e2b1d58f962dd74bcbe42135351649d432f53edfdeb4d02b2aead069bf7a"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-v0.22.0-x86_64-apple-darwin"
      sha256 "a4319c1111708e91836042141ce88b7f0f0f63d5b26343f2d6c7eb113896d691"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-relay-v0.22.0-x86_64-apple-darwin"
        sha256 "142e2d52871c4558ed9af8f4851df19b73676fd844896c862e169d59ebea1f23"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-v0.22.0-aarch64-unknown-linux-musl"
      sha256 "324ff6df94d7f06d2555368037b79e0d906575c907106fc695c006bc93eb9d8c"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-relay-v0.22.0-aarch64-unknown-linux-musl"
        sha256 "f649ad69951b5774363fd84a1fd3e82753d997ca67b709c2e6f1e1c7fef232a8"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-v0.22.0-x86_64-unknown-linux-musl"
      sha256 "477e857591c2e5c1709c871601b2da64b1aebffcab661a0f24ba91a6aa941108"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.22.0/silver-relay-v0.22.0-x86_64-unknown-linux-musl"
        sha256 "9a141610967f851bc1f8137b640ccd3441449cd738cdcd1825db248d08f61fce"
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
