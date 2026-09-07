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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-v0.12.3-aarch64-apple-darwin"
      sha256 "3bb6269739cfbd4b9c4d6d2ada6e9130070ea6d8b2275caef54fd7eb7f95381f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-relay-v0.12.3-aarch64-apple-darwin"
        sha256 "b22b136f6314d16bca033f13e69b802776b792efa23ba7412ae1df25ce4ada10"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-v0.12.3-x86_64-apple-darwin"
      sha256 "0bfc02ea1cac8807d7a1ba1084db763ec7bf4a3f2961254e198e275d143f9b22"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-relay-v0.12.3-x86_64-apple-darwin"
        sha256 "46e6935ee998525a4d222a0a782d03cfcbcab88d2d1dc3dfb538f0dc80afdc88"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-v0.12.3-aarch64-unknown-linux-musl"
      sha256 "f65b0fef27f55b4d1b9d9edfc6b2a6feccb0d8da34556368738dbb7f0cc4fa8f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-relay-v0.12.3-aarch64-unknown-linux-musl"
        sha256 "dd5b323212fb9d48543126da74bd0bc124c07565d0bc9e5a749e72af0641294a"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-v0.12.3-x86_64-unknown-linux-musl"
      sha256 "7c4db0d95ebc46f7918a59420badb11fd175896e2a582351cf78536baa392ead"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.3/silver-relay-v0.12.3-x86_64-unknown-linux-musl"
        sha256 "bc0ae5530096ee28828a7b5386cfcace36ded7edb3c8ee81f07439af390ac31a"
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
