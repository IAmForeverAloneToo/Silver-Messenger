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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-v0.24.1-aarch64-apple-darwin"
      sha256 "aa63f950b94080b16ce8e5e5e45062c200f12c03bb5c182b00cedd98ff58538e"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-relay-v0.24.1-aarch64-apple-darwin"
        sha256 "177beb1b2bfdb89c35fdc29fec5da96f7985acb40360e7aec396ba1cd3f436f0"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-v0.24.1-x86_64-apple-darwin"
      sha256 "a629ec298cb8b09deddba4724b50806e52db25cf84ebf458e4668524f0441d9b"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-relay-v0.24.1-x86_64-apple-darwin"
        sha256 "7ceef62564d0cec5a3882fe5c43c123df2a661847642f503d7325b095404818e"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-v0.24.1-aarch64-unknown-linux-musl"
      sha256 "6975ad435acf4d29c9fb2d38342ac2dad889d3625c9f40f550921f6b6b8b9b58"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-relay-v0.24.1-aarch64-unknown-linux-musl"
        sha256 "f886e3c4c8a9e178bdf6cfc718408e0a89e03d7b65ee6221df9bc8b6e48fa23b"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-v0.24.1-x86_64-unknown-linux-musl"
      sha256 "99e8c73239c9abcee9a35f40faaa1a12963355253fb7730153f754b7b3e2d5d6"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.1/silver-relay-v0.24.1-x86_64-unknown-linux-musl"
        sha256 "c2cb18b7fb2bfcc42de4a76f99dd39a8a199f8787f21525dd4f0aa005ccf1662"
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
