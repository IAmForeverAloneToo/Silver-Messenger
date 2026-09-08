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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-v0.12.4-aarch64-apple-darwin"
      sha256 "57ec2fc901be2c305a78bc7ec24489cac81f10f07a12b241d21a3424810e68fc"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-relay-v0.12.4-aarch64-apple-darwin"
        sha256 "279f9ca778046314d54fc340225e93fcffdee5b51410869f2fa8ca830978bc90"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-v0.12.4-x86_64-apple-darwin"
      sha256 "f31c566f26c46f7f36465a18c035f5fc49ceb3015c52b76dacc6a6fb4c9af832"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-relay-v0.12.4-x86_64-apple-darwin"
        sha256 "1701dc3f355901f3c2833f9632a0d7ddb0a384f63295ff28cb3fd6ff090676b9"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-v0.12.4-aarch64-unknown-linux-musl"
      sha256 "ec3f469b45955d2a0427191b2ce7fc902a6b81745add73f34d1fcad03f593b1e"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-relay-v0.12.4-aarch64-unknown-linux-musl"
        sha256 "4ea30a795f17d77eda66895aa43dcfeeec85641171f3eefde4a6e4712770d277"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-v0.12.4-x86_64-unknown-linux-musl"
      sha256 "b957e1b7c5579e36823c8753ce61932afaa8640d094b3a5db0da671cc3cc47a6"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.4/silver-relay-v0.12.4-x86_64-unknown-linux-musl"
        sha256 "576a44cb5ad4573fcce832d5f291823654187eef8ee899ff7a64fb4fdfdfe6a1"
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
