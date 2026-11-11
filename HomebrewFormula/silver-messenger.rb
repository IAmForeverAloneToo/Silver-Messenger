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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-v0.24.0-aarch64-apple-darwin"
      sha256 "7f9b7731bde5292dd3aa9a7606d1f361fae4912b4a8a1d8ff79dbf64ce554ec7"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-relay-v0.24.0-aarch64-apple-darwin"
        sha256 "8fd3c60e1688284a4650001f98f82ec84d092e8bded8eee444c2d1e1ad65c9f5"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-v0.24.0-x86_64-apple-darwin"
      sha256 "51dc783625e11d5bb8f8b4f6a181110f3e89cfaed2380ffccb39146fc2940122"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-relay-v0.24.0-x86_64-apple-darwin"
        sha256 "22b4eb9b3a7624e31738a1b727cf990dfacf1346b6764f147b3d8a6b1352e1a8"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-v0.24.0-aarch64-unknown-linux-musl"
      sha256 "000b93c0c0478262ffb8de803a4c19f2cac71502578d1e2183cf33c180c7cd16"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-relay-v0.24.0-aarch64-unknown-linux-musl"
        sha256 "4daf452b5bc8490055ea6c33065968b96443c412f276e6cecac8492199b95bbf"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-v0.24.0-x86_64-unknown-linux-musl"
      sha256 "839cd9d08ea066892d663a94492a03f56e413058115946d860eeac864965b36a"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.24.0/silver-relay-v0.24.0-x86_64-unknown-linux-musl"
        sha256 "270afb8271114d16c78b088335fb138769ff81c34a3f69b8ea01724b03dae888"
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
