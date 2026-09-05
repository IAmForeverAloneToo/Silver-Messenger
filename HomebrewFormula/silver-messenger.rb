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

  on_macos do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.0/silver-messenger-v0.10.0-aarch64-apple-darwin.tar.gz"
      sha256 "0f7bdc0884af21590c19ff7e5ea74a38c5139015081b503a87a8d6bde1f5d316"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.0/silver-messenger-v0.10.0-x86_64-apple-darwin.tar.gz"
      sha256 "38735d78e40c019ed3714a9ee3340cdacb46527aab9e7696767bddcb771d9af5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.0/silver-messenger-v0.10.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0fef095b6a552707e90537cf8ec34b3b12208ab71a967f5f9393e88c3c75a323"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.0/silver-messenger-v0.10.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "c02625734d15d3a5a6a23f05300a4a78b8a74ce5890392e2b831b294229e7fbb"
    end
  end

  def install
    bin.install "silver", "silver-relay"
    doc.install "README.md", "CHANGELOG.md"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/silver --version")
  end
end
