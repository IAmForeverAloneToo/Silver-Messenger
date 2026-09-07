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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.1/silver-messenger-v0.12.1-aarch64-apple-darwin.tar.gz"
      sha256 "fa742cb932e2c61a6d5cd334a9ba1395a32362bbc97aed127452e5c033657bf2"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.1/silver-messenger-v0.12.1-x86_64-apple-darwin.tar.gz"
      sha256 "0fc51bd73472e9796f73eeb875f65d29cfcb79aa5a7e3894a7621268e8163e24"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.1/silver-messenger-v0.12.1-aarch64-unknown-linux-musl.tar.gz"
      sha256 "9ae36d3dd69ef17fd0cbb630480f7212bdad3927145eb38f5befa3e5581ccf5d"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.1/silver-messenger-v0.12.1-x86_64-unknown-linux-musl.tar.gz"
      sha256 "d4fd75a2ababa08296764a490b9a7e9ef4ff4029b58fd4b70efb7db88d507c09"
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
