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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.9.0/silver-messenger-v0.9.0-aarch64-apple-darwin.tar.gz"
      sha256 "5e4114021a27ef161d20b6eaa8d1b41aade85ec8115d957d3431eac1a91f448d"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.9.0/silver-messenger-v0.9.0-x86_64-apple-darwin.tar.gz"
      sha256 "9ea14b19ca082224290b612a7973f2e2f5e3ca81a68d9561097a415c028cb3c8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.9.0/silver-messenger-v0.9.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "d71d0cae5a7116460cadf520ec7b6468e41085356560be1c22a3102ffdec96ca"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.9.0/silver-messenger-v0.9.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "091951b1defb2d6eef155ad3417b8fcd9ebc5b31ee9083fd74a80f8a3ec100a3"
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
