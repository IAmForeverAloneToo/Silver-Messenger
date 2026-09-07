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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.11.0/silver-messenger-v0.11.0-aarch64-apple-darwin.tar.gz"
      sha256 "81b55fbef4324b7eb0033b1f538d6a85f370801015ba238de5d50119091c2123"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.11.0/silver-messenger-v0.11.0-x86_64-apple-darwin.tar.gz"
      sha256 "7b585a43d5aade8d6e10790b120d3c30bb8fe73a696296c43576ddb4d60adfba"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.11.0/silver-messenger-v0.11.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "14f0df908553b9cbd9f8008b57ad7200cc28204663cc26fe2524456287ae1617"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.11.0/silver-messenger-v0.11.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "efa1485a2f6e17bd747c02f47d3c79f1a04a09f45c5b838bac62f59174dd3625"
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
