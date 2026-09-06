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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.1/silver-messenger-v0.10.1-aarch64-apple-darwin.tar.gz"
      sha256 "8aa479de4ed9274dd5ca3c53578417d8c95ff130601bb3e789177b5418faf66e"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.1/silver-messenger-v0.10.1-x86_64-apple-darwin.tar.gz"
      sha256 "1c83798b814e242f61bd07d584d78e4abfd1f82eefa45f7ee72f0fef1faae57d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.1/silver-messenger-v0.10.1-aarch64-unknown-linux-musl.tar.gz"
      sha256 "a6aeb42de15c612c449340b0f50ad65d18a5b5d6ed789cd37f4da43e2ce9a75c"
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.10.1/silver-messenger-v0.10.1-x86_64-unknown-linux-musl.tar.gz"
      sha256 "72833bdfcdfdb67701c3e38778fba948a61ab423bd6c7a5d845695eea5babc69"
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
