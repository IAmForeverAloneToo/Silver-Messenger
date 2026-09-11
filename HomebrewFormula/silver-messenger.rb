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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-v0.18.1-aarch64-apple-darwin"
      sha256 "4bf4722e4d521a4b13f4fc395b918f9b21f88841f88651379734ed7e36e70021"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-relay-v0.18.1-aarch64-apple-darwin"
        sha256 "38a8fe8c317c9dae75b11633974ebe6d4a2ed7eae7a6c7b324ffba9a48c76e61"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-v0.18.1-x86_64-apple-darwin"
      sha256 "48d388b3843dc5d9505f52fdc7a155d5022d5b5cc2f89d2b7e9e25a1f5a5a65b"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-relay-v0.18.1-x86_64-apple-darwin"
        sha256 "4cd2597a20847156c2a5d5b29de178832dc0a5942a9e882a7900b902af44e18d"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-v0.18.1-aarch64-unknown-linux-musl"
      sha256 "5b45106564d7e38782a824bd20ad01bc8fe146ae018dedb234f7b0cc4f081dd9"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-relay-v0.18.1-aarch64-unknown-linux-musl"
        sha256 "62b5fcb59385d9538ec65fe31dabb3cc314ebb84e59d18bd2740a618a394c403"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-v0.18.1-x86_64-unknown-linux-musl"
      sha256 "649ee27686930772b401561a48fcf07189828520606b9eb0c1363c366c355ec3"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.1/silver-relay-v0.18.1-x86_64-unknown-linux-musl"
        sha256 "03cfda044188601dd5b79f526dac31a1fb5e5c287ebcc303fc7f7a2fef8d0544"
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
