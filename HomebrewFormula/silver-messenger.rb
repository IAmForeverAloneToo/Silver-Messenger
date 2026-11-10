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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-v0.23.0-aarch64-apple-darwin"
      sha256 "260aa03a602aa7ffd75e5792c0cc0d5056c4a73c269396ea0bcbce6c4c5042be"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-relay-v0.23.0-aarch64-apple-darwin"
        sha256 "23ef1bf18dab11a8512b5c8577566e9b896ef088bd1821fe8ec417249899d2eb"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-v0.23.0-x86_64-apple-darwin"
      sha256 "8ad75773af9a7ac9557b9eabd001678637a2481e715cedc14ea21dcbae119907"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-relay-v0.23.0-x86_64-apple-darwin"
        sha256 "a6fa7eced01be573402dff18e2224d07b61daad853b586129ec51e14299c4dde"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-v0.23.0-aarch64-unknown-linux-musl"
      sha256 "7268a5ea6e2f284e770cdc90a779badfade85506c29b0029865c9bc623dd9c1b"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-relay-v0.23.0-aarch64-unknown-linux-musl"
        sha256 "045a197eebb919f18fec2bbb2ba6d7c6a188fcee17fbc7fe526df1e835eb857b"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-v0.23.0-x86_64-unknown-linux-musl"
      sha256 "1bf9257e4136076f4d9bce187f6cb61e8c51ef55ded86b9d340caa60b3d0cef3"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.23.0/silver-relay-v0.23.0-x86_64-unknown-linux-musl"
        sha256 "80b886d199ecf70afc50ed95b3bc089439b88b80f2aeda5afdfb6a4f0511272e"
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
