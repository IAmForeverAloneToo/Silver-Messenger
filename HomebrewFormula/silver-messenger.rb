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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-v0.19.0-aarch64-apple-darwin"
      sha256 "093da7df1be9fb4d6f19d3979e2cd8e6b8de45e932df021687792c067b2dcf28"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-relay-v0.19.0-aarch64-apple-darwin"
        sha256 "f87941c70d3cac01fc8c0e669a0a904c34475fedc916acf4efab422e1a49adcb"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-v0.19.0-x86_64-apple-darwin"
      sha256 "f4ac53d483ca4130676890c145981ec86a03ec09a191db490b57806bbf9dcc02"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-relay-v0.19.0-x86_64-apple-darwin"
        sha256 "0cbfc689774272bdceece3b9c023cc298a257d554491416f493a9ff025931c2c"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-v0.19.0-aarch64-unknown-linux-musl"
      sha256 "240e9b3b0db154f9bde95f1295895dbcf01adbc218540ba19cb3d70fb6678d96"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-relay-v0.19.0-aarch64-unknown-linux-musl"
        sha256 "cb84e1f59fe8ce4b4ac577eeb17249b2044b32aab83638807fec80f8544afc6d"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-v0.19.0-x86_64-unknown-linux-musl"
      sha256 "72f7cda5ad263ccda333f6a3ab27795a1bcf47361db0b487a07545fa0567b874"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.19.0/silver-relay-v0.19.0-x86_64-unknown-linux-musl"
        sha256 "25228acdadea58b689c89b3779e9d238c1c91b3407d69ef8863fbe4ff0570714"
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
