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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-v0.18.0-aarch64-apple-darwin"
      sha256 "215e3b9187bb1179e9ed4478b26775a9d1e2ce8ee227f0adca0bb313a652e37f"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-relay-v0.18.0-aarch64-apple-darwin"
        sha256 "f225affbf381763b0c5eb09614f698a1cc6cf354c82e4532f2e275fdd676017a"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-v0.18.0-x86_64-apple-darwin"
      sha256 "a28acef4a26d7c21e0400b2ca9a531c81dfd821b553f57fbead04005a6eccfab"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-relay-v0.18.0-x86_64-apple-darwin"
        sha256 "1294d0d227a118280572a5c866e92b24ec02fb590cc211623ad0a4c2857ee362"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-v0.18.0-aarch64-unknown-linux-musl"
      sha256 "a071c6bff2706f1d54bd2c557d483703eb13bb2026d9e3acfd76f86b7c97f785"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-relay-v0.18.0-aarch64-unknown-linux-musl"
        sha256 "ea0109912216aa39df1f614cc34d869fd852328c5304f4d1d76c63adf250c660"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-v0.18.0-x86_64-unknown-linux-musl"
      sha256 "5fbc931cd3828e0025e481c76e735343ff63fc12fe57728b17c9ee27286de4b0"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.18.0/silver-relay-v0.18.0-x86_64-unknown-linux-musl"
        sha256 "e72eb1c0220b4938571f1ef88af526017bb5c00b5431211995786cb6f3c4211d"
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
