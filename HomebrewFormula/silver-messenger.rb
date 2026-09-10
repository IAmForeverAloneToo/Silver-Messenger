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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-v0.16.0-aarch64-apple-darwin"
      sha256 "dc71b7452bbf5b760ed6af6f0be6bfcb329e5d82c23fb58542ded75947295a24"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-relay-v0.16.0-aarch64-apple-darwin"
        sha256 "9171d6328dbb9ff5138ec85e818ef79819dce2efc4e5d522a2969d4cd4ac4c08"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-v0.16.0-x86_64-apple-darwin"
      sha256 "e06d59e24a952006590b0be2e8a5c15ab77ccee5ce936006b12a4c28eeff5566"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-relay-v0.16.0-x86_64-apple-darwin"
        sha256 "a1d8860bbac560c66b41db39c4d7f3e5ace74d47d72d5ca710657b58d0d1a250"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-v0.16.0-aarch64-unknown-linux-musl"
      sha256 "c8ada86ac00a515a8a02fa43e8de87b997994e1cd23771f7aa5bd379e7d8648c"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-relay-v0.16.0-aarch64-unknown-linux-musl"
        sha256 "49991c35c1f952de2f30af687e79dc2d311466ebef61447deaba2c2133310942"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-v0.16.0-x86_64-unknown-linux-musl"
      sha256 "5eadf41e7201a041587eaf54bbc11a596ac8576786ba0bdd5ef54f6849d7335e"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.16.0/silver-relay-v0.16.0-x86_64-unknown-linux-musl"
        sha256 "ecb5c30e79dad2b4a19cde0cb0974a4b2d0ecf639646a7457c0c1a1d17a4b309"
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
