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
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-v0.12.5-aarch64-apple-darwin"
      sha256 "624c63f0821ba455887a4fab371506af45ebca67d792f35256765042aa366cb4"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-relay-v0.12.5-aarch64-apple-darwin"
        sha256 "a32392d05cdb838a1c4c4b5a5a5450af9cad1ef29632b162a963901e960dd7ea"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-v0.12.5-x86_64-apple-darwin"
      sha256 "20dc81f417909d5da93d14e6a9500d424b1da1e832b0398076178f5ade2336c7"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-relay-v0.12.5-x86_64-apple-darwin"
        sha256 "9a6bb0437febab05b274d24e3f08b319fb05d6f6e2217fae461b44622cea7125"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-v0.12.5-aarch64-unknown-linux-musl"
      sha256 "d26034bec9fc84849a87cbd76e1994ae18e8491529c41a28c5707ef153a00727"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-relay-v0.12.5-aarch64-unknown-linux-musl"
        sha256 "6a52569b55cfd3c512d7e25955161b1e3b439218db0f0ad17fb399dd2489aef4"
      end
    end
    on_intel do
      url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-v0.12.5-x86_64-unknown-linux-musl"
      sha256 "6175daeb58281f3685b8121823a6d68fb450e13071c4e3c4c8a958298776866e"
      resource "relay" do
        url "https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v0.12.5/silver-relay-v0.12.5-x86_64-unknown-linux-musl"
        sha256 "eb5dad2dd5ab21975e23119abecdc20f833ee7beea9b700ff68a5cf2a883cf88"
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
