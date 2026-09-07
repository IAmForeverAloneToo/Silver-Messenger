#!/usr/bin/env bash
# Make the release signing key, once, on a machine you hold.
#
# What a release signature is for: the client checks an update against it
# before it replaces itself (docs/design/updates.md), and a person checks
# a download against it (README, "Verifying a release"). Both check
# against `minisign.pub` in this repository, so the key made here is the
# one everything trusts.
#
#   packaging/new-signing-key.sh              # the workflow signs each release
#   packaging/new-signing-key.sh --by-hand    # you sign each release yourself
#
# The two differ only in where the private half lives, and clients cannot
# tell the resulting signatures apart, so starting with the first and
# moving to the second later costs nothing but the key.
#
#   default    An unencrypted key, for GitHub's secret store. The workflow
#              signs every release by itself and you do nothing further.
#              No password: a password kept in the same secret store as
#              the key it protects is not protecting anything.
#
#   --by-hand  A password-protected key that never leaves this computer.
#              You sign each release yourself, with the one command
#              printed at the end. Stronger -- a compromise of the
#              repository cannot sign anything -- at a step per release.
#
# Run it on your own computer: not on a server, not in CI, and not
# anywhere a transcript is kept. The private half must exist in one place
# only, and nobody helping with this repository ever needs to see it. A
# key that has passed through a chat, an issue or a paste site is spent.
set -euo pipefail

by_hand=0
case "${1:-}" in
  --by-hand) by_hand=1 ;;
  "") ;;
  *) echo "usage: $0 [--by-hand]" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

if ! command -v minisign >/dev/null 2>&1; then
  cat >&2 <<'EOF'
minisign is not installed. One of:

  Debian/Ubuntu   sudo apt install minisign
  Fedora/RHEL     sudo dnf install minisign
  macOS           brew install minisign
  Arch            sudo pacman -S minisign
  Windows         winget install jedisct1.minisign

then run this again.
EOF
  exit 1
fi

if [ -f "$repo/minisign.pub" ]; then
  {
    echo "This repository already publishes a signing key:"
    echo
    sed 's/^/  /' "$repo/minisign.pub"
    cat <<'EOF'

Replacing it makes every older release unverifiable against the new key,
and every client with the old one compiled in refuses the next update
until it is replaced by hand. If the old key is lost or exposed that is
the price and it is worth paying: move minisign.pub aside and run this
again. Otherwise stop here.
EOF
  } >&2
  exit 1
fi

dir="${SILVER_KEY_DIR:-$HOME/.silver-signing}"
mkdir -p "$dir"
chmod 700 "$dir"
key="$dir/minisign.key"
pub="$dir/minisign.pub"

if [ -e "$key" ]; then
  echo "$key already exists; move it aside first, or set SILVER_KEY_DIR." >&2
  exit 1
fi

umask 077
if [ "$by_hand" -eq 1 ]; then
  echo "Making a password-protected key in $dir."
  echo "You will be asked for a password; you type it each time you sign."
  echo
  minisign -G -s "$key" -p "$pub"
else
  echo "Making a key in $dir, without a password: it is going into"
  echo "GitHub's secret store, where a password would sit beside it."
  echo
  minisign -G -W -s "$key" -p "$pub"
fi

cp "$pub" "$repo/minisign.pub"

# Prove the halves match before telling anyone to rely on them.
check="$(mktemp)"
trap 'rm -f "$check" "$check.minisig"' EXIT
printf 'signing key self-test\n' > "$check"
if [ "$by_hand" -eq 1 ]; then
  echo
  echo "Signing a test file, to check the key works. Your password again:"
  minisign -S -s "$key" -m "$check" >/dev/null
else
  minisign -S -W -s "$key" -m "$check" >/dev/null
fi
minisign -V -p "$repo/minisign.pub" -m "$check" >/dev/null
echo
echo "Key checked: it signs, and minisign.pub verifies what it signed."

echo
echo "The public half is now at minisign.pub in this checkout. Commit it:"
echo
echo "    git add minisign.pub && git commit -m 'The release signing key'"
echo
echo "It is public by design: it is what verifies, never what signs."
echo

if [ "$by_hand" -eq 1 ]; then
  cat <<EOF
The private half stays at $key and goes nowhere else. Back it up as you
would a password manager's export. Do not put it in the repository's
secrets: the point of --by-hand is that the repository cannot sign.

After each release, download that release's SHA256SUMS and run:

    minisign -Sm SHA256SUMS -t 'Silver Messenger v<version>'

then attach the SHA256SUMS.minisig it writes to the release. The release
workflow will say, in its log, that it published an unsigned SHA256SUMS
and is waiting for yours.
EOF
else
  cat <<EOF
The private half is at $key. Back it up as you would a password manager's
export, then put it into this repository's secrets:

    https://github.com/IAmForeverAloneToo/Silver-Messanger/settings/secrets/actions

    New repository secret
      Name    MINISIGN_SECRET_KEY
      Value   the whole contents of $key, both lines

Paste it into that page and nowhere else. There is no second secret: the
key has no password.

From the next release onwards the workflow signs SHA256SUMS with it and
publishes SHA256SUMS.minisig beside it, checking its own signature against
minisign.pub first, so a mismatched secret fails the release rather than
shipping something nobody can verify.

To move the key offline later, delete the secret and sign by hand:

    minisign -Sm SHA256SUMS -t 'Silver Messenger v<version>'

Clients cannot tell the two apart, so nothing else changes.
EOF
fi
