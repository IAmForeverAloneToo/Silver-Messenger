#!/usr/bin/env bash
# Build the Debian package of Silver Messenger from prebuilt binaries
# (docs/design/distribution.md, section 4): both executables, the relay's
# unit with its path rewritten (installed, not enabled), the documents
# and the copyright file. Reproducible: every file's time is the commit's
# (SOURCE_DATE_EPOCH) and the archive is built with a fixed owner and
# compression, so the same input gives the same package.
#
#   packaging/deb/build.sh <version> <amd64|arm64> <dir with the binaries> <out dir>
#
# <version> is the release tag with or without its v. <dir> holds
# `silver` and `silver-relay`, and README.md and CHANGELOG.md when they
# are wanted from there (a release archive has them; for a checkout the
# repository's copies are used).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 <version> <amd64|arm64> <dir with the binaries> <out dir>" >&2
  exit 2
fi
version="${1#v}"
arch="$2"
bindir="$3"
outdir="$4"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
case "$arch" in
  amd64 | arm64) ;;
  *) echo "the architecture must be amd64 or arm64, not $arch" >&2; exit 2 ;;
esac
for bin in silver silver-relay; do
  if [ ! -x "$bindir/$bin" ]; then
    echo "no executable $bindir/$bin" >&2
    exit 2
  fi
done
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH="$epoch"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/silver-messenger"
doc="$root/usr/share/doc/silver-messenger"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/lib/systemd/system" "$doc"

install -m 0755 "$bindir/silver" "$root/usr/bin/silver"
install -m 0755 "$bindir/silver-relay" "$root/usr/bin/silver-relay"
sed 's|/usr/local/bin/silver-relay|/usr/bin/silver-relay|' \
  "$repo/deploy/silver-relay.service" > "$root/lib/systemd/system/silver-relay.service"
chmod 0644 "$root/lib/systemd/system/silver-relay.service"
for name in README.md CHANGELOG.md; do
  src="$bindir/$name"
  [ -f "$src" ] || src="$repo/$name"
  install -m 0644 "$src" "$doc/$name"
done
install -m 0644 "$here/copyright" "$doc/copyright"
# The Debian changelog: one entry, the release; the project's own is
# CHANGELOG.md beside it.
maintainer="IAmForeverAloneToo <16734439+IAmForeverAloneToo@users.noreply.github.com>"
{
  printf 'silver-messenger (%s) unstable; urgency=medium\n\n' "$version"
  printf '  * Silver Messenger %s, as published on the releases page;\n' "$version"
  printf '    CHANGELOG.md beside this file says what changed.\n\n'
  printf ' -- %s  %s\n' "$maintainer" "$(date -u -R -d "@$epoch")"
} | gzip -9n > "$doc/changelog.gz"
chmod 0644 "$doc/changelog.gz"
# The binaries are static on purpose (the release's are musl builds that
# depend on nothing); lintian would otherwise count that an error.
mkdir -p "$root/usr/share/lintian/overrides"
cat > "$root/usr/share/lintian/overrides/silver-messenger" <<'EOF'
# Static binaries, as the release publishes them: nothing to depend on.
silver-messenger: statically-linked-binary *
EOF
chmod 0644 "$root/usr/share/lintian/overrides/silver-messenger"

# Installed-Size is in KiB of what lands on disk.
size="$(du -sk --apparent-size --exclude=DEBIAN "$root" | cut -f1)"
cat > "$root/DEBIAN/control" <<EOF
Package: silver-messenger
Version: $version
Section: net
Priority: optional
Architecture: $arch
Installed-Size: $size
Depends: adduser
Maintainer: $maintainer
Homepage: https://github.com/IAmForeverAloneToo/Silver-Messenger
Description: End-to-end encrypted messaging in your terminal
 The client (silver) and the relay (silver-relay) of Silver Messenger, as
 the release of the same version publishes them: static binaries that
 depend on nothing else on the system. The relay's systemd unit is
 installed and left disabled; the operator's guide in the repository
 (docs/OPERATING.md) says how to run a relay. Removing the package keeps
 the relay's data in /var/lib/silver-relay and the client's in each
 user's data directory.
EOF

cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
# The relay's system user, for the unit; nothing is started or enabled.
set -e
if [ "$1" = configure ]; then
  if ! getent passwd silver >/dev/null; then
    adduser --system --group --home /var/lib/silver-relay --no-create-home \
      --shell /usr/sbin/nologin silver >/dev/null
  fi
  if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
  fi
fi
EOF

cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
# A running relay is stopped before its binary goes, the Debian way.
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ] && command -v deb-systemd-invoke >/dev/null 2>&1; then
  deb-systemd-invoke stop silver-relay.service >/dev/null || true
fi
EOF

cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
# The data in /var/lib/silver-relay and the user stay, even on purge:
# they are the relay's mailboxes and keys, not the package's.
set -e
if [ -d /run/systemd/system ]; then
  systemctl --system daemon-reload >/dev/null || true
fi
if [ "$1" = purge ] && command -v deb-systemd-helper >/dev/null 2>&1; then
  deb-systemd-helper purge silver-relay.service >/dev/null || true
  deb-systemd-helper unmask silver-relay.service >/dev/null || true
fi
EOF
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

# One time for everything, the commit's, so a rebuild is the same bytes.
find "$root" -exec touch -h -d "@$epoch" {} +
mkdir -p "$outdir"
out="$outdir/silver-messenger_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out" >/dev/null
echo "$out"
