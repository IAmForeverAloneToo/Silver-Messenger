# Upgrading a relay

How to move a relay from one version to the next, roll it back, and move
it to another host, without losing a mailbox. The client updates itself
(`silver --update`); this is about the server side. The changes behind
each version are in [CHANGELOG.md](../CHANGELOG.md).

## Before every upgrade

Take a backup and note what you are running:

```
silver-relay backup /var/lib/silver-relay/before-0.8.0.backup
silver-relay admin status
```

`silver-relay backup` talks to the running relay through its admin socket
and writes one consistent snapshot of the whole database: identities and
their key bundles, prekeys, queued messages, files on deposit, bans, the
settings changed at runtime, and the counters. The file is written next to
its final name, checked against its own checksum, and only then given the
name, so a file called a backup is a whole one. With the relay stopped the
same command reads the data directory directly (`--data-dir`, which
defaults as it does for the relay).

A backup holds what the database holds: ciphertext, public keys, who is
banned. Keep it as private as the database (the file is created readable
by its owner only) and encrypt it before it leaves the host, with `age`,
`gpg` or the backup tool you already use.

## Upgrading

**With the installer** (a systemd service from `deploy/install.sh` or the
"Deploy relay" workflow): run the installer again, or the workflow with
`deploy`. It puts the new binary in place, installs the unit file that
came with it, keeps `/etc/silver-relay/relay.env` and adds any setting a
new version needs there, restarts the service and checks that it answers.
Then:

```
systemctl status silver-relay
journalctl -u silver-relay -n 50
silver-relay admin status
```

**In a container**: change the image tag in `deploy/compose.yml` (or pull
`latest`) and `docker compose -f deploy/compose.yml up -d`. The database
and the ACME account live on the `data` volume and carry over.

**By hand**: stop the service, replace the binary, install the new
`deploy/silver-relay.service` if it changed (the version notes below say
when), start the service.

Clients keep working across an upgrade: the relay accepts the wire
protocol of older clients, and a client that meets a newer relay uses what
it understands.

## The database and its version

The database is one file, `relay.redb` in the data directory
(`/var/lib/silver-relay` under systemd, `/var/lib/silver-relay` on the
container's volume, `./silver-relay-data` otherwise). From 0.7.0 on it
carries a schema version. At its first start a new relay brings an older
layout up to date in one transaction and says so in the log; a database
from before 0.7.0, which carries no version, is treated as version 0 and
stamped. A relay refuses to open a database stamped with a version newer
than it knows, and says which relay to run instead, rather than misread
it. `silver-relay admin status` shows the version in force.

A backup carries the version it was taken under. A newer relay restores an
older backup and brings it up to date on the way in; a backup taken by a
newer relay is refused with the same message.

## Rolling back

Stop the service, put the previous binary back, and if the previous
version refuses the database (the version notes say when that happens),
restore the backup you took before the upgrade:

```
systemctl stop silver-relay
silver-relay restore /var/lib/silver-relay/before-0.8.0.backup \
    --data-dir /var/lib/silver-relay --replace
systemctl start silver-relay
```

`restore` checks the file before it touches anything, moves the database
that was there to `relay.redb.before-restore-<time>` (delete it once the
relay runs as expected), loads the backup into a fresh database, and puts
the old one back if anything goes wrong on the way. It refuses to run
while the relay holds the database, and refuses an existing database
without `--replace`.

Messages that arrived between the backup and the rollback are lost with
the database they were in; their senders' clients keep them and resend
where the protocol allows, but a rollback is a loss to plan for, not a
routine step.

## Moving to another host

1. On the old host: `silver-relay backup relay.backup`, and copy the
   `acme/` directory from the data directory along with it if the relay
   terminates TLS itself. It holds the certificate's private key, which
   clients that pin the relay (`silver --pin`) expect to see again, and
   the ACME account. Copy `/etc/silver-relay/relay.env` too.
2. On the new host: install the same version with the installer (or the
   container), stop it, `silver-relay restore relay.backup --data-dir
   /var/lib/silver-relay --replace`, put `acme/` back in place owned by
   the relay's user, start it.
3. Point the DNS name at the new host. Clients reconnect on their own.

## Version notes

### 0.8.0

* **The schema version moves to 2: the key transparency log.** The relay
  now keeps an append-only, hash-chained log of every key bundle change
  and lifecycle statement it serves (`PROTOCOL.md` section 11), in two
  new tables. At its first start 0.8.0 enters one entry for every bundle,
  revocation and succession already in the database, in one transaction,
  and stamps version 2. **Rolling back to 0.7.0 needs a restore**: 0.7.0
  refuses a version-2 database rather than serve key changes it would not
  log, which clients on 0.8.0 would report as the relay hiding entries. So
  take the backup before the upgrade (as always), and restore it if you
  roll back.
* **A restore shortens the log.** A backup carries the log as it stood
  when it was taken. Restoring an older one puts the relay's log back to
  that point; every client that had verified further sees the log go
  backwards, says so ("the relay's key log went backwards"), and replays
  the log from the start. That is the expected consequence of a restore,
  not a fault, but it is one more reason to restore the newest backup you
  have, and to expect clients to mention it once afterwards.
* **Identity lifecycle statements** (revocations and successions) are
  accepted and served; a relay before 0.8.0 drops them, so clients behind
  one learn of a revoked or rotated key only from copies pushed inside
  messages.

### 0.7.0

* **TLS in the relay.** The relay can obtain and renew its own
  certificate (`--acme-domain`), so Caddy in front is optional. The
  installer keeps an existing Caddy setup unless told `SILVER_TLS=builtin`,
  which stops Caddy and moves the relay to port 443; port 80 is then no
  longer needed. A relay behind Caddy can stay behind Caddy.
* **The admin socket.** `SILVER_RELAY_ADMIN_SOCKET=/run/silver-relay/admin.sock`
  is added to `relay.env` by the installer, and the unit file gains a
  runtime directory and `AF_UNIX` among the allowed address families.
  Installing by hand: copy the new `deploy/silver-relay.service` and
  `systemctl daemon-reload`, or `silver-relay admin` and `silver-relay
  backup` cannot reach the relay.
* **The schema version.** The database is stamped with version 1 at the
  first start. Rolling back to 0.6.0 works without a restore: 0.6.0 does
  not look at the version and ignores the two tables 0.7.0 added (bans and
  runtime settings), so bans and a token set at runtime are simply not
  applied by it.
* **Metrics and JSON logs** are off unless `SILVER_RELAY_METRICS_LISTEN`
  and `SILVER_RELAY_LOG_FORMAT` say otherwise; nothing changes for an
  install that does not set them.
* **Releases carry Linux arm64 binaries and a container image.**
