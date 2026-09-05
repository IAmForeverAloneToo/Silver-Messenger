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

### 0.10.0

* **Nothing for the relay.** The schema stays at 3 and the backup format
  at 2; a 0.10.0 relay is a 0.9.0 relay with the same tables, and the
  everyday features (`PROTOCOL.md` section 4.7) are content inside the
  encrypted body the relay never sees. A 0.9.0 relay serves 0.10.0
  clients in full.
* **Clients.** The history files gain update lines (`read`, `edit`,
  `react`, `gone`) after the entries, and a file is rewritten in place
  (atomically, under the same encryption) when a message is removed for
  good by a deletion or a timer. `contacts.json` and `groups.json` gain
  each conversation's timer and `config.json` the encrypted-downloads
  option, all with defaults. Rolling a client back to 0.9.0 is safe: it
  skips the history lines it does not know, keeps them as they are, and
  shows the rest, with edits, reactions and timers unseen until 0.10.0
  runs again; a file received under `/files encrypt on` is ciphertext a
  0.9.0 client cannot open, so turn the option off and `/files decrypt`
  what you need before rolling back. Every 0.10.0 body advertises the
  `edits`, `reactions` and `timers` capabilities and every key package
  and leaf declares the `0xF003` leaf capability; a client refreshes a
  leaf that lacks it at once, so the first start after the upgrade makes
  one commit per active group.

### 0.9.0

* **The schema version moves to 3: key packages, the group sequencer
  and device revocations.** The relay keeps three more kinds of thing
  (`PROTOCOL.md` sections 13 and 14): each identity's MLS key packages
  on deposit, handed out like one-time prekeys; one epoch counter with
  one hash per group, which orders the group's commits and says nothing
  else about it; and each account's signed statements that a linked
  device is no longer its own, served and logged like identity
  revocations. All live in new tables; the migration creates them and
  touches nothing else. **Rolling back to 0.8.0 needs a restore**: 0.8.0
  refuses a version-3 database, as it would leave deposits to go stale,
  every group without its sequencer and every revoked device alive. Take
  the backup before the upgrade.
* **The backup format moves to 2.** A backup taken by 0.9.0 carries the
  new tables; 0.9.0 reads backups in format 1 (0.7.0 and 0.8.0) and 2,
  but 0.8.0 refuses a format-2 backup. So a rollback restores a backup
  taken *before* the upgrade; one taken after it is for 0.9.0 alone.
  Groups whose sequencer moved on since that backup are re-created by
  their members from where they stand (`PROTOCOL.md` section 13), and
  key packages deposited since are deposited again at the next login, so
  a restore costs nothing beyond what it always cost. A device revoked
  since that backup is revoked again by its owner's client, which keeps
  the statement.
* **Devices are served by default.** Every relay on 0.9.0 advertises the
  `devices` feature: it keeps the device list in an account's bundle and
  the certificate in a linked device's, checks the certificate on
  publish, hands a client the linked devices' bundles with the account's,
  takes `revoke_device` from the account and cuts the device off (its
  connection closed, its mailbox and deposits dropped, its logins refused,
  envelopes for it refused). A linked device is one more identity to the
  relay: it counts against `--max-identities`, against the address's
  registrations per hour when it registers, and needs the invite token
  where one is required. There is no switch and no new limit; an account
  lists at most eight devices, and the metrics `silver_relay_devices` and
  `silver_relay_device_revocations_total` say how many there are.
* **Groups are served by default.** Every relay on 0.9.0 advertises the
  `groups` feature; there is no switch, since a group is one small row and
  a key package deposit is a few tens of kilobytes per identity.
  `--max-groups` (default 100 000) caps the sequencer entries, idle ones
  go after 180 days, and the metrics `silver_relay_groups`,
  `silver_relay_key_packages`, `silver_relay_group_commits_total` and
  `silver_relay_group_rejections_total` say how it is going. Clients on
  0.8.0 see none of this and keep working.
* **Clients.** A 0.9.0 client puts MLS key packages on deposit as soon
  as it connects to a relay that serves groups, and advertises `groups`
  in its signed bundle capabilities, so contacts on 0.9.0 can add it to
  groups; against a 0.8.0 relay it does neither and `/group` says the
  relay is too old. Two new files appear in the data directory,
  `groups.json` and `groups.mls`, and group conversations go to
  `history/group-<id>.jsonl`, all encrypted like the rest when the
  directory is protected. Nothing changes for one-to-one messages, and a
  0.9.0 client is never sent a group message by a client that cannot
  see the capability. Rolling a client back to 0.8.0 leaves the three
  files where they are, untouched and unread; the groups in them are
  out of sync by the time 0.9.0 runs again, and their members re-add
  you.
* **Clients and devices.** A 0.9.0 client keeps a device state from its
  first start: `devices.json` in the data directory (the device list it
  publishes and the revocations it issued; on a linked device, the list
  as last synced) and, on a linked device, the account's certificate
  under `linked` in `identity.json`. It advertises `devices` in its
  bundle and in every body, seals each message once per device of the
  recipient's and of its own, and reads the copies its own devices send;
  nothing of this needs a change from the user, and a person with one
  device is what they were. Linking (`silver --link` on the new
  computer, `/devices link` on the old one, or the first-run prompt)
  needs the relay on 0.9.0; a client with devices on an older relay says
  so and works from the primary alone. A contact still on 0.8.0 keeps
  talking to a person with devices: it seals to the account as before,
  and the primary passes the message on. Rolling a client back to 0.8.0
  leaves `devices.json` unread; a primary then publishes a bundle
  without its device list, so contacts on 0.9.0 seal to it alone until
  it is back, while its linked devices keep their certificates and carry
  on when it returns. A linked device cannot be rolled back to 0.8.0
  (0.8.0 does not read the `linked` field and would start as an
  identity of its own); link it again from the primary once it is on
  0.9.0.

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
* **Clients.** Two clients on 0.8.0 speak protocol v4 to each other (the
  post-quantum ratchet, deniable messages) once each has published a
  bundle through a relay on 0.8.0, and v2 to older peers or through an
  older relay; `/session` says which. `/cover on` is new and off by
  default. Nothing in a client's data directory changes shape; a client
  from 0.7.0 reads and writes the same files, so a downgrade needs no
  restore.

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
