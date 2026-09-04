# Operating a relay

What running a Silver Messenger relay involves after the install: what
the machine needs, what the limits do, what the log and the metrics say,
how to administer it day to day, how to keep backups, and what to do when
the host is compromised. Installing is in the README ("Deploying a
relay"), moving between versions in [UPGRADING.md](UPGRADING.md), what the
relay can and cannot see in [THREAT_MODEL.md](THREAT_MODEL.md).

## What you are running

The relay stores and forwards. It holds each identity's signed key bundle
and prekeys (all public), the queued envelopes for each recipient
(ciphertext the relay cannot open), encrypted file chunks on deposit, the
bans and settings an administrator made, and counters. It sees who a
message is for, when it arrived and roughly how big it is, and the
address of the connection that brought it; it cannot read a message,
forge one, or impersonate a user. The threat model spells this out.

So the operator's duties are the ordinary ones of a server that holds
private metadata: keep it up, keep its key and its database to itself,
keep it updated, and know what to do when something goes wrong.

## A first deployment, step by step

1. **A host.** Any Linux with systemd; 1 vCPU, 1 GB of memory and 10 GB
   of disk serve hundreds of users (see "Sizing"). Or a machine with
   Docker for the container image.
2. **A name.** An A or AAAA record for the relay, pointing at the host.
   The relay obtains its certificate under that name.
3. **Ports.** 443 open to the world; nothing else. SSH from where you
   administer, and no other service on the host if you can help it.
4. **Install.** The README's installer (`deploy/install.sh`, or the
   "Deploy relay" workflow) with `SILVER_DOMAIN` and `SILVER_EMAIL`, or
   `deploy/compose.yml`. The installer sets up the service, the admin
   socket, the daily backup timer and the firewall.
5. **Decide who may register.** A relay for a known group of people
   should require an invite token: `silver-relay admin invite-set` prints
   a random one, which people pass to the client once (`silver --invite`,
   or an invite link). Without one, anyone who finds the relay can make
   an identity on it.
6. **Check it.** `silver-relay admin status`, `journalctl -u silver-relay
   -n 50`, and a client: `silver --relay wss://relay.example.org/ws`.
7. **Publish the pin.** `openssl s_client -connect relay.example.org:443
   </dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform
   der | openssl dgst -sha256` gives the key's pin; put it where your
   users can find it, so they can `silver --pin` it and stop trusting
   every certificate authority on their machine (README, "Pinning the
   relay's key").
8. **Backups.** The timer takes one every night into
   `/var/lib/silver-relay/backups`. Copy them off the host, encrypted;
   restore one into a scratch directory once to see that it works
   ("Backups" below).
9. **Monitoring.** At least: the certificate's expiry and the relay
   answering. `SILVER_RELAY_METRICS_LISTEN` and `deploy/alerts.yml` give
   Prometheus everything; without Prometheus, an uptime check on
   `https://relay.example.org/healthz` and a look at the journal's hourly
   line.
10. **Updates.** Subscribe to the releases
    (`https://github.com/IAmForeverAloneToo/Silver-Messenger/releases.atom`)
    and follow UPGRADING.md when one comes; a relay accepts older clients,
    so a relay upgrade never strands anyone.

## Sizing

**Processor.** The relay does no cryptography on messages beyond a
signature check at login; its work per message is a database write and a
WebSocket frame. The costliest thing it does is a TLS handshake. One vCPU
serves hundreds of users with room to spare; watch the connection and
message counts in the metrics before adding more.

**Memory.** The process is small at rest (tens of megabytes) and grows
with open connections (a few kilobytes each plus the frames in flight)
and with the database engine's cache. A relay under its default cap of
4096 connections fits in a gigabyte.

**Disk.** The database holds queued messages until they are acknowledged
or expire (30 days by default; at most 1000 messages or 32 MiB per
recipient), encrypted files on deposit (1 GiB in total by default,
expiring with the messages), and a few kilobytes per identity. Plan for
the file cap plus the mailbox caps of your active users, and as much
again for backups on the same disk. The database file does not shrink
when entries are deleted; the space is reused.

**Network.** Messages are small; files are the bulk, and each is
transferred twice (in and out). Nothing here needs more than the
smallest hosting plan's bandwidth.

**File descriptors.** One per connection plus a few; the unit allows
65536. Raise `LimitNOFILE` with `--max-connections`.

## The limits

Every limit is a flag on `silver-relay` and an environment variable in
`/etc/silver-relay/relay.env`; `silver-relay --help` lists them all and
shows the variable next to each flag (most are the flag's name in
capitals with `SILVER_RELAY_` in front: `--max-connections` is
`SILVER_RELAY_MAX_CONNECTIONS`). The ones worth knowing:

| Limit | Default | What it bounds | Change it when |
| --- | --- | --- | --- |
| `--invite-token` | none | Who may register a new identity | You want a closed relay; `admin invite-set` changes it without a restart |
| `--max-identities` | 100000 | Identities the relay keeps | A small relay: set it to the number of people you expect, with room |
| `--registrations-per-hour` | 20 per address | New identities from one address | A shared address (a NAT, a Tor exit) registers many people at once |
| `--connections-per-address` | 16 | Open connections from one address | Many users behind one NAT (raise), or abuse (lower) |
| `--max-connections` | 4096 | Open connections in total | The host is bigger or smaller than that |
| `--idle-timeout-secs` | 120 | A silent connection is closed after this | Clients ping every 30 seconds; only if a network needs longer |
| `--sends-per-minute` | 60 | Messages one authenticated connection may submit | Bots or bulk senders |
| `--anonymous-sends-per-minute` | 30 | Messages a connection that never logs in may submit; 0 turns anonymous submission off | See "Abuse": turning it off costs senders their anonymity towards the relay |
| `--lookups-per-minute` | 30 | Key lookups per connection | Rarely |
| `--one-time-prekeys-per-user-per-hour` | 30 | One-time prekeys handed out for one user | Rarely; beyond it, lookups get the bundle without one |
| `--max-mailbox-messages`, `--max-mailbox-mib` | 1000, 32 | A recipient's queue | Users who are offline for long stretches |
| `--message-ttl-days` | 30 | How long an unacknowledged message is kept | A stricter retention policy (shorter), or long-absent users (longer) |
| `--max-blob-mib` | 16 | Largest file; 0 turns file transfer off | Your users share bigger files, or none |
| `--blob-storage-mib` | 1024 | Files on deposit in total | Disk |
| `--blob-mib-per-address-per-hour` | 256 | Uploads from one address | Abuse, or a shared address |
| `--trusted-proxy` | loopback | Whose `X-Forwarded-For` names the client | A TLS front on another host |
| `--require-bound-auth` | off | Refuse the login of clients before 0.6.0 | Once everyone has updated |

A limit that says no is counted (`silver_relay_refused_total` by reason in
the metrics, and the hourly line in the log), so you see when one bites
before anyone complains.

## The log

The relay logs to the journal (`journalctl -u silver-relay`). At the
default level (`RUST_LOG=info`) it writes: its configuration at start;
one line when a client logs in and one when it disconnects, naming the
client by a pseudonym; one line an hour with the counters (connections,
addresses, refusals by kind, failed logins, idle closes); certificate
events; and warnings about abuse. It does not write message ids,
recipients or sizes, and it does not write user ids: the pseudonym is
twelve hex digits of a salted hash, and the salt is new at every start,
so the journal is not a record of who used the relay and a pseudonym
from yesterday's log names nobody today. `--log-ids` writes the ids as
they are, for a relay whose operator wants that record.

A client's address appears at this level in one place: the warning when
it fails to log in twenty times within an hour. Debug level
(`RUST_LOG=debug`) is for finding a bug and writes frame-level detail;
do not run it in production.

Retention is journald's. What the journal still records is when each
pseudonym was connected, so keep it short. To keep a week and no more
than 200 MB, in `/etc/systemd/journald.conf`:

```
[Journal]
SystemMaxUse=200M
MaxRetentionSec=1week
```

then `systemctl restart systemd-journald`. `journalctl --vacuum-time=7d`
trims what is already there. For a log collector, `SILVER_RELAY_LOG_FORMAT=json`
writes one JSON object per line with the same fields.

## Monitoring

`SILVER_RELAY_METRICS_LISTEN=127.0.0.1:9107` serves Prometheus metrics at
`/metrics` on that address and nothing else. Keep it on loopback or a
private network: the numbers describe how the relay is used. What they
say:

| Metric | Meaning |
| --- | --- |
| `silver_relay_info` | Version, as a label |
| `silver_relay_uptime_seconds` | Since the last start |
| `silver_relay_connections_open`, `silver_relay_connections_limit` | Open WebSocket connections against the cap |
| `silver_relay_connected_addresses` | Distinct client addresses connected |
| `silver_relay_refused_total{reason}` | Refusals by kind: `connection`, `registration`, `upload`, `login` |
| `silver_relay_idle_closed_total` | Connections closed for silence |
| `silver_relay_anonymous_submissions_total` | Messages submitted on connections that never logged in |
| `silver_relay_auth_failures_total`, `silver_relay_auth_failure_addresses`, `silver_relay_auth_failures_max_per_address` | Failed logins in total, addresses that failed in the last hour, the most from one of them (the address itself is in the log, never here) |
| `silver_relay_identities`, `silver_relay_mailboxes`, `silver_relay_messages_queued`, `silver_relay_mailbox_bytes` | What the store holds |
| `silver_relay_blobs`, `silver_relay_blob_bytes`, `silver_relay_blob_bytes_limit` | Files on deposit against the cap |
| `silver_relay_certificate_expiry_seconds`, `silver_relay_acme_failures_total` | When the served certificate expires (0 while there is none), and renewals that failed |

`deploy/alerts.yml` carries the rules worth waking up for: the relay
down, a certificate that will not renew, a flood of failed logins or
refused registrations, a nearly full file store, connections near the
cap. Without Prometheus, an uptime monitor on `https://<name>/healthz`
(it answers `ok` while the relay runs) and a weekly look at `silver-relay
admin status` cover the essentials; the certificate's expiry is in that
output.

## Day to day

Everything an administrator does goes through `silver-relay admin`, over
the Unix socket the installer configured (`/run/silver-relay/admin.sock`;
root or the `silver` user can use it, nobody on the network can).

**Who is on the relay.** `admin identities` lists every identity under
its log pseudonym with its mailbox size, its prekey deposit, when it last
published keys, and whether it is online or banned. The pseudonyms are
the ones in the current log, and they change at every restart; a name
you want to keep across restarts is the full id, which you get from the
person, not from the relay (`--log-ids` makes the relay show ids
instead).

**Registration.** `admin invite-set [token]` requires a token from new
identities from now on (a random one is printed when none is given),
`admin invite-off` opens registration, `admin invite-reset` returns to
what `relay.env` says. All three take effect at once and survive
restarts. Existing identities are never affected.

**Abuse.** `admin ban <address>` refuses an address at the door and
`admin ban <pseudonym or id>` refuses an identity at login, both kept
across restarts and listed by `admin bans`; `admin unban` lifts one.
`admin evict <who>` deletes an identity's bundle, prekeys and queued
messages and disconnects it; the identity can register again unless it
is also banned. A ban on an address hits everyone behind it.

The limits handle most abuse on their own: the counters and the hourly
line tell you when one is biting, and the warning about failed logins
names the address. Anonymous submission (a client sends on a connection
that never logs in, so the relay cannot tell who sent what) is what keeps
the relay from learning the sender of every message; turning it off
(`--anonymous-sends-per-minute 0`) makes senders identifiable to the
relay and is a trade against your users' privacy, not a free hardening.

## Backups

The installer enables `silver-relay-backup.timer`, which runs
`silver-relay backup` every night (at a random minute within an hour of
midnight) into `/var/lib/silver-relay/backups/relay-<date>.backup`,
readable by the relay's user only, and deletes files older than two
weeks. `systemctl list-timers silver-relay-backup.timer` shows the next
run; `systemctl start silver-relay-backup.service` takes one now. A
backup is one consistent snapshot of the whole database, checked against
its own checksum before it gets its name.

A backup on the same disk as the database is not a backup of the disk.
Copy the files off the host, encrypted: for example

```
age -r age1... -o relay-2026-09-04.backup.age /var/lib/silver-relay/backups/relay-2026-09-04T0213.backup
```

or let restic, borg or the tool you already use pick up the directory. A
backup holds what the database holds (ciphertext, public keys, bans) and
must be kept as private.

Restoring is in UPGRADING.md ("Rolling back"). Do it once into a scratch
directory before you need it:

```
silver-relay restore /var/lib/silver-relay/backups/relay-2026-09-04T0213.backup --data-dir /tmp/check
rm -r /tmp/check
```

The certificate's key and the ACME account live in `acme/` under the
data directory and are not in the backup; copy the directory along with
the backups if the relay terminates TLS itself, or accept that a rebuilt
relay presents a new key and pinned clients need the new pin.

## Updates

New versions are announced on the releases page and its feed. Read the
version's notes in [UPGRADING.md](UPGRADING.md) and CHANGELOG.md, take a
backup, run the installer again (or pull the new image), and check
`admin status` and the journal. The relay accepts older clients, so
upgrade the relay first and let users update at their pace; a client
that is older than the relay simply lacks the newer features.

## After a compromise of the host

If someone else has had root on the host, or the disk, assume they have:

* **the certificate's private key** (`acme/key.pem`) and the ACME
  account. With the key they can impersonate the relay to clients whose
  traffic they can redirect, and so see the metadata the relay sees and
  refuse service; they cannot read messages, whose keys never touch the
  relay, and a login they collect from a current client is bound to
  your relay's name and worthless elsewhere;
* **the database**: who talks to whom (by recipient), when, how much,
  and the public keys. Nothing in it decrypts a message. They can also
  have altered it: withheld or dropped queued messages, served stale
  bundles. They cannot forge a bundle or a message, since users sign
  both;
* **the journal**: the same metadata, by pseudonym, for as long as it
  was kept.

Then:

1. Take the host off the network. Do not try to clean it.
2. Build a new host from a fresh image and install the relay from a
   release you verified (README, "Verifying a release").
3. Restore the last backup you trust into it. If you suspect the
   database was altered, a backup from before the compromise loses the
   messages queued since, which is the safer loss; a database from the
   compromised host can be restored too, since it holds nothing the
   attacker did not already have and nothing a user's client will
   trust unsigned.
4. Give the relay a new key: do not copy `acme/` over. Clients that
   pinned the old key stop connecting until they are given the new pin,
   which is the point; publish it.
5. Rotate everything else the host knew: the invite token (`admin
   invite-set`), the host's SSH keys and passwords, any hosting API
   tokens, the Prometheus credentials if it scraped through
   authentication.
6. Tell your users what happened, what the attacker could see (who
   wrote to whom and when, sizes, addresses, for the period in
   question) and could not (any message content), and give them the new
   pin. If they use Tor to reach the relay, the addresses were exit
   nodes and tell nobody anything.
7. Look at the old host's journal and the backups' dates to bound the
   period, and keep the old disk for that, unplugged.

## Shutting a relay down

Tell your users first: identities live on their clients, not on the
relay, and they can move to another relay with them, but messages
queued on this relay for people who are offline are lost with it. Take
a final backup if you may come back, stop the service, and delete the
data directory and the backups; the certificate expires on its own, and
there is nothing to revoke unless the key was compromised. Remove the
DNS record so clients fail cleanly rather than wait on a dead name.
