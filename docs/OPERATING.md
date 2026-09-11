# Operating a relay

What running a Silver Messenger relay involves: installing it, what the
machine needs, what the limits do, what the log and the metrics say,
how to administer it day to day, how to keep backups, and what to do
when the host is compromised. Moving between versions is in
[UPGRADING.md](UPGRADING.md), what the relay can and cannot see in
[THREAT_MODEL.md](THREAT_MODEL.md).

## What you are running

The relay stores and forwards. It holds each identity's signed key bundle
and prekeys (all public), the queued envelopes for each recipient
(ciphertext the relay cannot open), encrypted file chunks on deposit, the
bans and settings an administrator made, and counters. It sees who a
message is for, when it arrived and roughly how big it is, and the
address of the connection that brought it; it cannot read a message,
forge one, or impersonate a user. From 0.9.0 a person may run several
devices; each is one more identity to the relay, with its own mailbox
and keys, named in the person's bundle, and the relay keeps the signed
statement that ends one. The threat model spells this out.

So the operator's duties are the ordinary ones of a server that holds
private metadata: keep it up, keep its key and its database to itself,
keep it updated, and know what to do when something goes wrong.

## Installing

The relay is one static binary that needs one open TCP port. Under
systemd it runs as the unprivileged `silver` user with the hardened
unit `deploy/silver-relay.service`, reads its settings from
`/etc/silver-relay/relay.env`, keeps its database in
`/var/lib/silver-relay`, and logs to the journal (`journalctl -u
silver-relay`). Open the port in your provider's firewall as well: 443
with the built-in TLS, 7777 behind a TLS front of your own. Four ways
to put the binary there:

1. **The Debian package.** `apt install ./silver-messenger_<version>_<arch>.deb`
   (amd64 or arm64, from the release page) puts `silver` and
   `silver-relay` in `/usr/bin`, installs the unit without enabling it
   and makes the `silver` user. Then write `/etc/silver-relay/relay.env`
   (owner root, group `silver`, mode 640) with
   `SILVER_RELAY_LISTEN=0.0.0.0:443`, `SILVER_RELAY_ACME_DOMAIN`,
   `SILVER_RELAY_ACME_EMAIL` and
   `SILVER_RELAY_ADMIN_SOCKET=/run/silver-relay/admin.sock`, and
   `systemctl enable --now silver-relay`. The backup timer and the
   firewall are the installer's; with the package, set them up yourself
   ("Backups" below, and one port open).
2. **The release binary.** One file on the release page, covered by
   the signed `SHA256SUMS` ([RELEASES.md](RELEASES.md)), so you verify
   a signature and a checksum rather than read a script:

   ```sh
   v=<version>; t=x86_64-unknown-linux-musl          # the version on the releases page, and your target
   base=https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/download/v$v
   curl -fsSLO "$base/silver-relay-v$v-$t" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.minisig"
   minisign -Vm SHA256SUMS -p minisign.pub          # the list is the project's
   grep " silver-relay-v$v-$t\$" SHA256SUMS | sha256sum -c -
   sudo install -m755 "silver-relay-v$v-$t" /usr/local/bin/silver-relay
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin silver
   ```

   with `deploy/silver-relay.service` from the repository as the unit
   and `relay.env` written as for the package.
3. **The installer**, on a Debian/Ubuntu or Fedora server as root. It
   is in the repository and worth reading before running a script that
   installs software as root, which is why it is not offered as a pipe
   from a branch into a shell:

   ```sh
   curl -fsSLO https://github.com/IAmForeverAloneToo/Silver-Messenger/raw/main/deploy/install.sh
   less install.sh
   SILVER_DOMAIN=relay.example.org SILVER_EMAIL=you@example.org bash install.sh
   ```

   It installs build tools and Rust (`rustup-init` from the Rust
   project's own host, checked against the SHA-256 published next to
   it), clones the repository into `/opt/silver-messenger`, builds the
   relay on the server, and sets up the service, the admin socket, the
   daily backup timer and the firewall. Re-running it updates to the
   latest `main`. With a `silver-relay` binary and `silver-relay.service`
   placed next to it, it installs those instead and needs no compiler.
   Without `SILVER_DOMAIN` the relay listens on `127.0.0.1:7777`, since
   a public port with no TLS is not something to get by accident;
   `SILVER_ALLOW_PLAINTEXT=1` opens it to `0.0.0.0:7777` for a TLS front
   of your own.

   The same script runs from GitHub Actions, and works for a private
   repository: add the secrets `VPS_HOST` and `VPS_SSH_KEY` (a private
   key whose public half is in the server's `authorized_keys`;
   `VPS_USER` optionally, default `root`), put the server's own SSH host
   key in the repository *variable* `VPS_HOST_KEY` (what `ssh-keyscan
   <host>` prints, read once from somewhere you trust: the workflow will
   not fetch it itself, since that would trust whoever answers), set
   the variable `VPS_DOMAIN` for the built-in TLS, and run the **Deploy
   relay** workflow. It builds a static binary on the runner and
   installs it over SSH, so the server needs neither Rust nor access to
   the repository; the same workflow can show status and logs or
   restart the relay.
4. **The container image.** Each release publishes
   `ghcr.io/iamforeveralonetoo/silver-relay` for amd64 and arm64: the
   release's own static binary and a CA bundle on an empty base,
   running as an unprivileged user, with a provenance attestation
   ([RELEASES.md](RELEASES.md) says how to check it). `deploy/compose.yml`
   runs it with the built-in TLS on port 443, a read-only filesystem and
   no capabilities: `SILVER_DOMAIN=relay.example.org docker compose -f
   deploy/compose.yml up -d`, then `docker compose -f deploy/compose.yml
   exec relay silver-relay admin status` for administration and the
   same with `silver-relay backup /var/lib/silver-relay/relay.backup`
   for a backup on the data volume. `deploy/Dockerfile` builds the same
   image from source.

A relay for a few people can run with `SILVER_RELAY_EPHEMERAL=1` in
`relay.env` (`--ephemeral`), keeping mailboxes in memory only: a
restart loses queued messages, and the disk never holds any.

### TLS

Plain WebSocket on port 7777 is safe for message content, which is
end-to-end encrypted before it leaves the client, but shows recipient
ids and timing to the network path, and corporate or campus proxies
often block non-standard ports outright. Serve `wss://` on 443, one of
three ways:

* **Built in.** Point a hostname at the server and start the relay with
  `--listen 0.0.0.0:443 --acme-domain relay.example.org`
  (`SILVER_RELAY_ACME_DOMAIN` in `relay.env`; the installer does this
  from `SILVER_DOMAIN`). The relay obtains a Let's Encrypt certificate
  on its own, proving control of the name over TLS on that same port
  (TLS-ALPN-01, RFC 8737), so port 80 stays closed and nothing else is
  installed; renewals happen inside the relay, and the journal says
  when. Using Let's Encrypt means agreeing to its terms; `--acme-email`
  (`SILVER_EMAIL` for the installer) gives it an address for expiry
  warnings, `--acme-directory` points at another certificate authority
  (Let's Encrypt's staging directory, for a dry run) and `--acme-root`
  trusts a private one. The account, the key and the certificate live
  under `acme/` in the data directory, readable by the relay's user
  only. Clients then use `silver --relay wss://relay.example.org/ws`; a
  client trusts the operating system's certificate store and Mozilla's
  roots, so it works behind a TLS-inspecting proxy whose root is
  installed on the machine, and once it has reached a relay over
  `wss://` it refuses that host over plain `ws://`, so a mistyped or
  tampered URL cannot quietly drop the encryption.
* **A certificate from elsewhere.** `--tls-cert chain.pem --tls-key
  key.pem` serves it and re-reads the files whenever they change, so
  certbot's renewals take effect without a restart.
* **A TLS front.** Caddy, nginx or any reverse proxy can terminate TLS
  and forward the WebSocket to the relay on localhost. The relay then
  learns the client's address from `X-Forwarded-For`, trusted only from
  the addresses in `--trusted-proxy`, and must be told the name clients
  reach it by with `--host` (`SILVER_RELAY_HOST`), or their bound logins
  fail. The installer sets Caddy up this way with `SILVER_TLS=caddy`,
  and keeps a Caddy setup from before 0.7.0 unless `SILVER_TLS=builtin`
  tells it to switch, which stops Caddy and moves the relay to port 443.

### As an onion service

A relay can be reachable as a Tor onion service instead of, or as well
as, a public name: no relay address is published, nobody's traffic
leaves the Tor network, and Tor encrypts the connection end to end, so
plain `ws://` is the right scheme for it. On the relay host, with the
relay listening on `127.0.0.1:7777` and told its onion name with
`--host`, add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/silver-relay/
HiddenServicePort 80 127.0.0.1:7777
```

and restart Tor; `/var/lib/tor/silver-relay/hostname` holds the
address. Clients use `silver --relay ws://<that address>.onion/ws
--proxy socks5://127.0.0.1:9050`. The onion address is the relay's
identity: give it to people the way you would an invite link. This
recipe was run live with 0.18.0: a relay that knew only its onion name,
reached through Tor by two clients, a message each way.

### The key clients pin

A client can pin the relay's TLS public key (`silver --pin`) and then
refuse every other, and the pin outlives renewals that keep the key:
the built-in ACME client generates its key once and reuses it for every
renewal (delete `acme/key.pem` to change it), the installer's Caddyfile
sets `reuse_private_keys`, and certbot does the same with `--reuse-key`.
Step 7 below says how to compute the pin and publish it. When the key
does change, pinned clients fail to connect until they are given the
new pin, which is the point.

### Flags and variables

Every flag has an environment variable for `relay.env`, and
`silver-relay --help` lists them all. The limits are in their own table
below; the rest:

| Flag | Variable | What |
| --- | --- | --- |
| `--listen <ADDR>` | `SILVER_RELAY_LISTEN` | Where to listen; default `0.0.0.0:7777` |
| `--data-dir <DIR>` | `SILVER_RELAY_DATA` | The database; `/var/lib/silver-relay` under systemd |
| `--host <NAME>` | `SILVER_RELAY_HOST` | Names clients reach the relay by, comma separated, which a bound login must carry; the ACME domains and the certificate's names count already |
| `--acme-domain`, `--acme-email`, `--acme-directory`, `--acme-root` | `SILVER_RELAY_ACME_DOMAIN`, `_EMAIL`, `_DIRECTORY`, `_ROOT` | The built-in TLS, above |
| `--tls-cert`, `--tls-key` | `SILVER_RELAY_TLS_CERT`, `_KEY` | A certificate from elsewhere, above |
| `--trusted-proxy <ADDR>` | `SILVER_RELAY_TRUSTED_PROXY` | Whose `X-Forwarded-For` names the client; loopback by default |
| `--admin-socket <PATH>` | `SILVER_RELAY_ADMIN_SOCKET` | The Unix socket `silver-relay admin` uses ("Day to day") |
| `--metrics-listen <ADDR>` | `SILVER_RELAY_METRICS_LISTEN` | Prometheus metrics ("Monitoring"); loopback or a private network |
| `--log-format json` | `SILVER_RELAY_LOG_FORMAT` | One JSON object per line, for a log collector |
| `--log-ids` | `SILVER_RELAY_LOG_IDS` | Real ids in the log instead of per-run pseudonyms |
| `--ephemeral` | `SILVER_RELAY_EPHEMERAL` | Everything in memory only |
| `RUST_LOG=debug` | | Log level; `info` by default |

## A first deployment, step by step

1. **A host.** Any Linux with systemd; 1 vCPU, 1 GB of memory and 10 GB
   of disk serve hundreds of users (see "Sizing"). Or a machine with
   Docker for the container image.
2. **A name.** An A or AAAA record for the relay, pointing at the host.
   The relay obtains its certificate under that name.
3. **Ports.** 443 open to the world; nothing else. SSH from where you
   administer, and no other service on the host if you can help it.
4. **Install.** One of the four ways under "Installing" (the package,
   the release binary, the installer, the container image), with the
   built-in TLS under the name from step 2.
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
| `--max-identities` | 100000 | Identities the relay keeps, linked devices included (each person's devices count, at most eight per person) | A small relay: set it to the number of people you expect, times the devices each may link, with room |
| `--registrations-per-hour` | 20 per address | New identities from one address; a linked device registers as one, and a device revocation costs one too; 0 closes registration | A shared address (a NAT, a Tor exit) registers many people at once |
| `--connections-per-address` | 16 | Open connections from one address | Many users behind one NAT (raise), or abuse (lower) |
| `--max-connections` | 4096 | Open connections in total | The host is bigger or smaller than that |
| `--idle-timeout-secs` | 120 | A silent connection is closed after this | Clients ping every 30 seconds; only if a network needs longer |
| `--sends-per-minute` | 60 | Messages one authenticated connection may submit | Bots or bulk senders |
| `--anonymous-sends-per-minute` | 30 | Messages a connection that never logs in may submit; 0 turns anonymous submission off | See "Abuse": turning it off costs senders their anonymity towards the relay |
| `--lookups-per-minute` | 30 | Key lookups per connection; 0 turns them off rather than allowing one a minute | Rarely |
| `--one-time-prekeys-per-user-per-hour` | 30 | One-time prekeys handed out for one user; 0 stops them being handed out | Rarely; beyond it, lookups get the bundle without one |
| `--log-entries-per-user-per-hour` | 12 | Key changes one identity may add to the transparency log; 0 for no cap | The log is append-only and kept for good, so this is where its growth is bounded. A client publishing an unchanged bundle never adds one; an honest one adds a few a week |
| `--max-mailbox-messages`, `--max-mailbox-mib` | 1000, 32 | A recipient's queue; 0 for no cap on either | Users who are offline for long stretches |
| `--message-ttl-days` | 30 | How long an unacknowledged message is kept | A stricter retention policy (shorter), or long-absent users (longer) |
| `--max-blob-mib` | 16 | Largest file; 0 turns file transfer off | Your users share bigger files, or none |
| `--blob-storage-mib` | 1024 | Files on deposit in total | Disk |
| `--mailbox-storage-mib` | 4096 | Queued messages in every mailbox together; 0 for no cap | Disk. Mail is freed as recipients acknowledge it and by `--message-ttl-days`; past the cap a send is answered `storage_full` |
| `--blob-mib-per-address-per-hour` | 256 | Uploads from one address; 0 stops uploads | Abuse, or a shared address |
| `--max-groups` | 100000 | Groups with a live epoch sequencer entry (one counter and one hash each; an entry idle for 180 days is retired and its headstone dropped 180 days after that, neither counting against the cap); 0 for no cap | A small relay, with room: a group costs the relay almost nothing, so this is a guard against a loop making entries, not a sizing knob |
| `--trusted-proxy` | loopback | Whose `X-Forwarded-For` names the client | A TLS front on another host |
| `--require-bound-auth` | off | Refuse the login of clients before 0.6.0 | Once everyone has updated |
| `--host` | the ACME domains and the names in `--tls-cert` | The names clients reach this relay by, which a bound login must name | A TLS front, an onion address, or an address clients use literally: without the name, a login collected by another relay under that name is taken here (protocol section 7.1). The relay says at start which names it takes, or that it knows none |

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
| `silver_relay_refused_total{reason}` | Refusals by kind: `connection`, `registration`, `upload`. Refused logins are not one of these; they are `silver_relay_auth_failures_total` below |
| `silver_relay_idle_closed_total` | Connections closed for silence |
| `silver_relay_slow_closed_total` | Connections closed because the client stopped reading what was written to it (a frame did not go within 30 seconds) |
| `silver_relay_anonymous_submissions_total` | Messages submitted on connections that never logged in |
| `silver_relay_auth_failures_total`, `silver_relay_auth_failure_addresses`, `silver_relay_auth_failures_max_per_address` | Failed logins in total, addresses that failed in the last hour, the most from one of them (the address itself is in the log, never here) |
| `silver_relay_identities`, `silver_relay_mailboxes`, `silver_relay_messages_queued`, `silver_relay_mailbox_bytes` | What the store holds |
| `silver_relay_blobs`, `silver_relay_blob_bytes`, `silver_relay_blob_bytes_limit` | Files on deposit against the cap |
| `silver_relay_key_packages`, `silver_relay_groups`, `silver_relay_retired_groups`, `silver_relay_groups_limit` | MLS key packages on deposit (the last-resort ones not counted), groups with a live sequencer entry, entries retired for sitting still (kept so the ids stay taken), and the cap |
| `silver_relay_group_commits_total`, `silver_relay_group_rejections_total` | Group commits the sequencer accepted and refused; rejections are normal when two members change a group at once, a steady stream of them is a client stuck on a stale epoch |
| `silver_relay_devices`, `silver_relay_device_revocations_total` | Linked devices (identities whose bundle carries a device certificate; each is one of the identities above too) and device revocations held, which nothing removes |
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

**Devices.** `admin unrevoke-device <who>` drops the device revocation
the relay holds for an id, so it may publish, log in and receive again.
An account revokes its own devices (protocol section 14.2) and the relay
takes the statement only for a device that claims that account, so this
is for putting right a revocation that should not have been taken: an
account revoking a device it had not lost, or a statement a relay before
0.10.1 took under the rule that finding SM-R-01 of the audit closed. The
log entry stays, as an append-only log's do; a client reads the entry
against the statement served beside the bundle, and there is none once
this returns.

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

The backup also carries the key transparency log (`PROTOCOL.md` section
11): one small entry per key change or lifecycle statement, which never
shrinks (a few hundred bytes per identity per prekey rotation; not a
sizing concern for the networks a single relay serves). Restoring an older
backup puts the log back to where it stood then. Every client that had
verified further reports once that the relay's key log went backwards and
replays it from the start; that is the expected consequence of a restore,
and a reason to restore the newest backup you have. A relay whose log went
backwards *without* a restore is a relay whose database was tampered with
or replaced, and clients treat the two alike, so if you see the report
without having restored, look for the cause.

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
   release you verified ([RELEASES.md](RELEASES.md)).
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
