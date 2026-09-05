# Silver Messenger

End-to-end encrypted messaging in your terminal. Written in Rust; runs on
Windows, Linux and macOS.

Messages travel through a **self-hosted relay** that only ever stores and
forwards encrypted blobs. The relay cannot read your messages or forge them.
The sender's identity is sealed inside the ciphertext, so the envelope itself
names only the recipient; the relay can still see which connection submitted
it. What the relay, the network and a stolen laptop can and cannot learn is
spelled out in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); how the code
measures up against the OWASP ASVS controls is in
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md); how to report
a vulnerability is in [SECURITY.md](SECURITY.md). The questions people
ask first, with short answers, are in [docs/FAQ.md](docs/FAQ.md); how to
build, test and propose a change is in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Layout

The repository is a Cargo workspace with four crates:

| Crate             | What it is                                                                 |
| ----------------- | -------------------------------------------------------------------------- |
| `silver-protocol` | Shared types and all cryptography: identities, key bundles, sealed envelopes, relay wire frames. |
| `silver-relay`    | The relay server binary (`silver-relay`). Authenticates clients, stores key bundles, queues envelopes per recipient. |
| `silver-client`   | Client core with no UI: relay connection with auto-reconnect, local store (keys, contacts, history). |
| `silver-tui`      | The terminal client binary (`silver`), built on ratatui.                   |

## Quick start

### From the release binaries

Download the archive for your system from the
[releases page](https://github.com/IAmForeverAloneToo/Silver-Messenger/releases):

| System  | Archive                                                                 |
| ------- | ----------------------------------------------------------------------- |
| Windows | `silver-messenger-<version>-x86_64-pc-windows-msvc.zip`                 |
| macOS   | `…-aarch64-apple-darwin.tar.gz` (Apple Silicon), `…-x86_64-apple-darwin.tar.gz` (Intel) |
| Linux   | `…-x86_64-unknown-linux-musl.tar.gz` (static; runs on any distribution) |

Unpack it. Inside are the client `silver` (`silver.exe` on Windows), the
relay `silver-relay`, and the docs. Open a terminal in that folder and
point the client at a relay once:

```
.\silver.exe --relay wss://relay.example.org/ws     # Windows, in PowerShell or Windows Terminal
./silver --relay wss://relay.example.org/ws         # macOS and Linux
```

The relay is remembered, so from then on `silver` alone is enough (on
Windows, double-clicking `silver.exe` works too). A data directory from an
earlier version is picked up as it is.

**Windows:** use [Windows Terminal](https://aka.ms/terminal) (preinstalled
on Windows 11, in the Microsoft Store on Windows 10) rather than the
classic console window. Its fonts have the check marks, and selection, copy
and paste behave as you expect. In the classic console the client draws
ASCII marks (`v`, `vv`, `x`, `..`) by itself; `/marks` changes that, and
`--no-mouse` hands selection and right-click paste back to the console.

**macOS:** until a release is notarised (the release notes say), the
first start may be refused. Right-click `silver` and choose Open once, or
run `xattr -d com.apple.quarantine silver`.

**With a package manager:** each of these installs the release archive
above by its checksum, so what arrives is what the release page carries.

```sh
brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger
brew install silver-messenger                 # macOS and Linux (Homebrew)
winget install IAmForeverAloneToo.SilverMessenger   # Windows, once the manifest is in winget-pkgs (the release notes say)
sudo apt install ./silver-messenger_0.10.0_amd64.deb   # Debian and Ubuntu: the .deb from the release page, amd64 or arm64
makepkg -si                                   # Arch: in packaging/aur/ of this repository (silver-messenger-bin), or from the AUR once published
```

The Debian package puts `silver` and `silver-relay` in `/usr/bin` and
installs the relay's systemd unit without enabling it;
[docs/OPERATING.md](docs/OPERATING.md) says how to run a relay from it.

### Verifying a release

Every release page carries, next to the archives, a `SHA256SUMS` file,
its signature `SHA256SUMS.minisig`, and a CycloneDX SBOM per binary; every
file has a build provenance attestation from GitHub. To check a download:

```sh
sha256sum -c SHA256SUMS --ignore-missing          # the archive is what was published
minisign -Vm SHA256SUMS -p minisign.pub           # ...by the maintainer (key: minisign.pub in this repository)
gh attestation verify silver-messenger-*.tar.gz --owner IAmForeverAloneToo   # ...by the release workflow, from the tagged commit
cargo audit bin silver                            # the dependencies inside the binary, against the advisory database
```

The binaries are reproducible: build the tagged commit yourself and the
bytes match (CI does this twice on every push for Linux and fails when
they differ). From a fresh clone at the tag, with the same stable
toolchain as the release (see the workflow run), on Linux:

```sh
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$HOME/.cargo=/cargo" \
cargo auditable build --release --locked --workspace --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/silver-relay   # compare with SHA256SUMS
```

A signed Windows or macOS executable (the release notes say whether a
release is signed) differs from a rebuild by its signature alone: strip
it and compare (`osslsigncode remove-signature -in silver.exe -out
plain.exe` on any platform, `codesign --remove-signature silver` on a
Mac). The Linux archives, the Debian packages and the container image
carry no embedded signature and reproduce byte for byte.

`silver --check-release` asks the releases page once whether a newer
version exists and prints the answer. It never runs by itself, downloads
nothing, and tells GitHub only that some computer at your address runs
Silver Messenger.

### From source

You need a Rust toolchain (https://rustup.rs). From the repository root:

```sh
# 1. Run a relay somewhere both parties can reach (defaults to 0.0.0.0:7777)
cargo run --release --bin silver-relay

# 2. Each person runs the client, pointing it at the relay once
cargo run --release --bin silver -- --relay ws://relay.example.org:7777/ws
```

### First steps

On first start the client generates an identity and shows your **user id** in
the System pane. Share it with the person you want to talk to (any channel
works; the id *is* your public key, so comparing it out of band is the same as
verifying a fingerprint). `/invite` shows it as a link
(`silver://add/<id>?relay=…`) and as a QR code that a phone can scan, so
nobody has to type 44 characters. Then:

```
/add <their-user-id or link> alice   # fetches their key from the relay and opens a chat
hello!                               # anything not starting with / is sent to the selected chat
/send ~/photo.jpg                    # sends a file (up to 16 MiB), encrypted like a message
```

A message from someone who is not a contact yet lands in the **Requests**
pane rather than in a chat; `/accept <n>` turns it into a contact (and moves
the held messages into the chat), `/block <n>` drops everything from that id
from then on. `/alias <name>` gives a contact a friendly name.

`/group new <name>` makes a group; `/group add <contact>` adds people who
are contacts (their client takes you in at once if you are theirs, and
otherwise shows the invitation in their Requests pane), and `/group
invite` prints a link and a QR code anyone can join by. A group is a pane
after the contacts, with each line showing who wrote it. Groups run on
MLS (RFC 9420) with a post-quantum hybrid suite and need a relay on
0.9.0; the relay never learns who is in a group.

One identity can run on several computers. On the new one run `silver
--link` (or answer yes when a first start asks whether to link this
computer to an identity you already have): it prints a link and a QR
code. On the computer you already use, `/devices link <link>` takes it
in: the new device gets your contacts, your groups and the last thirty
days of history, and from then on every message reaches both, what you
send on one shows on the other, and contacts see one person with one id
and one safety number. `/devices` lists your devices, `/devices remove
<n>` cuts one off for good (a lost laptop, say), and `/devices leave
confirm` on a linked computer erases it. Your identity key stays on the
computer it was made on; a linked device holds keys of its own and a
certificate from it. Needs a relay on 0.9.0.

Sent messages carry a mark: `⋯` waiting for the relay, `✓` accepted by the
relay, `✓✓` delivered to the contact's device, `✓✓` in colour read, `✗`
refused. Received files are saved under their own name in
`<data-dir>/downloads` (never overwriting) and the chat line says where.

### Commands and keys

| Command                         | Effect                                                       |
| ------------------------------- | ------------------------------------------------------------ |
| `/add <user-id or link> [alias]` | Add a contact by id or invite link                           |
| `/invite [copy]`                | Show your invite link and a QR code of it; `copy` puts it on the clipboard |
| `/copy [id\|link]`              | Copy the last message of this chat, your id, or your invite link |
| `/alias <name>`                 | Name the selected contact or group                           |
| `/remove`                       | Forget the selected contact (history file stays on disk)     |
| `/verify`                       | Show the safety number to compare with the selected contact  |
| `/verify ok` / `/verify no`     | Mark the selected contact as verified, or clear the mark     |
| `/refresh`                      | Fetch the selected contact's key again and report any change |
| `/session`                      | Show how messages with the selected contact are protected    |
| `/send <path>`                  | Send a file to the selected contact or group (also `/file`, `/attach`) |
| `/get [all]`                    | Fetch the newest file waiting in this chat, or `all` of them (double-click its line also fetches) |
| `/files auto\|ask`              | Fetch this contact's files as they arrive, or wait for `/get` (the default) |
| `/open`                         | Open the last file received in this chat (or double-click its line) |
| `/reply <text>`                 | Answer the selected message (or the last one received), quoted on every screen from that reader's own copy |
| `/react <emoji>` / `/react none` | React to the selected message (or the last one received); `none` takes yours back |
| `/edit <text>`                  | Replace the text of the selected message of yours (or your last one) within a day of sending; it shows as edited |
| `/delete`                       | Delete the selected message of yours (or your last one) for everyone, within a day of sending; a placeholder stays |
| `/delete me`                    | Remove any message from your devices only; the other side keeps its copy |
| `/timer <30s\|5m\|1h\|8h\|1d\|1w\|off>` | Messages in this chat disappear that long after you send them or they read them, on every device; in a group, admins only; `/timer` alone shows the setting |
| `/files encrypt on\|off`, `/files decrypt` | Keep received files as ciphertext (needs a protected data directory; `/open` still reads them), or write a plain copy of the last one |
| `/search <text>`                | Find messages in the selected chat or group, or in every chat and group from System; it reads the history files, so lines older than the screen holds are found |
| `/receipts on\|off`             | Tell contacts when you have read their messages (default on) |
| `/notify all\|bell\|off`        | Bell and desktop notification, bell only, or nothing         |
| `/marks ascii\|unicode\|auto`   | Draw the marks in ASCII if your terminal shows boxes for them |
| `/theme dark\|light\|mono\|contrast` | Colours for a dark or a light background, none at all, or bright bold text on black for high contrast |
| `/go <name>`                    | Open the chat whose name (or id) starts with `name`          |
| `/sidebar <12-60>`              | How many columns the chat list takes (dragging its edge does the same); remembered |
| `/reader on\|off`               | Start in reader mode next time (see below); `silver --reader` does it once |
| `/history [n]`                  | In reader mode, read the last `n` lines of this chat with their times (default 10) |
| `/unread`                       | Say what waits unread in every chat                          |
| `/accept <n>`                   | Accept a contact request from the Requests pane              |
| `/group new <name>`             | Make a group (needs a relay on 0.9.0); its pane opens after the contacts |
| `/group add <contact>` / `remove <member>` / `leave` | Membership, by an admin; anyone may leave |
| `/group members` / `info` / `rename <name>` / `admin add\|remove <member>` | List, describe, rename, appoint |
| `/group invite [copy]` / `link reset` / `join <link>` | Show or copy the group's invite link (and its QR code), void old links, or ask to join by one |
| `/group rejoin` / `forget`      | Ask the admins to re-add you after a missed change; drop a group you left or were removed from |
| `/accept g<n>` / `/decline g<n>` | Take or turn down a group invitation from a stranger (a contact's is taken at once) |
| `/block <n or id>`              | Drop everything from that id from now on                     |
| `/unblock <id>`, `/blocked`     | Undo a block; list blocked ids                               |
| `/me`                           | Show your own id                                             |
| `/devices`                      | List your identity's devices: their names, when each was linked, and which one this is |
| `/devices link <link> [days]`   | Take in a computer that printed a link with `silver --link`, sending it that many days of history (default 30, 0 for none) |
| `/devices remove <n>` / `name <n> <name>` / `join` | Revoke a device, rename one, or add your devices to the groups they are not in yet (all on the primary) |
| `/devices leave confirm`        | On a linked device: ask the primary to revoke it, erase its keys, contacts and history, and exit |
| `/relay <ws-url>`               | Change the relay (used on next start)                        |
| `/lock`                         | Forget the keys until the passphrase is typed again (needs one; `lock_after_minutes` in config.json does it by itself) |
| `/help`, `/quit`                |                                                              |

`F1` (or `/help`) opens a help overlay with all of this. `Tab` completes
`/commands` and file paths, and the status line at the bottom says what the
keys do where you are.

Mouse: click a chat, Requests or System in the list to open it, the wheel
scrolls, the scrollbar on the right edge can be dragged, so can the line
between the list and the chat to resize the list. Drag in the chat to select
text (double click selects a word, triple click a whole message), double
click a received file's line to open it.

Keys: `Tab` / `Shift-Tab` or `Alt-Up` / `Alt-Down` switch chats, `Up` /
`Down` recall earlier lines, `Alt-Enter` starts a new line in a message,
`PgUp` / `PgDn` scroll and `Ctrl-Home` / `Ctrl-End` jump, `Shift-Up` /
`Shift-Down` select messages, which `/reply`, `/react`, `/edit` and
`/delete` then act on. `Ctrl-C` copies the selection (with nothing
selected, pressing it twice quits), `Ctrl-V`, `Shift-Insert` or a right
click paste from the system clipboard, `Esc` clears the selection and then
the input line, `Ctrl-Q` quits. Copies go to the system clipboard, or to
the terminal's clipboard through OSC 52 over SSH and in tmux. Pasting keeps
line breaks. New messages in chats you are not looking at ring the bell,
raise a desktop notification where the terminal can (WezTerm, kitty, foot,
iTerm2, rxvt and others; the notification never contains the message), and
put the unread count in the window title; `/notify` adjusts that. If the
terminal is narrower than 70 columns the list folds away and the chat title
shows where you are. Everything the mouse does has a key or a command:
`/go <name>` opens a chat by name and `/sidebar <columns>` resizes the
list, so nothing needs the mouse.

Reader mode, for a screen reader: `silver --reader` (or `/reader on`,
which remembers it) runs the client as a line-at-a-time program with no
panes, no box drawing, no colours and no mouse. Every event is one line
at the bottom of the terminal's own scrollback (`alice: hello`, or `alice,
in team: hello` when that chat is not open; `you: …` for what you send;
`alice edited: …`, `alice deleted a message`, `alice reacted 👍 to: …`),
and the last line is where you type, its prompt naming the open chat
(`alice> `). Switching chats reads `Chat: alice, 2 unread.` and the unread
lines (or the last three); `Shift-Up` and `Shift-Down` select a message
and say it, `/history [n]` reads the last lines back with their times,
`/unread` says what waits where, `F1` prints the help as lines. The
commands and keys are the ones above. `--theme contrast` is a palette for
low vision in the full mode: bright bold text on black, and every colour
pair at high contrast. docs/TERMINALS.md says how each screen reader was
checked, or that it has not been.

### Options

```
silver --relay <URL>       relay WebSocket URL; remembered in config.json   (env SILVER_RELAY)
silver --data-dir <DIR>    where keys, contacts and history live            (env SILVER_DATA_DIR)
silver --ca-cert <PEM>     extra trusted root certificates for wss://; remembered (env SILVER_CA_CERT)
silver --proxy <URL>       proxy to reach the relay through: http://host:port (CONNECT) or socks5://host:port (Tor); remembered (env SILVER_PROXY, else HTTPS_PROXY / ALL_PROXY)
silver --pin <PIN>         pin the relay's TLS key (sha256:<hex>); refuse any other; remembered (env SILVER_PIN)
silver --print-pin         connect once, print the pin of the key the relay presents and whether its certificate is trusted, and exit
silver --check-release     ask the releases page once whether a newer version exists, print the answer, and exit (never by itself)
silver --invite <TOKEN>    invite token for a relay that only registers invited identities; remembered (env SILVER_INVITE)
silver --print-id          print your user id and exit
silver --print-invite      print your invite link (silver://add/<id>?relay=…) and exit
silver --link              make this (empty) data directory a device of an identity you use elsewhere: register with the relay, print a link and a QR code for /devices link on the other computer, and wait ten minutes for it
silver --device-name <N>   with --link: what your own devices call this one, up to 32 characters; the primary may name it instead (env SILVER_DEVICE_NAME)
silver --no-mouse          leave the mouse to the terminal: no wheel scrolling, but text selects without Shift (env SILVER_NO_MOUSE)
silver --ascii             draw marks in ASCII (v, vv, x, ..); chosen by itself in the classic Windows console (env SILVER_ASCII)
silver --theme <NAME>      dark (default), light for a light background, mono for no colour, or contrast for bright bold text on black; NO_COLOR means mono (env SILVER_THEME)
silver --reader            reader mode for a screen reader: one line per event, no box drawing, no colours, no mouse; /reader on makes it the default (env SILVER_READER)
silver --set-passphrase    encrypt keys, contacts and history under a passphrase (asked at every start)
silver --remove-passphrase drop the passphrase; files stay encrypted under this computer's key store where there is one
silver --no-keystore       keep the files unencrypted rather than under a key from this computer's key store; remembered
SILVER_PASSPHRASE=…        supplies the passphrase non-interactively (scripts, tests)
silver --export-backup <F> write an encrypted backup of identity and contacts to F (asks for a passphrase for it)
silver --import-backup <F> restore identity and contacts from F; add --force to replace an existing identity
SILVER_BACKUP_PASSPHRASE=… supplies the backup passphrase non-interactively
silver --export-history <D> write every conversation to D (outside the data directory), a text file each, or JSON lines with --format json; deleted and expired messages are not there, nothing is overwritten
silver --submit-authenticated  send on the authenticated connection instead of the relay's anonymous one (env SILVER_SUBMIT_AUTHENTICATED)
SILVER_LOG=debug silver    write logs to <data-dir>/silver.log

silver-relay --listen <ADDR>          default 0.0.0.0:7777                          (env SILVER_RELAY_LISTEN)
silver-relay --data-dir <DIR>         database location; under systemd /var/lib/silver-relay (env SILVER_RELAY_DATA)
silver-relay --message-ttl-days <N>   delete unacknowledged messages after N days, default 30 (env SILVER_RELAY_TTL_DAYS)
silver-relay --max-mailbox-messages   per-recipient queue cap, default 1000            (env SILVER_RELAY_MAX_MESSAGES)
silver-relay --max-mailbox-mib        per-recipient queue cap in MiB, default 32       (env SILVER_RELAY_MAX_MIB)
silver-relay --sends-per-minute <N>   messages one connection may submit per minute, default 60 (env SILVER_RELAY_SENDS_PER_MINUTE)
silver-relay --lookups-per-minute <N> key lookups per connection per minute, default 30   (env SILVER_RELAY_LOOKUPS_PER_MINUTE)
silver-relay --invite-token <T>       only register new identities that present T   (env SILVER_RELAY_INVITE_TOKEN)
silver-relay --anonymous-sends-per-minute <N>  messages an unauthenticated connection may submit per minute, default 30; 0 turns anonymous submission off (env SILVER_RELAY_ANONYMOUS_SENDS_PER_MINUTE)
silver-relay --max-blob-mib <N>       largest encrypted file to store, default 16; 0 turns file transfer off (env SILVER_RELAY_MAX_BLOB_MIB)
silver-relay --blob-storage-mib <N>   encrypted file bytes to keep in total, default 1024 (env SILVER_RELAY_BLOB_STORAGE_MIB)
silver-relay --max-groups <N>         group sequencer entries to keep at most, default 100000; 0 for no cap (env SILVER_RELAY_MAX_GROUPS)
silver-relay --ephemeral              keep everything in memory only
RUST_LOG=debug silver-relay           relay log level
```

Default data directory: `~/.local/share/silver-messenger` on Linux,
`~/Library/Application Support/silver-messenger` on macOS,
`%APPDATA%\silver-messenger\data` on Windows. Everything in it is encrypted
at rest: under a passphrase if you set one, otherwise under a key kept in
this computer's key store (the Credential Manager on Windows, the Keychain
on macOS, the Secret Service on Linux desktops), so a copied directory is
useless elsewhere. Where there is no key store (a server, a container) the
files are plain and the System pane says so at start. Received files go to
`downloads/` inside it; they are ordinary files, not encrypted at rest, so
other programs can open them, unless `/files encrypt on` keeps them
encrypted too, in which case `/open` decrypts a private copy for the
program that opens the file. The client keeps its keys out of core dumps
and, on Linux, away from debuggers of the same user.

## Deploying a relay

A relay is a single static binary that needs one open TCP port. It runs as
the unprivileged `silver` user under a hardened systemd unit
(`deploy/silver-relay.service`), listening on `0.0.0.0:7777`. Settings live
in `/etc/silver-relay/relay.env`, the database in `/var/lib/silver-relay`,
and logs are in `journalctl -u silver-relay`.
Remember to open port 7777/tcp in your provider's firewall as well.
[docs/OPERATING.md](docs/OPERATING.md) is the operator's guide: a
checklist for a first deployment, sizing, the limits, the log, monitoring,
day-to-day administration, backups, and what to do after a compromise of
the host.

The relay is careful about what it keeps. Its log names clients by a
pseudonym that changes every run (`--log-ids` writes the real ids, for
debugging); the database directory and file are readable by the `silver`
user only. What the log still records is when a client was connected, so
keep the journal short: `journalctl --vacuum-time=7d` trims it once, and
`MaxRetentionSec=7day` in `/etc/systemd/journald.conf` keeps it so. A relay
for a few people can run with `SILVER_RELAY_EPHEMERAL=1` in `relay.env`,
keeping mailboxes in memory only: a restart loses queued messages, and the
disk never holds any.

**From GitHub Actions** (works for a private repository): add the secrets
`VPS_HOST` and `VPS_SSH_KEY` (a private key whose public half is in the
server's `authorized_keys`; `VPS_USER` optionally, default `root`) and run
the **Deploy relay** workflow. It builds a static binary on the runner and
installs it over SSH, so the server needs neither Rust nor access to the
repository. The same workflow can show status and logs or restart the relay.

**By hand**, on a Debian/Ubuntu or Fedora server as root, if the repository
is public:

```sh
curl -fsSL https://raw.githubusercontent.com/IAmForeverAloneToo/Silver-Messenger/main/deploy/install.sh | bash
```

This installs build tools and Rust, clones the repository into
`/opt/silver-messenger`, and builds the relay on the server. Re-running it
updates to the latest `main`. With a `silver-relay` binary and
`silver-relay.service` placed next to it, the same script installs those
instead and needs no compiler.

Clients then start with `silver --relay ws://<server-ip>:7777/ws`.

**HTTPS / port 443.** Plain WebSocket on port 7777 is safe for message
content (everything is end-to-end encrypted before it leaves the client) but
exposes recipient ids and timing to the network path, and corporate or campus
proxies often block non-standard ports outright. Point a hostname at the
server and run the installer with `SILVER_DOMAIN=relay.example.org` (or set
the repository variable `VPS_DOMAIN` for the workflow). The relay then
listens on port 443 itself and obtains a Let's Encrypt certificate on its
own: it proves control of the name over TLS on that same port
(TLS-ALPN-01, RFC 8737), so port 80 stays closed and nothing else is
installed; renewals happen inside the relay, and `journalctl -u
silver-relay` says when. Using Let's Encrypt means agreeing to its terms;
`SILVER_EMAIL=you@example.org` gives it an address for expiry warnings.
Clients then use `silver --relay wss://relay.example.org/ws`. The client
trusts both the operating system's certificate store and Mozilla's root
bundle, so it also works behind TLS-inspecting proxies whose root
certificate is installed on the machine. Once a client has reached a relay
over `wss://` it refuses to talk to that host over plain `ws://`, so a
mistyped or tampered URL cannot quietly drop the encryption (the list is
`secure_hosts` in `config.json`).

The same without the installer: `silver-relay --listen 0.0.0.0:443
--acme-domain relay.example.org` (`SILVER_RELAY_ACME_DOMAIN` in
`relay.env`), with the account, the key and the certificate kept under
`acme/` in the data directory, readable by the relay's user only.
`--acme-email` gives the certificate authority an address for expiry
warnings, `--acme-directory` points at another certificate authority, for
example Let's Encrypt's staging directory for a dry run, and
`--acme-root` trusts a private one. A certificate from elsewhere works too: `--tls-cert
chain.pem --tls-key key.pem` serves it and re-reads the files whenever
they change, so certbot's renewals take effect without a restart.

**A TLS front instead.** Caddy, nginx or any other reverse proxy can still
terminate TLS and forward the WebSocket to the relay on localhost; then
the relay learns the client's address from `X-Forwarded-For`, trusted
only from the addresses in `--trusted-proxy`. The installer sets Caddy up
this way with `SILVER_TLS=caddy`, and keeps an existing Caddy setup from
before 0.7.0 unless `SILVER_TLS=builtin` tells it to switch (which stops
Caddy and moves the relay to port 443).

**Watching it.** `silver-relay --metrics-listen 127.0.0.1:9107`
(`SILVER_RELAY_METRICS_LISTEN` in `relay.env`) serves Prometheus metrics
at `/metrics` on that address and nothing else: open connections and
their cap, refusals by kind, failed logins (in total, and how many
addresses failed in the last hour and the most from one of them, never
the addresses themselves), identities, queued messages and their bytes,
files on deposit against the cap, the certificate's expiry and failed
renewals. It is meant for loopback or a private network, since the
numbers describe how the relay is used. `deploy/alerts.yml` holds
alerting rules for the things worth waking up for: the relay down, a
certificate that will not renew, a flood of failed logins or of refused
registrations, a nearly full file store. The log still carries the
hourly summary, and names an address in a warning once it fails to log
in twenty times within an hour; `--log-format json` writes one JSON
object per line for a log collector.

**Administering it.** With `--admin-socket /run/silver-relay/admin.sock`
(`SILVER_RELAY_ADMIN_SOCKET` in `relay.env`, which the installer sets)
the relay answers `silver-relay admin` on a Unix socket that only root
and the relay's user can open; nothing about administration is reachable
from the network and there is no password to keep. `silver-relay admin
status` prints the counters, the store's numbers, the registration
policy and the certificate; `admin identities` lists every identity
under the pseudonym the log uses, with its mailbox size and its prekey
deposit, largest mailbox first; `admin evict <who>` deletes an identity's
bundle, prekeys and mailbox and disconnects it; `admin ban <target>
--note why` and `admin unban` refuse or readmit an address or an
identity (a pseudonym from the listing, or a full id), kept across
restarts and listed by `admin bans`; `admin invite-set [token]`,
`invite-off` and `invite-reset` change which token new identities need
without a restart, until `invite-reset` hands the decision back to the
command line. None of it shows a message or a key: the store holds only
ciphertext and public keys, and the listing shows what the relay already
knows about each identity.

**Backups and upgrades.** `silver-relay backup relay.backup` writes one
consistent snapshot of the whole database, through the admin socket while
the relay runs or straight from the data directory while it is stopped, in
a format of the relay's own that is checked against its checksum before
the file gets its name. `silver-relay restore relay.backup --data-dir
/var/lib/silver-relay` loads it into a stopped relay (`--replace` moves an
existing database aside first). A backup holds what the database holds,
ciphertext and public keys and bans, so keep it as private and encrypt it
before it leaves the host. The database carries a schema version: an
upgrade brings an older layout along at the first start, and a relay
refuses a newer one rather than misread it.
[docs/UPGRADING.md](docs/UPGRADING.md) has the procedure, the rollback and
the version notes.

**In a container.** Each release publishes
`ghcr.io/iamforeveralonetoo/silver-relay` for amd64 and arm64: the release's
own static binary and a CA bundle on an empty base, running as an
unprivileged user, with a build provenance attestation that `gh
attestation verify oci://ghcr.io/iamforeveralonetoo/silver-relay:<version>
--owner IAmForeverAloneToo` checks. `deploy/compose.yml` runs it with the
built-in TLS on port 443, a read-only filesystem and no capabilities:
`SILVER_DOMAIN=relay.example.org docker compose -f deploy/compose.yml up
-d`, then `docker compose -f deploy/compose.yml exec relay silver-relay
admin status` for administration and `... silver-relay backup
/var/lib/silver-relay/relay.backup` for a backup on the data volume.
`deploy/Dockerfile` builds the same image from source, with the release's
flags, so it matches.

**Pinning the relay's key.** To trust one key rather than every
certificate authority on the machine, pin it: `silver --print-pin` shows
the pin of the key the relay presents right now, and `silver --pin
sha256:…` remembers it, after which any other key is refused. Compare the
pin with what the relay's operator published (they get it with
`openssl s_client -connect relay.example.org:443 </dev/null | openssl x509
-pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`)
rather than trusting the first answer. The pin names the public key, not
the certificate, so a renewal that keeps the key needs no change: the
relay's own ACME client generates its key once and reuses it for every
renewal (delete `acme/key.pem` to change it), the installer's Caddyfile
sets `reuse_private_keys`, and certbot does the same with `--reuse-key`.
When the key does change, clients fail to connect until they are given the
new pin (`--pin` again adds it; the list is `relay_pins` in
`config.json`).

**Through Tor.** With Tor running locally, `silver --proxy
socks5://127.0.0.1:9050` sends both relay connections through it. The
relay's name is resolved by Tor, not on the machine, and every connection
gets its own circuit, so the relay sees two unrelated exit addresses rather
than one address for the authenticated and the anonymous connection. An
HTTP `CONNECT` proxy (`--proxy http://proxy.corp:3128`, or `HTTPS_PROXY`)
works as before.

**As an onion service.** A relay can be reachable as a Tor onion service
instead of, or as well as, a public name: then no relay address is
published, nobody's traffic leaves the Tor network, and the connection
is encrypted end to end by Tor itself, so plain `ws://` is the right
scheme for it. On the relay host, with the relay listening on
`127.0.0.1:7777`, add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/silver-relay/
HiddenServicePort 80 127.0.0.1:7777
```

and restart Tor; `/var/lib/tor/silver-relay/hostname` holds the address.
Clients use `silver --relay ws://<that address>.onion/ws --proxy
socks5://127.0.0.1:9050`. The onion address is the relay's identity: give
it to people the way you would an invite link.

## How the crypto works

The exact wire format and every constant are in
[docs/PROTOCOL.md](docs/PROTOCOL.md); what it protects against, and what
it does not, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

* **Identity**: an Ed25519 signing key (its public half is your user id,
  shown as base58) plus a long-term X25519 key for Diffie–Hellman.
* **Key bundle**: your X25519 public key, signed with your identity key,
  plus your prekeys: a signed medium-term key rotated weekly and a batch of
  one-time keys. The relay stores and serves bundles, hands out one
  one-time key per lookup, and tells you when to deposit more. Clients
  verify the signatures and pin the long-term key on first use.
* **Envelope** (what the relay sees): `{ id, to, ephemeral_public, nonce, ciphertext }`.
  For each message the sender makes a fresh X25519 ephemeral key, derives a
  key with HKDF-SHA256 from `DH(ephemeral, recipient)`, and encrypts
  `sender_id || signature || body` with XChaCha20-Poly1305. The recipient id
  and ephemeral key are bound as associated data, and the signature covers the
  recipient, ephemeral key, nonce and body, so an envelope cannot be
  re-addressed, altered, or forged. The sender is inside the ciphertext, so
  the relay never sees it.
* **Forward-secret sessions**: when the recipient has published prekeys, the
  body inside the envelope is not the message but a Double Ratchet message.
  The first one carries an X3DH handshake against the recipient's identity
  key, signed prekey and a one-time prekey; from then on every message is
  encrypted under a key derived for it alone and discarded afterwards, and
  each change of direction in the conversation performs a fresh
  Diffie–Hellman step. A stolen device or key cannot decrypt messages that
  were already read, and a compromised chain heals at the next step. From
  0.6.0 the handshake is a hybrid (PQXDH-style): the recipient also
  publishes ML-KEM-768 keys (FIPS 203), the sender encapsulates a secret
  to one of them, and the session key depends on the Diffie–Hellman values
  *and* that secret, so a recording of today's traffic stays closed to a
  future quantum computer. From 0.8.0 the ratchet after the handshake is
  post-quantum too (protocol v4): every step does an ML-KEM step beside the
  Diffie–Hellman one, so a compromise heals against a quantum adversary
  within a round trip, and the message carries no signature at that layer,
  which makes it deniable (nothing lets the recipient prove to a third
  party who wrote it). The chat title says `forward secret` once a session
  exists, `forward secret, post-quantum` when ML-KEM is in play; `/session`
  explains the state, including whether the ratchet is post-quantum and
  whether the messages are deniable. A recipient without prekeys (a client
  older than 0.3.0, or anyone behind an older relay) is sent the plain v1
  body instead (signed, not deniable, and on its way out); one without
  ML-KEM keys gets the classical handshake; and one whose relay predates
  0.8.0 gets the v2 ratchet, so everyone keeps talking during the upgrade.
* **Anonymous submission**: a relay from 0.3.0 on accepts messages on
  connections that never authenticate, and the client uses one such
  connection (with TLS session resumption off) for everything it sends. The
  relay therefore cannot pair an envelope with the identity that submitted
  it; it still sees the address and the timing. `--submit-authenticated`
  turns this off for networks that allow one connection only.
* **Capabilities, receipts and files**: every encrypted body lists what the
  sending client understands beyond text (`receipts`, `files`), so a client
  never sends a peer something it cannot read and old clients keep working.
  A delivery receipt goes back when a message has been decrypted and
  stored, a read receipt when it has been shown (`/receipts off` keeps
  those to yourself); both are ordinary encrypted messages, batched so a
  full mailbox costs one, and never sent to strangers. A file is encrypted
  on the sender's machine under a fresh per-file key (XChaCha20-Poly1305 in
  64 KiB chunks, each bound to the file id and its position), the
  ciphertext is parked on the relay in chunks over the anonymous connection,
  and the key, name, size and SHA-256 travel to the recipient inside a
  normal message. The recipient fetches the chunks, decrypts, checks the
  hash, and saves the file. The relay holds bytes it cannot read, for a
  recipient it cannot name, and deletes them with the message expiry.
  Files from people you have not accepted are listed with their request
  but never fetched.
* **Abuse controls**: strangers who know your id can write to you, but their
  messages wait in the Requests pane until you accept or block them. The
  relay limits each connection to 60 messages, 30 key lookups and 600 file
  chunks per minute, caps every mailbox and its total file storage, and can
  be told to register only identities that present an invite token.
* **Encryption at rest**: with a passphrase set, every file in the data
  directory (identity keys, prekeys, sessions, contacts, history, outbox,
  config) is encrypted
  with XChaCha20-Poly1305 under a random data key, which is itself wrapped
  by the passphrase stretched with Argon2id (64 MiB, 3 passes). Each file is
  bound to its own name and history is encrypted line by line. A new
  identity offers to set a passphrase on first start; `--set-passphrase`
  and `--remove-passphrase` change it later.
* **Backups**: `--export-backup` writes the identity keys, the revocation
  certificate and the contact list to one file encrypted under a passphrase
  of its own (Argon2id and XChaCha20-Poly1305). `--import-backup` restores
  it onto a fresh installation: same id, same contacts, and a new
  message-numbering epoch so contacts see a reinstall rather than replays.
  History is not included.
* **Safety numbers**: `/verify` shows twelve groups of five digits derived
  from both identity keys, identical on both sides. Two people who read them
  to each other confirm that nobody sits between them; `/verify ok` records
  that. A contact's encryption key can only change with a signature from
  their identity key; when it does, the client warns loudly and clears the
  verified mark, because it means either a deliberate rotation or a stolen
  identity key.
* **Retire or replace an identity**: `/revoke` declares your identity dead
  with a certificate pre-signed on first run and kept in the data directory
  and the backup, so a key that is lost can still be retired; contacts that
  see it stop trusting the key, and the relay refuses to publish it ever
  again. `/rotate` moves to a fresh identity with a handover signed by both
  the old and the new key, so contacts re-pin to the new key on their own.
  A revoked contact is marked and cannot be messaged; a rotated one is
  re-pinned and its conversation carried across, with a nudge to compare
  safety numbers again. Needs a relay on 0.8.0; older relays still pass on
  the copy pushed inside a message.
* **Key transparency**: the relay keeps a hash-chained, append-only log of
  every key it serves and every revocation or handover, and the client
  replays it. A key the relay shows that is not the latest one in its log
  (an old prekey, or one it never logged) is refused, as is a hidden
  revocation, and every message carries the log head inside its encrypted
  body so two contacts compare what the relay told each of them: a relay
  keeping two versions of its log is reported as a fork by the next
  message between them. `/log` shows where the log stands. Since your id
  *is* your key, the relay never could substitute an identity; the log
  catches what signatures cannot, staleness and different stories to
  different people. Needs a relay on 0.8.0.
* **Sequence numbers**: every message carries, inside the encrypted body, a
  per-conversation counter plus a random per-installation epoch. The
  recipient drops replays, points out gaps, and notices when a contact has
  started over from a fresh installation. Messages from older clients that
  do not number messages are accepted unchecked.
* **Relay auth**: on connect the relay sends a random nonce; the client signs
  it with its identity key. Only the owner of an id can read its mailbox.
* **Delivery**: the relay keeps an envelope in an embedded database until the
  recipient acknowledges it, so nothing is lost if a client drops
  mid-download or the relay restarts. Unacknowledged envelopes expire after
  30 days by default, mailboxes are capped per recipient, and resends of the
  same envelope id are ignored. Clients de-duplicate by envelope id too.
* **Outbox**: a message written while offline is sealed immediately, kept in
  `outbox.json` in the data directory, and handed to the relay on the next
  connection; it shows a pending mark (`⋯`) until the relay accepts it, and a
  failure mark (`✗`) if the relay refuses it for good.

* **Checked against a model and vectors**: the handshake and the ratchet
  are modelled in Verifpal ([`formal/`](formal/)), with the outcome of
  every query, including the ones a model is meant to break, recorded and
  checked in CI; every operation has known-answer vectors
  ([`docs/vectors/`](docs/vectors/)) that the test suite replays and a
  second implementation can check itself against; property tests cover
  what must hold for every input.

* **Cover traffic, opt-in**: `/cover on` sends meaningless messages at
  random moments to contacts who have it on too, while you are both
  around, so the relay cannot tell when you really talk. It shows that
  you are in contact and does not hide bursts, long messages or files;
  it costs bandwidth, so it is off by default, and the threat model says
  exactly what it hides and what it does not.

* **Groups on MLS**: a group is an MLS group (RFC 9420, through OpenMLS)
  on the `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` suite, so its
  key agreement is post-quantum like the one-to-one handshake. Each
  member's leaf is signed by their identity key and carries their sealing
  key, so a group message is one MLS ciphertext sealed separately to every
  member into the ordinary envelope: the relay sees envelopes to people
  and no group, keeps no membership list, and orders membership changes
  with one counter per group it can move only for a token members of the
  current epoch derive. Admins add and remove members and every member's
  client checks every change against the group's rules, refusing and
  marking the group broken rather than let an intruder in; anyone may
  leave; invite links carry a secret an admin can rotate. Members refresh
  their keys weekly so a compromise heals. Group messages are signed
  inside MLS and so, unlike one-to-one messages, are not deniable; the
  threat model says what the relay can still infer.
* **Devices** (0.9.0 on): a linked device is a key pair of its own,
  certified by your identity key, which never leaves the computer it was
  made on. Your bundle lists your devices, signed as a whole, so a
  contact seals every message once per device of yours (and once per
  device of their own, so their other devices have it too), each under
  its own forward-secret session, all under one id; the relay sees a few
  more envelopes and no shared key. What one of your devices does the
  others are told inside ordinary messages that only your own devices
  can send. Linking sends the new device its certificate and a snapshot
  of your contacts and recent history through the relay, sealed under a
  one-time secret it printed; removing one is a signed statement the
  relay serves, logs and enforces and contacts act on. In groups each
  device is a leaf of its own.

* **Everyday features** (0.10.0): replies quoted from the reader's own
  copy, reactions, edits within a day, delete for everyone within a day
  (a placeholder stays; the threat model says exactly what the other
  side's software does and does not do about it) and delete for me, and
  a per-conversation timer after which messages disappear on every
  device, from sending for the sender and from reading for the reader.
  All of it travels inside the encrypted body as content the relay
  cannot tell from a short message; a contact on an older client is
  never sent what it would not read, and the client says so. Received
  files can be kept encrypted, and the history exported.

What it does **not** do yet: a screen-reader mode, or a client for a
phone. The ordered plan is in [ROADMAP.md](ROADMAP.md).

## Development

```sh
cargo test --workspace            # unit tests + in-process relay end-to-end tests
cargo clippy --workspace --all-targets
cargo fmt --all
cargo deny check                  # advisories, licenses, duplicate crates (deny.toml)
cargo audit
```

CI runs the same checks on every push, plus the test suite on Linux, macOS
and Windows, the terminal tests below under two terminal types, a minute
of fuzzing per parser, the relay's ACME client against Pebble (Let's
Encrypt's test server), and a reproducibility check that builds the Linux
binaries twice from scratch and compares them. Every GitHub Action is
pinned to a commit hash; the OpenSSF Scorecard runs weekly.

Pushing a `v*` tag (or running the release workflow with a tag) builds
the archives for all platforms with `cargo auditable`, attaches a CycloneDX
SBOM per binary, writes `SHA256SUMS`, signs it, attests the build
provenance, and publishes it all on the releases page.

**Signing releases** is the one step that needs a maintainer's key, kept
outside the build: once, run `minisign -G -W -p minisign.pub -s
minisign.key`, commit `minisign.pub` at the repository root, and put the
contents of `minisign.key` in the repository secret `MINISIGN_SECRET_KEY`
(the key is generated unencrypted so the workflow can use it; the secret
store protects it). Until then the workflow says so and publishes
`SHA256SUMS` unsigned; the provenance attestation is there either way.
The executables themselves are signed the same way, when the secrets
exist: on Windows with Authenticode from `AUTHENTICODE_PFX` (the PKCS#12
file, base64) and `AUTHENTICODE_PASSWORD`; on macOS with a Developer ID
Application certificate from `APPLE_CERTIFICATE_P12` (base64) and
`APPLE_CERTIFICATE_PASSWORD`, then notarised under `APPLE_ID`,
`APPLE_TEAM_ID` and `APPLE_APP_PASSWORD` (an app-specific password). With
none of a platform's secrets the workflow says so and publishes that
platform unsigned; with some but not all it fails, since a half-set
secret is a mistake. A bare executable takes a signature but no stapled
notarisation ticket, so Gatekeeper asks Apple about it the first time.

Security problems go through [SECURITY.md](SECURITY.md), not the issue
tracker.

The terminal client is tested for real in `tests/tui/`: each test starts a
relay and one or two clients in pseudo-terminals, types, clicks, drags
and reads the screen back through a terminal emulator (`pip install pyte`
first; `tests/tui/run.sh` runs them all, `TERMS="xterm-256color linux"`
for both terminal types, and `test_tmux.py` drives a client inside tmux).
Which terminals are known to work, and how, is in
[docs/TERMINALS.md](docs/TERMINALS.md). `tests/tui/soak.py --minutes N`
runs a relay and two clients exchanging messages for that long and
watches each process's memory: CI runs three minutes of it on every push,
the workflow can be dispatched for up to six hours, and
`--minutes 1440` is the day-long run.

The end-to-end tests in `crates/silver-client/tests/e2e.rs` start a relay
on a random port, connect two clients, and check both directions, offline
queueing, reconnection after the relay goes away, forward-secret sessions
(including handshakes that wait in the mailbox, restarts, a peer that lost
its session state, and a peer without prekeys), anonymous submission,
capabilities and receipts, file transfer (chunking, progress, a missing
blob, a tampered hash, a relay without file storage), groups, and
devices (`tests/devices.rs`: a device linked by its link, a message
reaching every device under one id, a revoked device cut off).
`tests/kill.rs` runs a writer child that saves the store as fast as it
can, kills it at random moments, and checks that the store opens with
nothing but the line being written lost.

## License

AGPL-3.0. You may use, study, share and modify Silver Messenger freely; if
you distribute a modified version, or run a modified relay for other people
over a network, you must offer them its source under the same terms. The
relay serves a link to its source at `/` for that reason.
