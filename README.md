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
a vulnerability is in [SECURITY.md](SECURITY.md). Two independent
adversarial reviews are published whole in [docs/audits/](docs/audits/),
with the answer to every finding in
[docs/design/audit-response.md](docs/design/audit-response.md) and
[docs/design/audit-response-2.md](docs/design/audit-response-2.md). The
questions people ask first, with short answers, are in
[docs/FAQ.md](docs/FAQ.md); how to build, test and propose a change is
in [CONTRIBUTING.md](CONTRIBUTING.md).

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

The [releases page](https://github.com/IAmForeverAloneToo/Silver-Messenger/releases)
carries the client and the relay as one file each per platform. Take
the client for your system:

| System  | File                                                                    |
| ------- | ----------------------------------------------------------------------- |
| Windows | `silver-v<version>-x86_64-pc-windows-msvc.exe`                          |
| macOS   | `silver-v<version>-aarch64-apple-darwin` (Apple Silicon), `…-x86_64-apple-darwin` (Intel) |
| Linux   | `silver-v<version>-x86_64-unknown-linux-musl` or `…-aarch64-unknown-linux-musl` (static; runs on any distribution) |

Rename it `silver` (`silver.exe` on Windows), make it executable on
macOS and Linux (`chmod +x silver`), and point it at a relay once:

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

**With a package manager:** both install the release binaries by their
checksum, so what arrives is what the release page carries.

```sh
brew tap iamforeveralonetoo/silver https://github.com/IAmForeverAloneToo/Silver-Messenger
brew install silver-messenger                          # macOS and Linux (Homebrew)
sudo apt install ./silver-messenger_<version>_amd64.deb   # Debian and Ubuntu, amd64 or arm64
```

On Windows, on Arch, and anywhere else, take the one file for your
platform from the release page: that is the whole client.

The Debian package puts `silver` and `silver-relay` in `/usr/bin` and
installs the relay's systemd unit without enabling it;
[docs/OPERATING.md](docs/OPERATING.md) says how to run a relay from it.

### Verifying a release

`SHA256SUMS` on the release page carries the project's signature, and
every file carries a build provenance attestation from GitHub. With
`minisign.pub` from the repository root:

```sh
minisign -Vm SHA256SUMS -p minisign.pub           # the list is the project's
sha256sum -c SHA256SUMS --ignore-missing          # the file is what was published
gh attestation verify silver-v* --owner IAmForeverAloneToo   # built by the release workflow, from the tagged commit
```

What each proves, how to rebuild a release and compare, and how a
release is made and signed are in [docs/RELEASES.md](docs/RELEASES.md).

### Updating

`silver update` replaces this binary with the newest release. It fetches
the client for your platform, checks it four ways, and only then renames
it into place:

* against the SHA-256 the releases page reports for that file, which
  comes from a different host than the bytes do;
* against the same hash in `SHA256SUMS`, which is what you would check by
  hand;
* against the project's signature over `SHA256SUMS`, using the key built
  into the client from `minisign.pub` — so what decides whether a binary
  may replace yours comes from the source, not from the network;
* and by running the downloaded file with `--version` and requiring the
  version that was expected.

If any of those disagrees, nothing on disk is touched and the message
says what disagreed with what. The binary it replaced is kept beside it,
so `silver update --rollback` puts it back. `silver update --check` says
what is available and changes nothing, and `silver update --to 0.11.0`
installs a named version — going backwards needs `--yes` as well, because
an older client may not read what a newer one has written in your data
directory.

A client your package manager installed is not replaced: `silver update`
says so and prints that manager's own command, since replacing it there
would break its verification and be undone by its next upgrade.

Nothing about this happens on its own. `silver update` runs when you run
it; `/update` inside the client says where you stand and installs
nothing. If you would like to be told, `update_check` in `config.json`
asks the releases page once a day at start and prints one line — off
unless you turn it on, because a check on a timer tells the release host
your address, that you run Silver Messenger, and when you use it.

`silver update` arrived in 0.12.0, and a release can only be installed by
a client that has it: 0.11.0 and earlier have no such command, so moving
from one of those to 0.12.0 is done once by hand, from the releases page
or a package manager. Every release after that is one command.

`silver --check-release` is `silver update --check` under its older name.
Both, and the daily check, go through the proxy and the extra roots this
data directory remembers, as the relay connection does, so a client whose
traffic is routed through Tor does not step outside it. A protected
directory asks for its passphrase so that they can be read; `--proxy` on
the command line answers the question without it.

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

A message from someone who is not a contact yet is a **request**: an entry
of its own at the bottom of the chat list, marked `?` and named by the
stranger's id, holding everything they sent. Open it and read; then
`/accept` makes them a contact and moves the messages into a chat (typing
a reply does the same), `/decline` says *not now* — the messages go, the
sender is told nothing, and if they write again the request comes back
without ringing — and `/block` drops everything from that id from then
on. Each of the three also takes the number the request was announced
with, or enough of the id, from anywhere; `/requests` lists what waits.
`/alias <name>` gives a contact a friendly name.

`/group new <name>` makes a group; `/group add <contact>` adds people who
are contacts (their client takes you in at once if you are theirs, and
otherwise lists the invitation in their chat list for them to open), and `/group
invite` prints a link and a QR code anyone can join by. A group is a pane
after the contacts, with each line showing who wrote it. Groups run on
MLS (RFC 9420) with a post-quantum hybrid suite and need a relay on
0.9.0; the relay never learns who is in a group.

One identity can run on several computers. On the new one run `silver
--link` (or answer yes when a first start asks whether to link this
computer to an identity you already have): it prints a link and a QR
code. On the computer you already use, `/devices link <link>` says what
that computer would be given — your identity signs a certificate for it,
so from then until you remove it that computer reads what is sent to you
and writes in your name — and shows its id to compare against the one it
printed. `/devices link confirm`, typed rather than pasted, takes it in:
the new device gets your contacts, your groups and the last thirty days
of history, and from then on every message reaches both, what you send on
one shows on the other, and contacts see one person with one id and one
safety number. `/devices` lists your devices, `/devices remove
<n>` cuts one off for good (a lost laptop, say), and `/devices leave
confirm` on a linked computer erases it. Your identity key stays on the
computer it was made on; a linked device holds keys of its own and a
certificate from it. Needs a relay on 0.9.0.

Sent messages carry a mark: `⋯` waiting for the relay, `✓` accepted by the
relay, `✓✓` delivered to the contact's device, `✓✓` in colour read, `✗`
refused. Received files are saved under their own name in
`<data-dir>/downloads` (never overwriting) and the chat line says where.
`/open` and `/files decrypt` reach that directory and nothing else, so a
message dressed up to look like a saved file elsewhere opens nothing.

### Commands and keys

| Command                         | Effect                                                       |
| ------------------------------- | ------------------------------------------------------------ |
| `/add <user-id or link> [alias]` | Add a contact by id or invite link                           |
| `/invite [copy]`                | Show your invite link and a QR code of it; `copy` puts it on the clipboard |
| `/copy [id [who]\|link]`        | Copy the last message of this chat, your id (or a contact's, by alias or id), or your invite link; a click on a chat's title copies that person's id too |
| `/whois [who]`                  | A person's id, alias, verification and how messages with them are protected, in the System pane: the open chat's, or one by alias, id or enough of it |
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
| `/notify all\|terminal\|desktop\|bell\|off` | Bell and a desktop notification (`all`: by the terminal or the desktop, whichever this terminal calls for; `terminal` or `desktop` forces one), bell only, or nothing |
| `/marks ascii\|unicode\|auto`   | Draw the marks in ASCII if your terminal shows boxes for them |
| `/theme dark\|light\|mono\|contrast` | Colours for a dark or a light background, none at all, or bright bold text on black for high contrast |
| `/go <name>`                    | Open the chat whose name (or id) starts with `name`; `system` and `requests` name those |
| `/sidebar <12-60>`              | How many columns the chat list takes (dragging its edge does the same); remembered |
| `/reader on\|off`               | Start in reader mode next time (see below); `silver --reader` does it once |
| `/history [n]`                  | In reader mode, read the last `n` lines of this chat with their times (default 10) |
| `/unread`                       | Say what waits unread in every chat                          |
| `/accept [n or id]`             | Accept a contact request or a group invitation: the open one, or one by its number or the sender's id (a typed reply to a request accepts it too) |
| `/decline [n or id]`            | Turn one down: not now, where `/block` is never; nothing is sent, and the sender's next one waits without ringing |
| `/requests`                     | List the requests and invitations waiting, with their numbers |
| `/group new <name>`             | Make a group (needs a relay on 0.9.0); its pane opens after the contacts |
| `/group add <contact>` / `remove <member>` / `leave` | Membership, by an admin; anyone may leave |
| `/group members` / `info` / `rename <name>` / `admin add\|remove <member>` | List, describe, rename, appoint |
| `/group invite [copy]` / `link reset` / `join <link>` | Show or copy the group's invite link (and its QR code), void old links, or ask to join by one (says who learns your id, then `/group join confirm`) |
| `/group rejoin` / `forget`      | Ask the admins to re-add you after a missed change; drop a group you left or were removed from |
| `/block [n, alias or id]`       | Drop everything from that id from now on: the open chat or request's, or one by number, alias or id |
| `/unblock <id>`, `/blocked`     | Undo a block (enough of the id will do); list blocked ids    |
| `/me`                           | Show your own id                                             |
| `/devices`                      | List your identity's devices: their names, when each was linked, and which one this is |
| `/devices link <link> [days]`   | Say what taking in a computer that printed a link with `silver --link` would grant it, and how much history goes with it (default 30 days, 0 for none); `/devices link confirm` goes ahead |
| `/devices remove <n>` / `name <n> <name>` / `join` | Revoke a device, rename one, or add your devices to the groups they are not in yet (all on the primary) |
| `/devices leave confirm`        | On a linked device: ask the primary to revoke it, erase its keys, contacts and history, and exit |
| `/relay <ws-url>`               | Say what moving to another relay costs; `/relay confirm` writes it (used on next start) |
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
raise a desktop notification — through the terminal where it raises one
itself (WezTerm, kitty, foot, iTerm2, rxvt-unicode, and over SSH), and
through the operating system everywhere else (Windows Terminal and the
Windows console, Terminal.app, GNOME Terminal and every VTE terminal,
Konsole, Alacritty) — and put the unread count in the window title;
`/notify` adjusts that. A notification says `New message` and nothing
else, ever: not who wrote, not what. If the
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
silver update              replace this binary with the newest release, after checking it against the releases page, SHA256SUMS and the project's signature
silver update --check      say what is available and change nothing (the same as --check-release)
silver update --rollback   put back the binary the last update replaced
silver update --to <VER>   install a named version rather than the newest (going backwards also needs --yes)
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
silver --reset-rollback-protection  start the record of what the directory last wrote again, when it is damaged and the client refuses to read; gives up telling whether a file was replaced with an older copy before now
SILVER_PASSPHRASE=…        supplies the passphrase non-interactively (scripts, tests); used once, then forgotten, so /lock asks for it again
silver --keep-passphrase   keep SILVER_PASSPHRASE in memory so /lock and the idle lock re-open without asking; for runs nobody is sitting at (env SILVER_KEEP_PASSPHRASE)
silver --export-backup <F> write an encrypted backup of identity and contacts to F (asks for a passphrase for it)
silver --import-backup <F> restore identity and contacts from F; add --force to replace an existing identity
SILVER_BACKUP_PASSPHRASE=… supplies the backup passphrase non-interactively
silver --export-history <D> write every conversation to D (outside the data directory), a text file each, or JSON lines with --format json; deleted and expired messages are not there, nothing is overwritten
silver --submit-authenticated  send on the authenticated connection instead of the relay's anonymous one (env SILVER_SUBMIT_AUTHENTICATED)
silver --require-anonymous send nothing at all to a relay that will not take anonymous submissions, rather than falling back to the authenticated connection (env SILVER_REQUIRE_ANONYMOUS)
silver --allow-unbound-login   log in to a relay older than 0.6.0, whose login signs the challenge without the relay's name (env SILVER_ALLOW_UNBOUND_LOGIN)
SILVER_LOG=debug silver    write logs to <data-dir>/silver.log (0600, not encrypted, rolled at 8 MiB with one earlier file kept; at debug it records envelope ids, contact ids and the relay's errors, so turn it on to debug and off after)
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
program that opens the file. The client keeps its keys out of core dumps, and out of reach of another
program running under your account as far as the platform allows: on
Linux the process cannot be traced or read, on Windows it carries an
access list that refuses being opened for reading, and on macOS neither
is available, so a debugger you started yourself can still attach. None
of that defends an unlocked client against a program running as you,
which no software on the same machine can; `/lock` and the idle lock are
what close it, by taking the client down and asking for the passphrase
again. `SILVER_NO_PROCESS_HARDENING=1` turns the process hardening off
if it gets in the way of a debugger or a tool you trust. The threat model
sets this out under "Program running as you".

### Pins and proxies

To trust one key rather than every certificate authority on the
machine, pin the relay's: `silver --print-pin` shows the pin of the key
the relay presents right now and whether its certificate is trusted,
and `silver --pin sha256:…` remembers it, after which any other key is
refused. Compare the pin with what the relay's operator published
rather than trusting the first answer. The pin names the relay's own
public key, the first one `--print-pin` prints, and nothing else in the
chain: a renewal that keeps the key needs no change, and a certificate
an inspecting proxy adds to the chain matches nothing. When the key
does change, connecting fails until the new pin is given (`--pin` again
adds it; the list is `relay_pins` in `config.json`).

With Tor running locally, `silver --proxy socks5://127.0.0.1:9050`
sends both relay connections through it: the relay's name is resolved
by Tor, and each connection gets its own circuit, so the relay sees two
unrelated exit addresses rather than one address for the authenticated
and the anonymous connection. An HTTP `CONNECT` proxy (`--proxy
http://proxy.corp:3128`, or `HTTPS_PROXY`) works too. A relay published
as an onion service is reached the same way, over plain `ws://`, which
Tor encrypts end to end: `silver --relay ws://<address>.onion/ws --proxy
socks5://127.0.0.1:9050`.

## Running a relay

A relay is one static binary that needs one open TCP port, runs as an
unprivileged user under a hardened systemd unit, and obtains its own
TLS certificate. [docs/OPERATING.md](docs/OPERATING.md) is the
operator's guide: installing from the Debian package, the release page,
the installer or the container image; TLS, a TLS front and an onion
service; a checklist for a first deployment; sizing, the limits, the
log, monitoring, administration, backups, what to do after a compromise
of the host, and shutting down. Moving between versions is
[docs/UPGRADING.md](docs/UPGRADING.md).

## What protects a message

The wire format and every constant are in
[docs/PROTOCOL.md](docs/PROTOCOL.md); what each of these protects
against, and what it does not, is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

* **Your id is your key.** An Ed25519 identity key, whose public half
  is the user id, and an X25519 key for Diffie–Hellman. Comparing ids
  is comparing keys, and `/verify` shows a safety number two people can
  read to each other.
* **The relay sees an envelope, not a letter.** Every message is sealed
  to the recipient's key; the sender's id is inside the ciphertext, the
  envelope names only the recipient, and it is submitted on a
  connection that never logs in. Bodies are padded to 160-byte steps,
  so a receipt and a short message look alike.
* **Forward secrecy, post-quantum.** A session starts with a PQXDH
  handshake (X3DH plus ML-KEM-768) against the recipient's published
  prekeys and continues as a Double Ratchet that does an ML-KEM step
  beside every Diffie–Hellman step: a key stolen tomorrow opens nothing
  read today, a compromise heals within a round trip, and a recording
  kept for a quantum computer stays closed. Session messages between
  current clients carry no signature, so nobody can prove to a third
  party who wrote one. `/session` says what a conversation has.
* **Keys you can check.** The relay keeps a hash-chained log of every
  key it serves; clients replay it, refuse a stale or unlogged key, and
  compare log heads inside their messages, so a relay telling two
  people two stories is caught by the next message between them. A
  contact's key change is announced loudly and clears the verified
  mark.
* **Keys you can retire.** `/rekey` replaces your encryption key under
  the same identity; `/rotate` hands over to a new identity with a
  cross-signed succession contacts re-pin to on their own; `/revoke`
  declares an identity dead with a certificate pre-signed on first run
  and kept in the backup, so a lost key can still be retired.
* **Groups on MLS.** A group is an MLS group (RFC 9420) on a hybrid
  post-quantum suite; each message is one MLS ciphertext sealed to
  every member, so the relay sees envelopes to people and no group, and
  keeps no membership list. Admins add and remove, every member checks
  every change, and group messages are signed inside MLS, so they are
  not deniable.
* **Devices.** A linked device has keys of its own, certified by your
  identity key, which never leaves the computer it was made on. Every
  message is sealed once per device, and a device is revoked by a
  signed statement the relay serves and contacts act on.
* **Files, receipts, edits.** A file travels as encrypted chunks under
  a per-file key carried inside the message; receipts, replies, edits,
  deletions, reactions and timers are content inside the encrypted body
  and look to the relay like short messages.
* **At rest.** Everything in the data directory is encrypted under a
  data key wrapped by the operating system's key store or a passphrase
  (Argon2id); each file is bound to its name and, all but two (roadmap
  item 66), a generation, so an older copy put back into a live
  directory is refused. `/lock` and the idle lock take the keys out of
  memory.
* **Backups.** `--export-backup` writes the identity, the revocation
  certificate and the contacts under a passphrase of their own;
  `--import-backup` restores them onto a fresh installation.
* **Cover traffic**, opt-in and mutual (`/cover on`), sends meaningless
  messages between two contacts at random moments while both are
  around, so the relay cannot tell when they really talk.
* **Checked against a model and vectors.** The handshake and the
  ratchet are modelled in Verifpal ([`formal/`](formal/)), and every
  operation has known-answer vectors ([`docs/vectors/`](docs/vectors/))
  that the test suite replays and a second implementation can check
  itself against.

What it does **not** do: a client for a phone, or a window to click in;
the client is a terminal program on purpose, and neither comes before
1.0. The ordered plan is in [ROADMAP.md](ROADMAP.md).

## Development

```sh
cargo test --workspace            # unit tests and in-process relay end-to-end tests
cargo clippy --workspace --all-targets
cargo fmt --all
cargo deny check                  # advisories, licences, duplicate crates (deny.toml)
```

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, what CI runs,
where the tests are and how to propose a change; how a release is made
and signed is in [docs/RELEASES.md](docs/RELEASES.md). Security
problems go through [SECURITY.md](SECURITY.md), not the issue tracker.

## License

AGPL-3.0. You may use, study, share and modify Silver Messenger freely; if
you distribute a modified version, or run a modified relay for other people
over a network, you must offer them its source under the same terms. The
relay serves a link to its source at `/` for that reason.
