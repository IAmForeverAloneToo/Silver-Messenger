# Roadmap

Ordered from first to last. Each item says why it sits where it does and
roughly how big it is (S: hours, M: a day or two, L: a week or more).
Tick items off as they land on `main`.

## Done

- [x] Workspace, protocol, relay, client core, TUI
- [x] End-to-end encryption with sealed sender, signed key bundles
- [x] Relay auth, mailbox with acknowledgements, reconnect with backoff
- [x] HTTPS relay behind Caddy, `wss://` with system and Mozilla roots,
      extra CA option, HTTP CONNECT proxy support
- [x] Installer, hardened systemd unit, deploy and release workflows
- [x] Live two-way and offline-delivery test against the deployed relay

## Phase 1: make what exists reliable

1. [x] **Relay persistence** (M). Mailboxes and key bundles in an embedded
       store (redb or SQLite) so an update or reboot loses nothing. Includes
       message expiry and a per-user disk quota. First because every deploy
       currently drops queued mail.
2. [x] **Client outbox** (S). Queue messages written while offline and flush
       them on reconnect, with a visible pending state. Second because it is
       the other half of "nothing gets lost".
3. [x] **Per-conversation sequence numbers** (S). A counter inside the
       encrypted body so the client detects replays, gaps and reordering.
       Early because later protocol work builds on it.
4. [x] **v0.1.0 release, checksums, `cargo audit` and `cargo deny` in CI**
       (S). A tagged baseline before the trust-model changes.

## Phase 2: complete the trust model

5. [x] **Threat model document** (S). What the relay, the network and a
       stolen device can each see. Written first so items 6 to 9 are
       measured against it.
6. [x] **Key-change warnings and `/verify`** (S). Loud warning when a
       contact's published key changes; a short safety-number string to
       compare out of band; a verified mark on contacts.
7. [x] **Encrypted local storage** (M). Keys and history under a passphrase
       (Argon2id, XChaCha20-Poly1305), optional OS keychain unlock.
8. [x] **Identity backup and restore** (S). Seed phrase or encrypted export,
       so a lost machine is not a lost identity.
9. [x] **Contact requests and relay abuse controls** (M). First messages
       from strangers land in a pending list; relay rate limits, per-sender
       quotas, optional invite-token registration.

## Phase 3: forward secrecy

10. [x] **Double ratchet sessions** (L). Prekey bundles for the initial
        handshake, then a ratchet per conversation, negotiated as protocol
        v2 with a fallback so old clients keep working during rollout.
11. [x] **Protocol specification** (S). Written alongside the ratchet so
        the wire format is documented once it stops changing
        (`docs/PROTOCOL.md`).
12. [x] **Unauthenticated submission** (M). Today the relay can pair a
        sealed envelope with the authenticated session that submitted it.
        Sending over a separate, unauthenticated connection (with abuse
        controls that do not need the sender's identity) closes that
        metadata leak.

## Phase 4: everyday messaging

13. [x] **Delivery and read receipts** (S). Encrypted message types; the
        relay learns nothing new.
14. [x] **TUI polish** (M). Date separators, mouse and keyboard scrolling,
        input history, multi-line composing, bracketed paste, `/search`.
15. [x] **Notifications** (S). Terminal bell, desktop notifications, unread
        count in the window title.
16. [x] **Invite links and QR codes** (S). `silver://add/<id>` and a QR
        rendered in the terminal, so ids are shared without copy-pasting
        44 characters.
17. [x] **Attachments** (M). Encrypted files, chunked or via a relay blob
        endpoint, with a size cap and progress display.

## Phase 5: a terminal client that feels native

The first real use on Windows (0.4.0, in the classic console) showed that
the client works but fights the terminal: the check marks do not render,
text cannot be selected, copied or pasted, and everything needs the
keyboard. Most of that has one cause: the client captures the mouse for
wheel scrolling, which on Windows turns off the console's QuickEdit mode
(its only selection and paste mechanism), and it draws marks in glyphs
the console's default fonts do not have. This phase does nothing but make
the client comfortable, on every terminal people actually use, before any
more protocol work.

18. [ ] **Windows first run** (S). Detect the classic console and
        terminals without the glyphs and fall back to ASCII marks
        (`..`, `v`, `vv`, `x`), with `--ascii` and a config key to force
        either way; check box drawing, the date rule and the QR code
        under the console's default fonts; make sure output is UTF-8 on
        every Windows host; document Windows Terminal as the recommended
        terminal and how to install it. First because it is what a new
        Windows user hits in the first minute.
19. [ ] **Clipboard that just works** (M). Paste from the system clipboard
        on `Ctrl-V`, `Shift-Insert` and right click, read by the client
        itself (arboard on Windows, macOS and X11/Wayland; OSC 52 over
        SSH and in tmux) instead of relying on the terminal's paste path;
        copy the selection or the last message with `Ctrl-C` and
        `/copy`, the invite link with `/invite copy`; move quitting to
        `Ctrl-Q` with a confirmation, with `Ctrl-C` quitting only when
        there is nothing to copy. Second because it removes the reason
        people reach for the terminal's own selection.
20. [ ] **Text selection inside the client** (M). Drag with the mouse or
        `Shift`+arrows in the message pane to select, with a visible
        highlight; double click selects a word, triple click a message;
        the selection copies to the clipboard and can be cleared with
        `Esc`. The terminal's native selection (`Shift`+drag, or
        `--no-mouse`) keeps working as the fallback.
21. [ ] **Mouse navigation** (M). Click a chat, the Requests entry or
        System in the sidebar to open it, click the message box to focus
        it, click a scrollbar or drag it, click a file line to open the
        file, drag the divider to resize the sidebar; the wheel keeps
        scrolling. Everything stays reachable by keyboard.
22. [ ] **Discoverability** (M). A help overlay on `F1` and `?`, a status
        line that shows the keys that matter for the focused pane,
        `Tab` completion and a suggestion popup for `/commands`, contact
        names and file paths, usage hints when a command is mistyped,
        unread badges in the sidebar, and a short guided first run in
        the System pane. So nobody needs the README to get going.
23. [ ] **Layout and rendering** (S). A narrow-terminal layout that
        collapses the sidebar, light and dark palettes with `--theme` and
        `NO_COLOR`, focus shown on pane borders, word-boundary wrapping
        with hanging indents everywhere, an unread separator in the
        chat, relative timestamps on hover-less terminals ("today",
        "yesterday"), and clickable OSC 8 links for invite links and
        saved file paths.
24. [ ] **Terminal test matrix** (S). Run the pty smoke tests and a
        snapshot test against xterm, Windows Terminal, the classic
        console, tmux, macOS Terminal.app and iTerm2; record each
        terminal's quirks in `docs/TERMINALS.md`; make the matrix part of
        CI where the terminal can be driven headless. Last because it
        keeps 18 to 23 from regressing.

## Phase 6: beyond one relay

25. [ ] **Relay metrics and admin tooling, built-in TLS** (S). Prometheus
        endpoint, mailbox inspection, ACME in the relay so Caddy is optional.
26. [ ] **Relay-agnostic addresses** (M). Contacts as `id@relay` so people
        on different self-hosted relays can talk.
27. [ ] **Username registry** (M). Optional, signed claims on a relay.
        Decide the openness of the network before this one.
28. [ ] **Group chats** (L). Sender keys, membership and invites.
29. [ ] **Multiple devices** (L). Linked devices first, full identity sync
        later.

## Continuous

- [ ] Fuzzing for the envelope and frame parsers, property tests for
      seal/open
- [ ] Docker image for the relay; code signing for Windows and macOS
- [ ] Contributor guide and FAQ for non-technical users
