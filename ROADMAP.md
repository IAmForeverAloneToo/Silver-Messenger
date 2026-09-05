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

18. [x] **Windows first run** (S). Detect the classic console and
        terminals without the glyphs and fall back to ASCII marks
        (`..`, `v`, `vv`, `x`), with `--ascii` and a config key to force
        either way; check box drawing, the date rule and the QR code
        under the console's default fonts; make sure output is UTF-8 on
        every Windows host; document Windows Terminal as the recommended
        terminal and how to install it. First because it is what a new
        Windows user hits in the first minute.
19. [x] **Clipboard that just works** (M). Paste from the system clipboard
        on `Ctrl-V`, `Shift-Insert` and right click, read by the client
        itself (arboard on Windows, macOS and X11/Wayland; OSC 52 over
        SSH and in tmux) instead of relying on the terminal's paste path;
        copy the selection or the last message with `Ctrl-C` and
        `/copy`, the invite link with `/invite copy`; move quitting to
        `Ctrl-Q` with a confirmation, with `Ctrl-C` quitting only when
        there is nothing to copy. Second because it removes the reason
        people reach for the terminal's own selection.
20. [x] **Text selection inside the client** (M). Drag with the mouse or
        `Shift`+arrows in the message pane to select, with a visible
        highlight; double click selects a word, triple click a message;
        the selection copies to the clipboard and can be cleared with
        `Esc`. The terminal's native selection (`Shift`+drag, or
        `--no-mouse`) keeps working as the fallback.
21. [x] **Mouse navigation** (M). Click a chat, the Requests entry or
        System in the sidebar to open it, click the message box to focus
        it, click a scrollbar or drag it, click a file line to open the
        file, drag the divider to resize the sidebar; the wheel keeps
        scrolling. Everything stays reachable by keyboard.
22. [x] **Discoverability** (M). A help overlay on `F1` and `?`, a status
        line that shows the keys that matter for the focused pane,
        `Tab` completion and a suggestion popup for `/commands`, contact
        names and file paths, usage hints when a command is mistyped,
        unread badges in the sidebar, and a short guided first run in
        the System pane. So nobody needs the README to get going.
23. [x] **Layout and rendering** (S). A narrow-terminal layout that
        collapses the sidebar, light and dark palettes with `--theme` and
        `NO_COLOR`, focus shown on pane borders, word-boundary wrapping
        with hanging indents everywhere, an unread separator in the
        chat, relative timestamps on hover-less terminals ("today",
        "yesterday"), and clickable OSC 8 links for invite links and
        saved file paths.
24. [x] **Terminal test matrix** (S). Run the pty smoke tests and a
        snapshot test against xterm, Windows Terminal, the classic
        console, tmux, macOS Terminal.app and iTerm2; record each
        terminal's quirks in `docs/TERMINALS.md`; make the matrix part of
        CI where the terminal can be driven headless. Last because it
        keeps 18 to 23 from regressing.

Done, with two deviations: clickable OSC 8 links were left out (the
renderer's cell buffer cannot carry them; paths and links are copied with
`/copy` and opened with `/open` or a double click instead), and only
xterm, the Linux console and tmux are driven in CI. Windows Terminal, the
classic console, Terminal.app and iTerm2 are documented in
`docs/TERMINALS.md` from hand checks and the terminals' own documentation.

## Phase 6: secure by default

The first file exchange over a real relay (0.5.0) showed that a contact's
file is fetched and written to disk the moment it arrives, with nothing
asked and nothing checked beyond its hash. That is one symptom of a
program that grew feature by feature; this phase does nothing but go
through the whole of it, relay and client, with the eyes of an attacker
and the checklists the industry uses, and closes what it finds. The point
of the program is to be secure and private, so this comes before any more
reach. The yardsticks: OWASP ASVS 4.0 (V2 authentication, V6
cryptography, V7 logging, V8 data protection, V12 files, V13 API), the
CWE Top 25, NIST SP 800-63B, RFC 9106 (Argon2) and FIPS 203 (ML-KEM), the
Signal specifications (X3DH, PQXDH, Double Ratchet, Sealed Sender), SLSA
and the OpenSSF Scorecard for the build, and `systemd-analyze security`
for the relay host.

Already checked and found sound while writing this phase, so they are
not items: secrets are zeroized (identity, prekeys, sessions, file keys),
the passphrase vault is Argon2id with 64 MiB and 3 passes under
XChaCha20-Poly1305, store files are created 0600, the relay's systemd
unit is hardened, frames are size-capped and unauthenticated connections
time out, bundles and signed prekeys are signature-checked, the anonymous
connection runs without TLS resumption, and the renderer drops control
characters, escape sequences and bidi overrides from anything a peer
sends, so a message cannot drive the terminal.

25. [x] **Files you agree to** (M). Nothing from the network is written
        to disk without consent: a file line shows the name, size and
        sender, and `/get` (or a click) fetches it; a per-contact
        `auto` setting restores today's behaviour for people you trust,
        and the default is "ask". Before any chunk is requested the
        announced size and chunk count are checked against the 16 MiB
        cap (today `assemble` allocates whatever size the sender claims),
        a total quota for `downloads/` is enforced, and a fetch that
        fails its hash leaves nothing behind. First because it is the
        finding that started the phase, and the only one a contact can
        exploit today with no skill. (ASVS V12, CWE-434, CWE-770.)
26. [x] **Opening files safely** (S). `/open` and the double click never
        launch an executable or script (`.exe`, `.msi`, `.bat`, `.cmd`,
        `.ps1`, `.scr`, `.lnk`, `.js`, `.vbs`, `.jar`, `.sh`, `.app`,
        `.desktop` and the rest) and say why; saved files carry the mark
        of the web on Windows so SmartScreen and Defender treat them as
        downloads; names are normalised (NFC), stripped of Unicode
        format and bidi characters (a right-to-left override makes
        `photo` + `gnp.exe` read as `photoexe.png` in a file manager),
        refused when they are Windows device names
        (`CON`, `NUL`, `COM1`) or end in a dot or space, and the chat
        line shows the full name as saved. (CWE-451, CWE-22.)
27. [x] **Untrusted input, bounded** (M). Everything a peer or the relay
        controls gets a limit and a test: held requests capped per
        stranger and in total (today a flood fills memory and
        `requests.json`), the seen-id set bounded, claimed timestamps
        clamped for ordering, envelope, frame, blob chunk, invite link,
        file name and history parsers fuzzed with `cargo-fuzz` in CI
        (the Continuous item moves here), a regression test that
        control characters and escape sequences in messages, aliases,
        file names and notifications never reach the terminal, and a
        `#![forbid(unsafe_code)]` on every crate. (CWE-400, CWE-116,
        CWE-150.)
28. [x] **Relay abuse controls** (M). Limits per address, not only per
        connection: connections per address and in total, an idle
        timeout with WebSocket ping/pong, registrations per address per
        hour and a cap on stored identities, file storage quotas per
        uploader address and per recipient so one client cannot fill
        the shared 1 GiB for everyone, and a constant-time invite token
        comparison. Behind the TLS front the client address comes from
        `X-Forwarded-For`, trusted only from the configured proxy.
        `silver-relay --status` shows the counters. (ASVS V13, CWE-770,
        CWE-208.)
29. [x] **Relay logs and storage that reveal less** (S). User ids leave
        the default log level (today every authentication and
        disconnection is logged with the id and time, which is the
        social graph in `journalctl`); ids are truncated or hashed
        unless `--log-ids` is set; the database directory is created
        0700 and the database 0600 (`StateDirectoryMode=0700` in the
        unit); a retention note for journald goes into the deployment
        docs; `--ephemeral` stays the recommended mode for small
        relays. (ASVS V7.1, data minimisation.)
30. [x] **Authentication bound to the relay, bundles that expire** (S).
        The auth signature covers the relay's host name (or the TLS
        exporter, RFC 9266) as well as the nonce, so a hostile relay
        cannot forward a challenge from another relay and use the
        client's signature there; signed prekeys already carry a
        creation time, so the client refuses bundles whose signed
        prekey is older than the rotation period plus a grace, and
        publishes a last-resort prekey so draining one-time keys costs
        nothing but forward secrecy of one message. (ASVS V2.8, Signal
        X3DH.)
31. [x] **Protected at rest without a passphrase** (M). Keys, sessions,
        contacts and history are encrypted under a key kept in the
        operating system's store (DPAPI on Windows, the Keychain on
        macOS, the Secret Service on Linux where there is one), so a
        copied data directory is useless without the account, with the
        passphrase remaining the stronger option; `downloads/` gets the
        same on request; `silver.log` is created 0600 and never logs
        ids at `info`; `SILVER_PASSPHRASE` is removed from the process
        environment once read; `/lock` and an idle lock after a
        configurable time wipe the keys from memory; core dumps are
        disabled (RLIMIT_CORE 0, PR_SET_DUMPABLE, and the Windows
        equivalent). (ASVS V6, V8; CWE-312, CWE-526, CWE-528.)
32. [x] **Less for the relay to see** (M). Bodies padded to size buckets
        (Signal's 160-byte steps) so a receipt, a short and a long
        message look alike; receipts sent after a random delay so they
        do not mark the moment a message was read; a SOCKS5 proxy
        option so both connections can go through Tor and the
        anonymous connection stops sharing an address with the
        authenticated one; a relay certificate pin (`--pin <sha256>`)
        and a rule that a relay once reached over `wss://` is never
        talked to over `ws://`. The threat model then says exactly what
        the relay still learns. (Signal Sealed Sender; ASVS V9.)
33. [x] **Supply chain and release integrity** (S). GitHub Actions
        pinned by commit hash,
        `cargo auditable` builds and a CycloneDX SBOM attached to each
        release, SLSA build provenance attestations, `SHA256SUMS`
        signed with a minisign key published in the repository and the
        README, reproducible builds checked in CI, and the OpenSSF
        Scorecard run on every push. An opt-in `silver --check-release`
        tells a user when a newer version exists; it never runs by
        itself. (SLSA v1.0, OpenSSF Scorecard.)
34. [x] **Post-quantum key agreement** (L). Protocol v3: the initial
        handshake becomes a hybrid of X3DH and ML-KEM-768 (PQXDH), with
        post-quantum prekeys published and rotated like the classical
        ones, so a recording of today's traffic cannot be opened by a
        future quantum computer; a post-quantum ratchet step follows
        once the design settles. The same item decides deniability
        (bodies are signed today, so a recipient can prove who wrote
        what) and records the decision either way. (FIPS 203, Signal
        PQXDH.)
35. [x] **Security policy, assessment and outside eyes** (S). A
        `SECURITY.md` with how to report a vulnerability and which
        versions get fixes; `docs/SECURITY_ASSESSMENT.md` that walks the
        ASVS Level 2 controls and says for each whether the code meets
        it, with the item that closes any gap; the threat model
        rewritten for everything above; and, before 1.0, an independent
        review of `silver-protocol` and the relay by someone who did not
        write them. Last because it records what the phase achieved.

## Phase 7: run it well

The relay is where a self-hosted program lives or dies: every new user is
also someone running one. Today it needs Caddy in front for TLS, keeps no
metrics, has no administration tooling, and has no backup, upgrade or
container story. Operations come before reach.

36. [x] **Built-in TLS** (M). ACME in the relay, so a bare host with a DNS
        name gets and renews its certificate itself, plus `--tls-cert`
        and `--tls-key` for people who have their own; Caddy becomes
        optional and the deployment docs show both. Publishing the relay
        as a Tor onion service is documented and tested in the same
        item, since a relay that hides its own address is the natural
        partner of a client that already connects through Tor.
        (RFC 8555.) Done, with one deviation: the onion recipe is
        documented and the client's SOCKS5 path is tested, but a live
        run of a relay behind an onion service has not been done yet.
37. [x] **Metrics and structured logs** (S). A Prometheus endpoint on a
        separate listener that is never public, with the counters the
        relay already keeps plus failed logins per address; JSON log
        output as an option; example alert rules for a full mailbox
        store, a full blob store and a burst of refused registrations.
        Closes the monitoring gap in `docs/SECURITY_ASSESSMENT.md`.
38. [x] **Administration** (M). `silver-relay admin` over a local Unix
        socket, for the operator only: identities and their mailbox
        sizes under the log pseudonyms, blob usage, evict an identity,
        rotate the invite token, ban an address or an id. Nothing an
        administrator can do reveals a message or a social graph beyond
        what the store already holds.
39. [x] **Lifecycle** (M). A schema version in the database with
        migrations run at start, `silver-relay backup` and `restore`
        that take and load a consistent snapshot, an upgrade guide, and
        a reproducible container image for the usual architectures with
        a Compose example that uses the built-in TLS.
40. [x] **Operator's guide** (S). `docs/OPERATING.md`: sizing, journald
        retention, tuning the limits, monitoring, what to do after a
        compromise of the host, and a checklist for a first deployment.

## Phase 8: finish the protocol

Each item here is a line in the threat model's table of gaps. The
handshake was post-quantum; the ratchet after it was not, and now is (41).
Messages were not deniable, and now are (42). An identity could not be
rotated or revoked, and now can (43). A relay that showed one person a
stale key or a different log was caught only when two people compared
safety numbers by hand, and is now caught by their clients gossiping the
log head (44). The handshake and the ratchet are modelled, with published
vectors and a harness that replays them (45). Cover traffic is there for
those who want to pay for it (46).

41. [x] **Post-quantum ratchet** (L). An ML-KEM ratchet next to the
        Diffie–Hellman one, so healing after a compromise is post-quantum
        too, not only the handshake. Signal's Sparse Post-Quantum Ratchet
        is the reference design; a simpler step every fixed number of
        messages is the fallback if its cost does not fit. Settled
        together with item 47: one-to-one conversations stay on the Double
        Ratchet (so item 42's deniability holds; MLS application messages
        are signed by the sender's leaf), and groups go on MLS, so this is
        the dense one-step-per-turn ML-KEM-768 ratchet of protocol v4, with
        the sparse variant left for later since the fields are already
        per-message optional.
42. [x] **Deniability** (M). The v4 ratchet body drops the inner
        signature; the AEAD authenticates and either party could have
        produced the transcript, and the handshake's one remaining
        signature is over a public key, not the transcript. The v1 fallback
        is put on a retirement schedule: 0.8.0 and 0.9.0 still send v1 to
        peers without prekeys and warn, 0.10.0 refuses.
43. [x] **Identity lifecycle** (M). A revocation statement pre-signed when
        an identity is created and kept in the backup, so a key that is
        lost can still be declared dead; a signed successor statement for
        a planned rotation; both served by the relay on lookup and pushed to
        contacts, who verify them against the old key and re-pin. A lost
        or rotated key then no longer needs word of mouth. `/revoke` and
        `/rotate` drive them; the relay refuses to publish a revoked
        identity ever again. OpenPGP revocation certificates and Matrix
        cross-signing are the references.
44. [x] **Key transparency, small edition** (L). The relay keeps a
        hash-chained, append-only log of every bundle change and
        lifecycle statement it serves, and clients replay it, refuse a
        key that is not the latest logged one or a statement the relay
        hides, and carry the log head inside their encrypted messages to
        compare what they were shown. A relay that shows one person a
        stale key or a different log is then caught by the two clients
        gossiping, with nobody reading numbers aloud. CONIKS and Signal's
        key transparency are the references; with one relay per network
        the gossip between clients is the essential part, since the relay
        is the only log server. (The id being the key, the relay never
        could substitute an identity; the log catches freshness and
        equivocation, which signatures cannot.)
45. [x] **Formal model and test vectors** (M). The handshake and the
        ratchet modelled in Verifpal or Tamarin with the properties the
        threat model claims; published test vectors for the envelope, the
        handshake and the ratchet; a conformance harness a second
        implementation could run; property tests for seal and open. Done
        before the outside review so the reviewer starts from a model.
46. [x] **Cover traffic, opt-in** (S). Two clients that both advertise
        it send dummy padded messages at random intervals while online
        and discard them on receipt, so the relay's picture of who talks
        when blurs. It costs bandwidth, so it is off by default and the
        threat model says exactly what it does and does not hide.

## Phase 9: more than two people, more than one device

47. [ ] **Groups on MLS** (L). RFC 9420 through OpenMLS, with the relay
        as the delivery service: key packages published and handed out
        like prekeys, welcome messages and ordered commits through group
        mailboxes, membership changes as signed proposals by group
        administrators, invites as links, and sealed sender kept so the
        relay still does not learn who wrote what. The design decides
        whether one-to-one conversations stay on the Double Ratchet or
        become two-member groups, and picks the ciphersuite, with a
        post-quantum hybrid as soon as one is standardised. The design
        note is docs/design/groups.md.
48. [ ] **Multiple devices** (L). Each device has its own keys under the
        identity, listed in the bundle and signed by the identity key;
        linking by a QR code and a short-lived secret; every device is a
        leaf in the MLS tree of every conversation it belongs to;
        optional encrypted history sync through the relay. Signal's
        Sesame is the reference for the device list.
49. [ ] **Usernames scoped to a relay** (M). `alice` as a signed claim,
        unique on that relay, resolved by the relay and verified by the
        client against the signature, with the safety number still the
        truth. Last, and only if 47 and 48 show that people want
        discovery beyond invite links.

## Phase 10: a finished terminal client

50. [ ] **Everyday privacy features** (M). Disappearing messages with a
        per-conversation timer enforced by both sides; delete for me and
        a best-effort delete for everyone that says exactly what it can
        and cannot promise; edits as new messages that reference the old
        one; replies and reactions; all as encrypted content types behind
        capabilities, so older clients see something sensible. Encrypted
        `downloads/` as an option, and history export.
51. [ ] **Accessibility in the terminal** (M). A screen-reader mode with
        linear output and no box drawing, high-contrast palettes, and
        every action reachable without the mouse checked against a
        screen reader on each platform.
52. [ ] **Client robustness** (S). The terminal restored on a panic,
        atomic writes for every store file checked under a kill test,
        memory caps for history and the seen-id set, and a soak test
        that runs a client for a day against a local relay.
53. [ ] **Distribution** (M). Authenticode on Windows and notarisation on
        macOS, a Homebrew tap, winget, an AUR package and a Debian
        package, each built from the same reproducible release.
54. [ ] **Contributor guide and FAQ** (S). How to build, test and propose
        a change; a FAQ for people who are not developers, written from
        the questions the first users ask.

## Phase 11: 1.0

55. [ ] **Independent review** (L). The review of `silver-protocol` and
        the relay promised in item 35, by someone who did not write
        them, its findings fixed and published with the report.
56. [ ] **Stable** (S). Protocol v4 frozen and documented as such, a
        support policy for what a stable release promises and for how
        long, and the first 1.0 release.

## Continuous

- [ ] Every new parser gets a fuzz target; the terminal matrix, the
      reproducible-build check and the live test against the deployed
      relay stay green.
- [ ] The threat model and the assessment are re-read at the end of each
      phase and changed where the phase changed the facts.
