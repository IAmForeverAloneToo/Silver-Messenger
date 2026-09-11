# Roadmap

Ordered from first to last. Each item says why it sits where it does and
roughly how big it is (S: hours, M: a day or two, L: a week or more).
Tick items off as they land on `main`. An item with parts lists them as
boxes of their own, so what is left of it can be read without reading it;
a decision an item turned on is one line here, and its argument is in the
design note the item links. A ticked item may keep an unticked line under
it: a check that needs a machine or a person this project does not have,
kept visible rather than assumed.

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
        - Clickable OSC 8 links were left out: the renderer's cell buffer
          cannot carry them; paths and links are copied with `/copy` and
          opened with `/open` or a double click instead.
        - xterm, the Linux console and tmux are driven in CI. Windows
          Terminal, the classic console, Terminal.app and iTerm2 are
          documented in `docs/TERMINALS.md` from hand checks and the
          terminals' own documentation.

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
        (RFC 8555.)
        - [x] A live run of a relay behind an onion service: done on
          2026-09-11 with 0.18.0, as the operator's guide's recipe says — Tor's
          hidden service in front of an ephemeral relay told its onion
          name with `--host`, two clients through SOCKS5, a message each
          way with its read receipt, torn down afterwards.
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

47. [x] **Groups on MLS** (L). RFC 9420 through OpenMLS, with the relay
        as the delivery service: key packages published and handed out
        like prekeys, membership changes as signed proposals by group
        administrators, invites as links, and sealed sender kept so the
        relay still does not learn who wrote what. Design note
        [docs/design/groups.md](docs/design/groups.md); `docs/PROTOCOL.md`
        section 13. Settled in 0.9.0: one-to-one conversations stay on the
        Double Ratchet, so 42's deniability holds; the suite is the hybrid
        `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` on its
        provisional code point; delivery is client fan-out through the
        members' own mailboxes, with a relay-side epoch sequencer ordering
        commits.
48. [x] **Multiple devices** (L). Each device has its own keys, certified
        by the identity key, which stays on the primary; linking by a link
        with a one-time secret, answered through the relay with the
        certificate and a snapshot of the contacts, groups and recent
        history; a device is a leaf of its own in every group; revocation
        by a signed statement the relay serves, logs and enforces.
        Signal's Sesame is the reference. Design note
        [docs/design/devices.md](docs/design/devices.md); `docs/PROTOCOL.md`
        section 14. Shipped in 0.9.0; a client from 0.8.0 keeps talking to
        a person with devices through the primary.
49. [ ] **Usernames scoped to a relay** (M). `alice` as a signed claim,
        unique on that relay, resolved by the relay and verified by the
        client, with the safety number still the truth. Gated: only if
        people who use groups and devices ask for discovery beyond invite
        links, and not a condition of 1.0.
        - Re-examined in 0.16.0, with 47 and 48 shipped: neither produced
          the need. A person is found by an invite or a QR code, a group
          by its link, a device by the link it prints, and each carries
          the relay. A name is a namespace the relay owns, and the thing
          people would trust instead of checking the safety number — the
          failure this program keeps refusing to build.
        - If the need comes, the shape is not a username but an unlisted,
          changeable, disposable handle for first contact: a discovery
          token handed to a stranger and retired afterwards, never shown
          as identity, never searchable. Signal arrived there after years
          without usernames, for the same reasons.

## Phase 10: a finished terminal client

50. [x] **Everyday privacy features** (M). Disappearing messages with a
        per-conversation timer enforced by both sides; delete for me, and
        a best-effort delete for everyone that says what it can and
        cannot promise; edits, replies and reactions; all as encrypted
        content types behind capabilities, so older clients see something
        sensible; encrypted `downloads/` as an option, and history export.
        Shipped in 0.10.0 as `/reply`, `/react`, `/edit`, `/delete [me]`,
        `/timer`, `/files encrypt` and `--export-history`; protocol
        sections 4.7, 13.3 and 14.5; design note
        [docs/design/everyday.md](docs/design/everyday.md).
51. [x] **Accessibility in the terminal** (M). A screen-reader mode with
        linear output and no box drawing, a high-contrast palette, and
        every action reachable without the mouse. Shipped as `--reader`
        and `/reader on`, the `contrast` palette, `/go` and `/sidebar`,
        with what the pty suite can check of reader mode checked.
        - [ ] The check against each platform's screen reader: a manual
          protocol in `docs/TERMINALS.md`, unrun until someone runs it.
52. [x] **Client robustness** (S). The terminal restored on a panic,
        atomic writes for every store file under a kill test, memory
        caps for history and the seen-id set, and a soak test. Shipped:
        one panic hook that undoes exactly what the client set up, the
        kill test on every platform CI tests, the windows and caps, and
        `tests/tui/soak.py` — three minutes on every push, an hour by
        hand with memory flat (`docs/design/robustness.md`).
        - [ ] The day-long soak run.
53. [x] **Distribution** (M). A Debian package and a Homebrew tap built
        from the same reproducible release; Authenticode on Windows and
        notarisation on macOS. Shipped: the package, the tap, and the
        signing and notarising steps. A PKGBUILD and winget manifests were
        written and removed again in 0.12.2: each needed a push to
        somebody else's index that never happened and cost a regenerated
        file per release for nothing.
        [docs/design/distribution.md](docs/design/distribution.md) says
        where each channel stands.
        - [ ] The maintainer's Authenticode certificate and Apple
          membership in the release secrets, which is what makes the
          signing steps run.
54. [x] **Contributor guide and FAQ** (S). How to build, test and propose
        a change; a FAQ for people who are not developers. Shipped as
        `CONTRIBUTING.md` and `docs/FAQ.md`, which grows with the
        questions that come in.

## Phase 11: 1.0

55. [x] **Independent review** (L). The review of `silver-protocol` and
        the relay promised in item 35, by someone who did not write them,
        its findings fixed and published with the report. The review of
        the 0.10.0 line reported 76 findings, published whole as
        [docs/audits/2026-09-security-audit.md](docs/audits/2026-09-security-audit.md),
        with what each turned out to be and what was done about it in
        [docs/design/audit-response.md](docs/design/audit-response.md).
        - [x] 0.10.1: the Critical, the ten Highs, and the Mediums that
          share their code.
        - [x] 0.11.0: the rest of the Mediums, the Lows and the
          Informational findings — 72 of the 76.
        - [x] The four that needed a format change: item 57.
56. [ ] **Stable** (S). Protocol v4 frozen and documented as such, a
        support policy for what a stable release promises and for how
        long, and the first 1.0 release.
57. [x] **What the review left for a format change** (L). The four
        findings of the report's section 13.3 that 0.11.0 could not take
        without changing a wire or an on-disk format, and the
        counter-signature that closes the shape of SM-R-01. Design note
        [docs/design/format-changes.md](docs/design/format-changes.md),
        which also records the three corrections its section 5 took while
        it was being implemented.
        - [x] SM-C-24, rollback protection for the key-bearing files: an
          older copy of a file put back into a live directory is refused
          rather than read. 0.16.0.
        - [x] SM-C-25, history file names under an HMAC rather than the
          contact's id. 0.16.0, in one migration with SM-C-24.
        - [x] SM-P-14, the message's id sealed inside the body where the
          AEAD covers it, since the envelope's is the relay's to choose.
          Optional in 0.16.0, required in 0.17.0.
        - [x] The device's own signature on its certificate, so an account
          cannot enroll a key its holder never offered. Optional in
          0.16.0, required in 0.17.0; section 6 says what "required" means
          at each site, and a device linked before 0.16.0 signs its stored
          certificate on first start rather than being stranded.
        - [x] SM-P-04, the identity key bound into the v4 handshake.
          **Decided against:** v4 stays deniable, because a secret that
          authenticates you impersonating you when stolen is what deniable
          authentication means (section 3). What the finding calls for
          instead is the key being replaceable, and a responder accepting
          only the key an identity currently publishes: `/rekey`, designed
          in [docs/design/dh-rotation.md](docs/design/dh-rotation.md).
          0.18.0.
        - 0.17.0 was cut the same day as 0.16.0, by decision; its
          changelog says in as many words that a client older than 0.16.0
          cannot be read.
58. [x] **Updating in place** (M). `silver update`: finds the newest
        release, downloads the client for this platform, checks it
        against the release API's digest and against `SHA256SUMS` under
        the release workflow's keyless signature, makes the binary say its
        own version, and renames it over the running one, keeping the old
        for `--rollback`. A binary a package manager owns is refused with
        that manager's command; nothing is automatic, the daily check off
        unless turned on and then only a printed line. Design note
        [docs/design/updates.md](docs/design/updates.md), whose section 8
        says what it does not defend against. Shipped in 0.12.0 with
        `/update`, per-target release assets, and tests that a tampered
        digest, a disagreeing `SHA256SUMS`, an unsigned release, a
        redirect off the host and a package-managed binary are each
        refused with nothing left behind.
59. [x] **Desktop notifications that reach the desktop** (M). Item 15
        raised them through the terminal alone, which the common terminals
        ignore. The client asks the operating system where the terminal
        will not — the session bus on Linux, `osascript` on macOS, a WinRT
        toast on Windows — and the notification says `New message` and
        nothing else, ever, enforced by a raising call that takes no text.
        Design note
        [docs/design/notifications.md](docs/design/notifications.md).
        Shipped in 0.13.0 with `/notify terminal` and `/notify desktop`,
        the tmux wrapping, and tests that every notification at a pty says
        the one text. That a toast appears on each platform is checked by
        hand and recorded in `docs/TERMINALS.md`.
60. [x] **Requests, and naming people** (M). A request becomes a chat not
        yet answered: an entry of its own in the sidebar showing the
        stranger's id and nothing they chose, where `/accept`, `/decline`
        and `/block` take no argument and a typed reply accepts; decline
        is *not now* where block is *never*, and the sender learns nothing
        either way. One resolver — alias, id, unique id prefix, or the
        selected chat — under every command that names a person;
        `/copy id`, `/whois`, a click on the title that copies the id,
        Tab completion of aliases and group names. Design note
        [docs/design/requests.md](docs/design/requests.md). Shipped in
        0.14.0, with a terminal test that walks a request through each of
        those.
61. [x] **What the keys are worth on your own computer** (S). An outside
        review dumped the memory of an unlocked 0.14.0 client on Windows
        11 from an ordinary program of the same user and read the keys.
        Reading an unlocked client is the documented limit; the review
        showed the limit was not the same on every platform, and found
        two other things wrong beside it.
        - [x] `harden_process` gained the Windows branch it never had: an
          access list that refuses the process being opened for reading,
          which is cost rather than prevention, since the owner of a
          process may rewrite it.
        - [x] Erasing a device, or a change that then failed, no longer
          leaves a wrapping key in the key store.
        - [x] The threat model gained the actor this describes, a
          per-platform table of what each manages and leaves, and swap
          and hibernation as a path out of memory that full-disk
          encryption answers and this program does not.
62. [x] **What the second audit found** (M). A second outside review, run
        adversarially over the whole tree and reconciled across three
        rounds, found no cryptographic break: every chain built against
        the protocol failed against a check that was already there. What
        it found clusters where a command does more than it looks like,
        where a promise is kept on one path only, and where the relay's
        bookkeeping disagrees with itself. The report is
        [docs/audits/2026-09-second-security-audit.md](docs/audits/2026-09-second-security-audit.md);
        the answers, with the claims argued down and the two the reviewer
        argued back, are
        [docs/design/audit-response-2.md](docs/design/audit-response-2.md).
        All twelve fixes are in 0.16.0.
        - [x] 62.1 `/devices link` no longer signs a certificate on one
          pasted line: it says what the device would be given and waits
          for a short second line, the shape `/relay` and `/group join`
          share, while `/send` takes the paste guard alone
          ([docs/design/consequential-commands.md](docs/design/consequential-commands.md)).
        - [x] 62.2 A build with no `minisign.pub` refuses to update, as
          its own comment had promised twice in writing; the tests gained
          a signing key of their own, so the accepting half is exercised.
        - [x] 62.3 Reader mode: a line break inside a message no longer
          buys its sender a journal line of their own. The filter moved to
          the one door every line goes through, with the invariant test
          full mode has had since 0.10.0.
        - [x] 62.4 A fall in a peer's post-quantum level is reported, with
          both readings, since the client cannot tell an older client from
          keys stripped in transit.
        - [x] 62.5 A group alias is filtered on the way in and out, as a
          contact's always was (L-18).
        - [x] 62.6 The key store paths 0.16.0 left half shut: the undecided
          name is written first and the next start settles it, and
          "cannot tell" is no longer read as "no".
        - [x] 62.7 Relay: `--registrations-per-hour 0` means none, not one
          an hour; the expiry sweep runs in one write transaction, so an
          acknowledgement landing mid-sweep is not charged twice.
        - [x] 62.8 Relay: a refused frame no longer writes a log line, the
          metrics listener has the header-read timeout, and `silver.log`
          is bounded.
        - [x] 62.9 The ratchet body is validated at the boundary, as every
          other body version already was.
        - [x] 62.10 The Windows swap's empty window is made survivable:
          copy when rename fails, say what to rename by hand when both do;
          rollback shares the recovery.
        - [x] 62.11 A trust store that will not load is a warning rather
          than a debug line; the threat model no longer implies Unix modes
          apply on Windows.
        - [x] 62.12 The unbound login is refused by default, with
          `--allow-unbound-auth` for a relay that still has clients older
          than 0.6.0; the two parsers the updater runs before any
          signature is checked are fuzzed.
        - [x] The report and the response linked from `SECURITY.md` and
          the threat model, as the first review's are. Both had been in
          the tree since 2026-09-09; the pointer a reader starts from
          came after 0.18.0.
63. [ ] **The second review's remainder** (M). The findings the September
        2026 review left open, none of them a way for anyone to read a
        message or forge one, each listed with what leaving it costs in
        [docs/design/audit-response-2.md](docs/design/audit-response-2.md)
        section 4. All but one are closed.
        - [x] I-1: `docs/design/updates.md` claimed a kill test of the
          swap that did not exist — the worst of them, a false statement
          about what is tested. Two tests stand behind it now.
        - [x] L-5: mailbox limits that wrapped on multiply and silently
          meant "always full" at zero.
        - [x] L-8 and L-16: validation at the protocol boundary rather
          than only where a value is used.
        - [x] L-6: the transparency log capped per identity.
        - [x] L-10: secrets that serialized as plaintext for anything
          persisting them outside the vault.
        - [x] L-13: homoglyph names.
        - [x] L-14: a fuzz target for each of the five remaining parsers,
          each asserting the property it exists for. Writing the first
          found `split_https_url` reading `evil.test@api.github.com` as a
          host; refused now.
        - [ ] **H-1.** A macOS release built without the notarization
          secrets is signed ad hoc with the hardened runtime asked for,
          and the release job fails if the flag is missing from the
          signature it made. Left: watch that refuse a same-user attach on
          a real Mac. Until someone has, the threat model and
          `SECURITY.md` go on counting macOS as unprotected — left rather
          than assumed, because I-1 was a document describing a check the
          code did not do.
        - Declined, on one decision: L-1 (`mlock`/`VirtualLock` on key
          buffers) and the M-1 remainder (a key-store sweep), both system
          calls in the crate that holds the keys and is
          `#![forbid(unsafe_code)]`; and the L-11 and L-12 remainders,
          each on its own argument. Section 4 has the arguments.
        - Decided against: a non-zero `lock_after_minutes` default.
          Locking after an idle spell is the person's choice; the setting
          and `/lock` are there.
64. [ ] **The identity key somewhere the memory is not** (L, undecided).
        The one place taking a key out of the process would buy
        something: the identity key signs, so a copy taken once
        impersonates the account for as long as the key stands, outliving
        the lock and the session. A token or a platform enclave would
        bound a memory dump to the session it was taken in — but enclaves
        and most tokens hold P-256 and the identity key is Ed25519, so
        custody means a second signature algorithm or a hybrid across the
        protocol, every peer accepting it, and a design note in front. The
        September 2026 review read the Diffie–Hellman key out of memory in
        six seconds, so "stolen once, for good" is demonstrated rather
        than hypothetical; the revocation certificate and `/rotate` remain
        the cheap answer, and this is not a condition of 1.0.
        - Depends on SM-P-04 as decided (57): under a deniable v4 with the
          Diffie–Hellman key rotating on its own, the identity key signs
          rarely — bundles, revocations, certificates — which is what an
          enclave is good for, and a memory read is worth only the time
          until the owner rekeys from a key the reader cannot reach. Had
          handshakes been bound with identity signatures, the hardware key
          would sign every session start and the item would cost more for
          less.
65. [x] **The documents** (L). Every document in the repository read
        against what it is for: thirty of them, written over eight days
        of releases, each right when written and since bent by accretion
        — one fact in several homes, version history where a description
        belongs, paragraphs in table cells, claims that stopped being
        true. The shape each kind of document is held to is written
        down in `CONTRIBUTING.md` ("What the documents hold to"). No
        code changes; section numbers and item numbers never move.
        Landed on `main` after 0.18.0, one commit per box; the next
        release carries it.
        - [x] 65.1 The facts: every wrong or stale statement found, fixed
          where it stands; the link checker under `tests/docs/` and its
          CI step.
        - [x] 65.2 The map: `docs/RELEASES.md` from the README's three
          release sections; "Installing" in the
          operator's guide from the README's deployment section; the
          README rebuilt around what is left; every cross-reference
          following.
        - [x] 65.3 The promises: the threat model reshaped into lists per
          actor and re-read claim by claim against 0.18.0; the assessment
          re-read row by row against the code.
        - [x] 65.4 The specification: `PROTOCOL.md` within its sections,
          the vectors harness run after each.
        - [x] 65.5 The arguments: the design notes brought to one
          template, with their corrections gathered.
        - [x] 65.6 The rest: the contributor guide, the FAQ, the terminals
          matrix, the upgrade guide's version notes, the changelog's
          intro. The two reference READMEs were read and left as they
          are, and this file was left as the record it is rather than
          given the tense pass first planned.
        - [x] 65.7 The close: the checker over everything, the line counts
          before and after in the closing commit's message.
66. [ ] **The two files outside the generation record** (S). The relay's
        key log as replayed (`transparency.json`) and the outbox are
        written by code of their own, bound to their names alone, so item
        57's rollback protection does not cover them: an older copy of the
        log put back sets the replay behind, its checkpoints and its
        record of a fork it had seen included, and an older outbox
        re-queues envelopes the relay already holds and drops as
        duplicates. Route both through the store's bound writes, with the
        rule for a file the record has never heard of loosened to take a
        name-only one once and bind it on its next write, since every
        directory since 0.16.0 holds both files in that shape. Found when
        the migration that stamps every file stamped these two and their
        readers refused them (fixed in 0.18.1); the threat model names
        the gap.

## Continuous

- [ ] Every new parser gets a fuzz target; the terminal matrix, the
      reproducible-build check and the live test against the deployed
      relay stay green.
- [ ] The threat model and the assessment are re-read at the end of each
      phase and changed where the phase changed the facts.
