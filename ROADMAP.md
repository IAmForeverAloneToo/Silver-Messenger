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

47. [x] **Groups on MLS** (L). RFC 9420 through OpenMLS, with the relay
        as the delivery service: key packages published and handed out
        like prekeys, welcome messages and ordered commits through group
        mailboxes, membership changes as signed proposals by group
        administrators, invites as links, and sealed sender kept so the
        relay still does not learn who wrote what. The design decides
        whether one-to-one conversations stay on the Double Ratchet or
        become two-member groups, and picks the ciphersuite, with a
        post-quantum hybrid as soon as one is standardised. The design
        note is docs/design/groups.md. Done in 0.9.0: one-to-one stays
        on the ratchet; the suite is the hybrid
        `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` on its
        provisional code point; delivery is client fan-out through the
        members' own mailboxes rather than group mailboxes, with a
        relay-side epoch sequencer ordering commits; PROTOCOL.md
        section 13.
48. [x] **Multiple devices** (L). Each device has its own keys under the
        identity, listed in the bundle and signed by the identity key;
        linking by a QR code and a short-lived secret; every device is a
        leaf in the MLS tree of every conversation it belongs to;
        optional encrypted history sync through the relay. Signal's
        Sesame is the reference for the device list. The design note
        is docs/design/devices.md. Done in 0.9.0: the identity key
        stays on the primary and every other device is certified by
        it; one Double Ratchet session per pair of devices, a message
        sealed once per device of both people under one id, and what
        one's own devices do told between them as `sync` content;
        linking by a link with a one-time secret, answered through the
        relay with the certificate and a snapshot of the contacts,
        groups and recent history, which is the one history sync there
        is; a device is a leaf of its own in groups, signed by the
        device key with the certificate in the leaf; revocation by a
        signed statement the relay serves, logs and enforces; a client
        from 0.8.0 keeps talking to a person with devices through the
        primary. PROTOCOL.md section 14.
49. [ ] **Usernames scoped to a relay** (M). `alice` as a signed claim,
        unique on that relay, resolved by the relay and verified by the
        client against the signature, with the safety number still the
        truth. Last, and only if 47 and 48 show that people want
        discovery beyond invite links. Not done in 0.9.0: nothing yet
        shows that need; a person is found by an invite link or a QR
        code, a group by its link, and a device by the link it prints,
        and each of those carries the relay. The item stays open for
        the day people who use groups and devices ask for names, and is
        not a condition of 1.0.
        Re-examined in 0.15.0 and still gated. Groups (47) and devices
        (48) have both shipped, which is the condition this item was
        waiting on, and neither produced the need: a group is joined by
        its link, a device by the link it prints, a person by an invite
        or a QR code, and each of those already carries the relay. A name
        would add a namespace the relay owns and can lie about — the
        safety number stays the truth either way, but a name is the thing
        people would trust instead of checking it, which is the failure
        this program keeps trying not to build. Left open rather than
        dropped: the condition is real and may yet be met.

## Phase 10: a finished terminal client

50. [x] **Everyday privacy features** (M). Disappearing messages with a
        per-conversation timer enforced by both sides; delete for me and
        a best-effort delete for everyone that says exactly what it can
        and cannot promise; edits as new messages that reference the old
        one; replies and reactions; all as encrypted content types behind
        capabilities, so older clients see something sensible. Encrypted
        `downloads/` as an option, and history export. Done in 0.10.0:
        `/reply`, `/react`, `/edit`, `/delete [me]`, `/timer`, `/files
        encrypt`, `--export-history`; protocol sections 4.7, 13.3 and
        14.5; the design note `docs/design/everyday.md`.
51. [x] **Accessibility in the terminal** (M). A screen-reader mode with
        linear output and no box drawing, high-contrast palettes, and
        every action reachable without the mouse checked against a
        screen reader on each platform. Shipped as `--reader` and
        `/reader on`, the `contrast` palette, `/go` and `/sidebar`; what
        the pty suite can check of reader mode it checks, and the
        check against each platform's screen reader is a manual protocol
        in docs/TERMINALS.md, unchecked until someone runs it.
52. [x] **Client robustness** (S). The terminal restored on a panic,
        atomic writes for every store file checked under a kill test,
        memory caps for history and the seen-id set, and a soak test
        that runs a client for a day against a local relay. Shipped:
        one panic hook that undoes exactly what the client set up, the
        kill test on every platform CI tests, the windows and caps, and
        `tests/tui/soak.py` for as long as it is told (three minutes on
        every push; an hour run by hand with memory flat, recorded in
        docs/design/robustness.md; the day-long run is still to be made).
53. [x] **Distribution** (M). Authenticode on Windows and notarisation on
        macOS, a Homebrew tap and a Debian package, each built from the
        same reproducible release. Shipped: a Debian package built in the
        release workflow from the release binaries, a Homebrew tap in
        this repository that works the moment the formula is committed,
        and the signing and notarising steps, which run once the
        maintainer's certificate and Apple membership are in the secrets.
        A PKGBUILD and winget manifests were written too and removed
        again in 0.12.2: both needed a push to somebody else's index
        before anyone could install anything, neither had been pushed,
        and each cost a regenerated file per release for nothing. Both
        platforms take the one file for them from the release page.
        docs/design/distribution.md says where each channel stands.
54. [x] **Contributor guide and FAQ** (S). How to build, test and propose
        a change; a FAQ for people who are not developers, written from
        the questions the first users ask. Shipped as CONTRIBUTING.md and
        docs/FAQ.md; the FAQ starts from the questions a messenger like
        this is asked and grows with the ones that come in.

## Phase 11: 1.0

55. [x] **Independent review** (L). The review of `silver-protocol` and
        the relay promised in item 35, by someone who did not write
        them, its findings fixed and published with the report. Under
        way: the review of the 0.10.0 line reported 76 findings and is
        published whole as
        [docs/audits/2026-09-security-audit.md](docs/audits/2026-09-security-audit.md),
        with what was found when each was checked against the code and
        what is done about it in
        [docs/design/audit-response.md](docs/design/audit-response.md).
        0.10.1 carried the Critical finding, the ten Highs and the
        Mediums that share their code; 0.11.0 carries the rest of the
        Mediums, the Lows and the Informational findings; item 57
        carries what needs a format change. Done: 72 of the 76 are
        fixed and out, and the four that are left — a message's own id
        inside the authenticated body, rollback protection for the
        key-bearing files, the identity key bound into the v4
        handshake, and history file names under an HMAC — are item 57.
56. [ ] **Stable** (S). Protocol v4 frozen and documented as such, a
        support policy for what a stable release promises and for how
        long, and the first 1.0 release.
57. [ ] **What the review left for a format change** (L). Settled in
        [docs/design/format-changes.md](docs/design/format-changes.md):
        the two on-disk changes go together in one release with one
        migration and need no peer coordination, the two wire changes go
        in as optional fields for a release before anything requires
        them, and SM-P-04 is a decision rather than a change — binding
        the identity key freshly costs v4 the deniability it exists for,
        so the note puts the two properties side by side and leaves the
        choice. Its minimum, correcting the threat model, is done: that
        document said the Diffie–Hellman key only decrypts, and has said
        since 0.15.0 that from v4 it impersonates too. The four
        findings of the report's section 13.3 that 0.11.0 could not
        take, each with a design note before code: a message's own id
        inside the authenticated body (SM-P-14); rollback protection for
        the key-bearing files (SM-C-24); the identity key bound into the
        v4 handshake, which today makes the long-term Diffie–Hellman key
        enough to impersonate (SM-P-04); history file names under an
        HMAC rather than the contact's id (SM-C-25). With them, the
        defence in depth that section suggests beyond the fixes already
        out: a device's own counter-signature on its certificate, so an
        account cannot enroll a stranger's key even where the relay is
        the one being lied to (SM-R-01 is fixed; this closes the shape
        of it). Each changes a wire or an on-disk format, so each waits
        for the version that may.
58. [x] **Updating in place** (M). `silver update`: one command that
        finds the newest release, downloads the client for this
        platform, checks its SHA-256 against the digest the release API
        gives and against `SHA256SUMS`, makes the downloaded binary say
        its own version, and renames it over the running one, keeping
        the old one for `silver update --rollback`. A binary a package
        manager owns is refused with that manager's command instead.
        Nothing automatic: `update-check` is off unless turned on, and
        even on it only prints a line. The release gains a per-target
        `silver` and `silver-relay` asset so an update fetches the
        client alone rather than the archive, and a keyless signature
        over `SHA256SUMS` made by the release workflow and recorded in a
        public transparency log — no key for anyone to hold. Design note
        [docs/design/updates.md](docs/design/updates.md); what it does
        not defend against is in its section 8 and the threat model.
        Done: the command, `/update`, the opt-in daily check, the
        per-target assets, and tests that a tampered digest, a
        disagreeing `SHA256SUMS`, an unsigned release, a redirect off the
        host and a package-managed binary are each refused with nothing
        left behind.
59. [x] **Desktop notifications that reach the desktop** (M). Item 15
        raised them through the terminal alone (OSC 777, 9 and 99), which
        the common terminals ignore, so on Windows Terminal, Terminal.app
        and every VTE terminal `all` was a bell and nothing more. The
        client asks the operating system itself where the terminal will
        not: the session bus on Linux through the `zbus` already linked,
        `osascript` on macOS, a WinRT toast on Windows; the terminal path
        stays for the terminals that raise one and for SSH, and the
        sequences pass through tmux. The notification says `New message`
        and nothing else, ever — no name, no id, no content — enforced by
        a raising call that takes no text. Design note
        [docs/design/notifications.md](docs/design/notifications.md).
        Done in 0.13.0: the route from the environment with `/notify
        terminal` and `/notify desktop` to force one, the three
        platforms, the tmux wrapping, a failed service left alone for ten
        minutes, and tests that every notification at a pty says the one
        text and that each row of the environment table picks its path.
        The desktop paths compile on every CI platform; that a toast
        appears is checked by hand and recorded in `docs/TERMINALS.md`.

60. [x] **Requests, and naming people** (M). A contact's id could not be
        copied and the header that shows it could not be selected, so
        every command that wanted an id was hard to use; the numbers
        `/accept` and `/block` took lived in one Requests pane and shifted
        as it changed; a request could not be dealt with from where it
        was read; and there was no way to turn a stranger down short of
        blocking them. A request becomes a chat not yet answered: an
        entry of its own in the sidebar, showing the stranger's id and
        nothing they chose, where `/accept`, `/decline` and `/block` take
        no argument and a typed reply accepts. Decline is *not now* where
        block is *never*: the sender learns nothing either way, and a
        declined stranger who writes again reappears without ringing.
        The bell and the desktop notification are raised for a message
        received and for nothing else. One resolver -- alias, id, unique
        id prefix, or the selected chat -- under every command that names
        a person; `/copy id <who>`, `/whois`, a click on the title that
        copies the id, Tab completion of aliases and group names; numbers
        that hold still. Design note
        [docs/design/requests.md](docs/design/requests.md). Done in
        0.14.0: the chat list is a list of panes with the waiting entries
        at its end and scrolls to the selection; `/requests`, `/whois`,
        `/copy id <who>`, `/decline`, the quiet rule for a declined
        stranger, the ringing rule, and the resolver under every command
        that names a person, with unit tests for each and a terminal test
        that walks a request through decline, the quiet return, a typed
        reply, `/whois`, the completed `/copy id`, the title click,
        `/block` and `/unblock`.

61. [x] **What the keys are worth on your own computer** (S). An outside
        review dumped the memory of an unlocked 0.14.0 client on Windows
        11 from an ordinary program of the same user, with no elevation,
        and read the keys. Reading an unlocked client is the documented
        limit and no software on that machine can close it, but the
        review showed the limit was not the same on every platform and
        that two other things were wrong. `harden_process` had no Windows
        branch at all, so what took root on Linux took nothing on
        Windows; the process now carries an access list that refuses
        being opened for reading, which is cost rather than prevention,
        since the owner of a process may rewrite it. Erasing a device
        left its wrapping key in the key store, where a copy of the
        directory taken beforehand still had something to be opened
        with, and a key made for a change that then failed was left there
        too; both are removed now. The threat model gains the actor this
        describes, says what each platform manages and what it leaves,
        and names swap and hibernation as a path out of memory that
        full-disk encryption answers and this program does not.

62. [x] **What the second audit found** (M). A second outside review, run
        adversarially over the whole tree and reconciled across three
        rounds, found no cryptographic break: every chain built against
        the protocol failed against a check that was already there. What
        it did find clusters in the places where a command does more than
        it looks like, where a promise the documentation makes is kept
        only on one path, and where the relay's bookkeeping disagrees with
        itself. The findings and this project's answers are published in
        `docs/audits/` when the work is done, unedited, as the first
        audit's were — including the three of the reviewer's claims this
        project argued down and the two the reviewer argued back.
        The first piece is done: `/devices link` no longer signs a device
        certificate on one pasted line. It says what the device would be
        given — that the identity signs for it and it thereafter reads and
        writes as the account — and waits for a short second line, which
        is where the paste guard belongs, because a link is pasted by
        design and a guard whose remedy is "type it out" cannot be met on
        one. `/relay` and `/group join` ask the same way; `/send` takes
        the guard alone, its argument being a path a person can type; and
        a group alias is filtered on the way in and out, as a contact's
        always was. `docs/design/consequential-commands.md` records which
        commands ask, which are guarded, which are neither, and why the
        list is meant to stay short.
        The second is done too: in reader mode a line break inside a
        message bought its sender a journal line of their own, which a
        screen reader hears as another person speaking, or as a warning
        this program never made. The filter that exists for exactly this
        was applied at two call sites and missed by two others, so it
        moved to the one door every line goes through, and took the
        invisible and bidirectional characters with it. Reader mode now
        has the mirror of the invariant test the full mode has had since
        0.10.0.
        The third closes the key store paths 0.15.0 left half shut. The
        key is written before the vault that needs it, so dropping an
        unneeded one on the failure path only worked if the process lived
        to take that path; a crash in the window left a key for good. The
        undecided name is written down first now, and the next start
        settles it -- the same for removing the protection and for erasing
        the device, which had the same gap on the other side. And the
        check that decides no longer reads "I cannot tell" as "no": that
        would have deleted the key opening every file in the directory.
        The fourth is the updater keeping a promise it had made twice in
        writing and never in code: a build with no `minisign.pub` skipped
        the signature and installed whatever the release host served. It
        refuses now, before fetching. The tests gained a signing key of
        their own, so the accepting half of the check is exercised too --
        with the project's key they could only ever show refusals.
        The fifth is saying when a peer's post-quantum protection goes
        away. Showing what a new session is was never enough: a classical
        session with somebody who used to have post-quantum ones reads
        exactly like one with somebody who never did, so a stripped bundle
        looked ordinary. The best level reached with each contact is kept
        with the contact and a fall is reported, with both readings --
        their older client, or somebody taking the keys out in transit --
        since the client cannot tell those apart.
        The sixth is two on the relay. An hourly limit of zero allowed one
        an hour rather than none, so `--registrations-per-hour 0` left
        registration open at a trickle -- a limit wrong in the only
        direction that matters. And the expiry sweep listed its victims in
        a read transaction and removed them in a later write one, so an
        acknowledgement landing between the two was charged for twice and
        the difference came out of the mail still queued. It runs in one
        write transaction now.
        The seventh is a batch of the same shape: things bounded in one
        place and not in the one next to it. A refused frame wrote a log
        line, so sitting on a rate limit filled the operator's disk; the
        metrics listener never called the helper that gives the main
        listener its header-read timeout, so a silent connection held a
        socket for ever; and `silver.log` grew without limit while being
        a record of who this device talked to.
        The eighth is the ratchet body being the one body version that
        went from JSON to a value unchecked, while v0/v1 and v5 had
        validated at the boundary for versions. Its rules existed, further
        in, where only the bodies that got that far met them.
        The ninth is the Windows swap, where the path is briefly empty
        because the operating system will not replace a running image any
        other way. That cannot be closed, so it is made survivable: the
        recovery copies when it cannot rename, and says what to rename by
        hand when it can do neither. Rollback shared the window and now
        shares the recovery.
        The tenth is two residuals: a system trust store that will not
        load is now a warning rather than a debug line nobody sees, since
        falling back to Mozilla's list alone drops this machine's own
        decisions about what to distrust; and the threat model no longer
        implies the data directory's Unix modes apply on Windows.
        The eleventh ends the unbound login's nine-release grace period --
        it is refused by default now, with `--allow-unbound-auth` for a
        relay that still has clients older than 0.6.0 -- and fuzzes the
        two parsers the updater runs before any signature is checked.

        All twelve are done and in 0.15.0. Publishing the review itself
        and the response note is held back for the maintainer to review
        first, so this item is ticked for the code and not for the
        disclosure.
63. [ ] **The second review's remainder** (M). Eight findings the
        September 2026 review left open, none of them a way for anyone to
        read a message or forge one, all of them listed with what leaving
        each costs in
        [docs/design/audit-response-2.md](docs/design/audit-response-2.md)
        section 4. Six are **done** and in 0.15.0: **I-1**, the claim in
        `docs/design/updates.md` that the swap is tested under a kill
        when no such test existed — the worst of them, being a false
        statement about what is tested, and two tests now stand behind
        it; **L-5**, the mailbox limits that wrapped on multiply and
        silently meant "always full" at zero; **L-16** and **L-8**,
        validation at the protocol boundary rather than only where a
        value is used; **L-6**, the uncapped transparency log; **L-10**,
        secrets that serialized as plaintext for anything persisting them
        outside the vault; **L-13**, homoglyph names. **L-1**, locking
        key buffers out of swap, is declined below, as is the remainder
        of a finding otherwise closed — an enumeration sweep of
        `data-key-*` entries for keys orphaned by versions before 0.15.0.

        **L-14** is done too, and wider than the report asked. Its five
        remaining parsers — the hand-rolled HTTP response head, with the
        redirect check beside it, `transparency.rs`, `vault.rs`,
        `linking.rs` and `Pin::parse` — each got a target that asserts
        the property it exists for rather than only running it: a page
        the transparency log refuses leaves the head where it was, a
        vault file opens under its own name and no other, a pin prints
        what it parsed, a device link prints the device somebody is meant
        to compare. Writing the first found a defect worth the exercise:
        `split_https_url` read `evil.test@api.github.com` as a host,
        which ends with `.github.com` and so passed the redirect check
        while naming another host to anybody reading it. Refused now.

        **What is left in this item** is one remainder. **H-1**: macOS
        release builds are unsigned unless notarization secrets are set,
        so the hardened runtime that would restrict a same-user attach is
        absent; ad-hoc signing with `--options runtime` is the cheap
        version of it, and belongs here only once somebody has checked on
        a real macOS that it restricts what it is supposed to, rather
        than on the strength of the manual page.

        **Two of those are declined, on one decision.** L-1 needs `mlock`
        or `VirtualLock`, and the key-store sweep needs `CredEnumerate`
        and its equivalents, which `keyring` does not expose on any
        backend. Both are system calls, and `silver-client` — the crate
        that holds the keys — is `#![forbid(unsafe_code)]`, which the
        September 2026 review named among the reasons the tree reads as it
        does. Each would therefore cost either that property in the crate
        that most wants it, or a dependency whose whole job is to hold the
        unsafe (`region`, `memsec`, or `secmem-alloc`, the last by the
        author of the `secmem-proc` this project already links on
        Windows). **Neither is worth it, and neither will be done.** A Low
        about swap — which full-disk encryption answers, and which pinning
        the key alone would not close anyway, since the plaintext beside
        it stays pageable — and a key left behind by a version older than
        0.15.0, removable by hand, do not buy back an audited-away
        invariant across every secret this program handles. If that trade
        ever changes it will be because something larger wants it, not
        these two.
        The review's other remainder, a non-zero `lock_after_minutes`
        default, is **decided against**: locking after an idle spell is
        the user's choice, not something to switch on for everybody. It
        would shorten the window the review demonstrated, and it would
        also lock people out of a program they left open on purpose. The
        setting is there, `/lock` is there, and the threat model says
        what an unlocked client is worth; which of those to use is the
        person's call.

64. [ ] **The identity key somewhere the memory is not** (L, undecided).
        The one place where taking a key out of the process would buy
        something. Everything else in memory is the conversation itself,
        and hiding the key that decrypts it from a program that can read
        the decrypted text achieves nothing; the identity key is
        different, because it signs, and a copy taken once impersonates
        the account for as long as the key stands, outliving the lock and
        the session. Keeping it in a token or a platform enclave would
        bound a memory dump to the session it was taken in.
        What stops this being a small change is the algorithm. The
        identity key is Ed25519, and it signs bundles, prekeys,
        revocations, successions and MLS credentials; the Secure Enclave
        holds P-256 only, TPMs commonly the same, and PIV tokens only in
        recent firmware, so hardware custody means either a second
        signature algorithm across the protocol or a hybrid, and every
        peer has to accept it. That is a protocol change with a design
        note in front of it, not a hardening pass. Worth doing only if
        the answer to "a key stolen once, for good" is judged to be worth
        that, and the revocation certificate and `/rotate` are the cheap
        answer standing in the meantime.
        The September 2026 review sharpens the question without settling
        it. It read the *Diffie–Hellman* key out of a running client's
        memory in six seconds, and the identity key sits in the same
        file — so "a key stolen once, for good" is demonstrated rather
        than hypothetical. But what hardware custody would buy is bounded
        by what the hardware holds: enclaves and most tokens do P-256,
        the identity key is Ed25519, and every peer would have to accept
        a second algorithm or a hybrid. That is a protocol change with
        its own design note, for a benefit that only bites after a
        compromise the revocation certificate already answers. Still
        undecided, and still not a condition of 1.0.

## Continuous

- [ ] Every new parser gets a fuzz target; the terminal matrix, the
      reproducible-build check and the live test against the deployed
      relay stay green.
- [ ] The threat model and the assessment are re-read at the end of each
      phase and changed where the phase changed the facts.
