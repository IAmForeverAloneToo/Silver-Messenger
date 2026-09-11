# Security policy

Silver Messenger is end-to-end encrypted messaging that people run for
themselves. A flaw in it can expose what someone said in confidence, so
reports are taken seriously and handled quietly until a fix is out.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's vulnerability reporting: on the
repository page, *Security* → *Report a vulnerability*. That opens a draft
advisory only you and the maintainer can see. If that page is not available
to you, open an ordinary issue that says only "security contact requested"
with no details, and you will be given a private channel.

What helps: which binary and version (`silver --version`,
`silver-relay --version`, or the commit), what an attacker needs to be
(see the actors in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)), the
steps or a proof of concept, and what it gets them. A minimal reproduction
beats a long write-up; a guess at the fix is welcome but not needed.

What to expect:

- An acknowledgement within 7 days.
- An assessment, and either a fix or a plan with dates, within 30 days of
  the report; a fix released within 90 days at the latest. Problems that
  let a relay or a network observer read content, or let anyone
  impersonate a user, come first.
- You are told when the fix ships and credited in the advisory and the
  changelog unless you ask otherwise.
- No bounty: there is no money behind the project. There is public
  thanks, and a fix.

Coordinated disclosure is the request: please keep the details private
until a fixed version is available, or 90 days have passed, whichever
comes first. Advisories are published as GitHub Security Advisories on
this repository and noted in [CHANGELOG.md](CHANGELOG.md).

Reviews done of the project are published the same way, whole, once
their findings are fixed or scheduled: [docs/audits/](docs/audits/)
holds the reports, and the answer to each finding — what the code was
found to do, what is done about it, in which release — is the design
note beside it.

## What is in scope

Everything this repository ships: `silver` (the terminal client),
`silver-relay`, the `silver-protocol` and `silver-client` crates, the
release and deploy workflows, and the relay installer. The reference relay
at `test-silver.duckdns.org` is a test instance; treat it as in scope for
protocol and relay bugs, but do not run load or denial-of-service tests
against it.

Reports that matter most, roughly in order:

1. Anything that lets someone other than the recipient read a message or
   a file, or that lets someone send a message that verifies as someone
   else's.
2. Anything that lets a relay operator, a network observer or a stranger
   learn more than [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) says they
   can.
3. Anything a peer can send that crashes, hangs or takes over a client,
   reaches the terminal unescaped, or writes outside `downloads/`.
4. Relay resource exhaustion that the documented limits should have
   stopped (limits are listed in the threat model and `PROTOCOL.md`
   section 7.4).
5. Problems in the build and release path: an action, a dependency or a
   workflow that could put something into a release the source does not
   contain.

### What memory protection is, per platform

A review in September 2026 recovered the data key of an *unlocked* client
from an ordinary same-user process on Windows 11, in seconds and with no
elevation. That is the limit the threat model already named, and no
software on the machine can close it; what the client does is raise the
cost, and it differs by platform:

| Platform | What the client does | What it leaves |
| --- | --- | --- |
| Linux | No core file; the process is not dumpable, so a same-user process may neither trace it nor read `/proc/<pid>/mem` | Root, and anything already attached |
| Windows (0.16.0) | No core file; the process object carries a restricted access list, so opening it for reading is refused | An attacker who rewrites that list first, which a process's owner may do; and an administrator |
| macOS | No core file. From 0.16.0 release builds carry an ad-hoc signature asking for the hardened runtime, which is **not verified** to restrict anything: treat macOS as having no protection here until somebody has checked it on a real Mac | A debugger run by the same user, which macOS allows for a program it started |

Pages of an unlocked client may also reach swap or a hibernation image;
full-disk encryption is what answers that, not this program. Reading an
unlocked client is therefore **not a vulnerability** — it is the
documented limit. `/lock`, the idle lock and quitting are the boundary
that does hold, because they take the client down rather than mark it
unreadable. A way *past* those, or key material readable while the
client is locked, is very much a vulnerability.

Not vulnerabilities, because the design does not claim otherwise: things
listed under *Out of scope* or *Gaps* in the threat model (a compromised
operating system or terminal, denial of service against a relay by sheer
volume, hiding that someone uses the program at all, deniability), a
weak passphrase chosen by the user, and a relay operator seeing the
metadata the threat model says they see.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `main` | Yes |
| The latest release (`0.x.y` with the highest `x`) | Yes, as a patch release |
| Earlier releases | No: upgrade. Clients and relays interoperate across the last two minor versions, so an upgrade does not need everyone to move at once. |

While the major version is 0 there is one supported line at a time. A
fix that changes the wire protocol is released together with a compatible
client and relay, and the changelog says what stops working with older
peers.

## Verifying what you run

Release binaries are reproducible and carry GitHub's build provenance;
`SHA256SUMS` is not signed by the maintainer today, and the README
section *Verifying a release* says so and explains how to check a
download against the published hashes and the attestation, and how to
rebuild the tagged commit and compare. Dependencies are checked
against the RustSec advisory database on every push (`cargo audit`,
`cargo deny`).

## How the code is assessed

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) says what is protected
against whom and where the gaps are.
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) walks the OWASP
ASVS Level 2 controls and says, for each that applies, whether the code
meets it and what closes any gap. Both are maintained by the author.

An independent adversarial review of the 0.10.0 line, by people who did
not write it, reported 76 findings: one Critical, ten High, 24 Medium, 30
Low and eleven Informational. It is published whole and unedited as
[docs/audits/2026-09-security-audit.md](docs/audits/2026-09-security-audit.md),
and what was found when each finding was checked against the code, what
was done about it and where a suggested fix was not taken is in
[docs/design/audit-response.md](docs/design/audit-response.md), finding by
finding. 0.10.1 carried the Critical, the Highs and the Mediums that
shared their code; 0.11.0 carried the rest, and the four that changed a
wire or an on-disk format went out in 0.16.0 and 0.17.0 — all 76 are
closed. The changelog's `Security` entries say what each finding was in
the release that fixed it.

A second adversarial review, of the 0.14.0 line, reported 29 findings
after three review rounds: two High, seven Medium, 18 Low and two
Informational, no Critical and no cryptographic break. It is published
whole as
[docs/audits/2026-09-second-security-audit.md](docs/audits/2026-09-second-security-audit.md),
with one class of edit the report itself names — identifiers of the
maintainer's own machine and infrastructure redacted from an appendix
and one finding — and its response, finding by finding, is
[docs/design/audit-response-2.md](docs/design/audit-response-2.md).
Both Highs, every Medium and most of the Lows went out in 0.16.0; what
is declined is declined with the argument written down, in that note's
section 4, and the one thing still open — watching the macOS hardened
runtime refuse an attach on a real Mac — is named there and in the
roadmap rather than assumed.

A further review is welcome. If you are in a position to do one, the
maintainer would like to hear from you.
