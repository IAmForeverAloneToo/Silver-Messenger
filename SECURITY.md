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

Release binaries are reproducible and signed; the README section
*Verifying a release* explains how to check a download against the
published hashes, the maintainer's signature and the build provenance, and
how to rebuild the tagged commit and compare. Dependencies are checked
against the RustSec advisory database on every push (`cargo audit`,
`cargo deny`).

## How the code is assessed

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) says what is protected
against whom and where the gaps are.
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) walks the OWASP
ASVS Level 2 controls and says, for each that applies, whether the code
meets it and what closes any gap. Both are maintained by the author; an
independent review of `silver-protocol` and the relay by someone who did
not write them is planned before 1.0 and has not happened yet. If you are
in a position to do one, the maintainer would like to hear from you.
