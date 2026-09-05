# Questions people ask first

Short answers, for people who want to use Silver Messenger rather than
build it. The long answers are in the README (how to use it), the
threat model (`docs/THREAT_MODEL.md`: what it protects against and what
it does not) and the operator's guide (`docs/OPERATING.md`: running a
relay). Where an answer here and one of those documents differ, the
document is right and this page needs a fix.

## What is it?

A messenger that runs in a terminal window: you type, the other person
reads, and only the two of you can read it. It comes as two programs,
the client `silver`, which you run, and the relay `silver-relay`, which
somebody runs on a server so that messages can wait for you while you
are offline. There is no company in between and no account with anyone:
your identity is a key made on your computer.

## Do I have to run a relay?

Somebody does. A relay is a small server program that stores encrypted
messages until they are collected; one relay is one network, and
everyone you talk to uses the same one. If a friend or a group you
belong to runs one, use theirs (`silver --relay wss://their.relay/ws`,
remembered after the first time). If not, `docs/OPERATING.md` says how
to run one on a cheap virtual machine in an evening; the installer does
most of it.

## Can I talk to someone on a different relay?

No. One relay is one network, on purpose: there is no federation and no
directory, so nothing about you leaves the relay you chose. If two
groups of people want to talk, they use the same relay.

## What does the relay see?

Envelopes: who a message is for, when it was sent, and its size, which
the client rounds up so that a short message and a long one look alike.
Not the text, not the files, not who reacted to what, not who is in a
group; every message is encrypted on your computer and decrypted on the
other person's, and a group message looks to the relay like ordinary
messages to people. The relay's operator can refuse to serve you (ban
your id) and can see that your address talked to the relay at a given
time; the threat model lists exactly what a relay operator, a network
observer and the others can and cannot do.

## How do I know I am talking to the right person?

Your id is your public key, 44 characters long. If you got a person's id
from them by another way (in person, over a call, a QR code from their
screen), you have already checked it. `/verify` shows a safety number
you can compare aloud with them; `/verify ok` marks the contact checked.
The relay keeps a public log of every key it has handed out, and clients
check it against each other, so a relay that gave two people different
keys for the same id would be caught.

## Is it secure? What does "secure" mean here?

Messages between two people are encrypted end to end with keys that
change with every message, so a key stolen tomorrow does not open
yesterday's messages (forward secrecy), and the key exchange includes a
post-quantum step, so a recording kept for a future quantum computer
does not help either. Groups run on the Messaging Layer Security
standard (MLS) with the same kind of hybrid. What is not protected: the
computer you run it on (a program that can read your files can read your
messages), and the fact that you talk to the relay at all. The threat
model is the honest list, including the gaps that remain, and the code
has not yet had an independent review; the roadmap says when it will.

## What happens if I lose my laptop?

If your data directory was under a passphrase (`silver
--set-passphrase`) or the computer's key store, the thief has encrypted
files and nothing else. If you run the identity on another computer as
well (see the next question), `/devices remove <n>` there cuts the lost
one off for good; contacts see nothing change. Without another device,
`/revoke confirm` from a restored backup tells your contacts the
identity is dead, and you start a new one.

## Can I use it on my desktop and my laptop?

Yes. On the new computer run `silver --link`; it prints a link and a QR
code. On the one you already use, `/devices link <link>` takes it in:
contacts, groups and the last thirty days of history arrive, and from
then on every message reaches both. Contacts see one person with one id.
Your identity key stays where it was made; the new device has keys of
its own that the first one vouched for.

## Is there a phone app, or a window I can click in?

Not before 1.0. The client is a terminal program on purpose: it runs
over SSH, on a server, in a screen reader, on a fifteen-year-old laptop,
and it is small enough to be checked. It supports the mouse, colours,
notifications and a reader mode for screen readers (`silver --reader`).
On Windows use Windows Terminal rather than the classic console.

## I forgot my passphrase.

Nothing can recover it; that is what a passphrase is. A backup made with
`silver --export-backup` (which asks for its own passphrase) restores
the identity and contacts; history is in the data directory, encrypted
under the passphrase you forgot. Choose a passphrase you can keep, and
make a backup after you set it.

## Do messages disappear? Can I unsend one?

`/timer 1d` (from thirty seconds to a week) makes messages in a chat go
that long after they were sent or read, on every device, on its own
clock; `/delete` removes one of your messages for everyone within a day
of sending it and leaves a placeholder. Both are promises the other
person's software keeps, not something cryptography can force: a
person who wanted a copy could have taken a photograph of the screen.
`/delete me` removes any message from your own devices only.

## Where do files go? Is it safe to open them?

Received files are fetched only when you ask (`/get`), unless you turn
on `/files auto` for a contact, and they are saved under
`downloads/` in the data directory under their own name, never
overwriting an earlier one. The client refuses to open executables and
marks downloads the way a browser does, so the system asks before
running anything. `/files encrypt on` keeps received files encrypted on
disk, if the data directory is protected.

## How long does the relay keep my messages?

Until your client has collected them, and for thirty days at most by
default (the operator can set it); after that they are deleted unread.
Your own history lives in your data directory, not on the relay.

## How do I back up, and how do I move to a new computer?

`silver --export-backup <file>` writes your identity and contacts under
a passphrase of its own; `silver --import-backup <file>` restores them.
`silver --export-history <dir>` writes every conversation as text or
JSON. To move for good, copy the whole data directory (it is encrypted
at rest) or link the new computer as a device and remove the old one.

## How do I update, and what breaks?

Releases are on the releases page and through the package managers the
README lists; each carries checksums, a signature and a provenance
attestation you can check. Clients and relays of different versions
talk to each other with what both understand, and a feature that needs
a newer relay says so in the client (groups and devices need a relay on
0.9.0 or later). `docs/UPGRADING.md` says what each version changes for
someone running a relay, and what a rollback leaves behind.

## Something is wrong. Where do I say so?

A bug or a question: the issue tracker on GitHub. A security problem:
`SECURITY.md`, which says how to reach the maintainer privately and what
to expect.

## Is it free?

Yes, and free software: AGPL-3.0. You may use, study, share and change
it; if you run a changed relay for other people, you must offer them its
source under the same terms.
