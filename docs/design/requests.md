# Design note: requests, and naming people

Roadmap item 60. Written before the code, as the record of the decisions;
what ships is described in README.md when the code lands. Where this note
and the code later disagree, the code wins and this note is corrected.

The problem, in the maintainer's words: there is no way to copy a
contact's id, and the chat header that shows it cannot be selected, so
every command that wants an id is hard to use; the numbers that `/accept`
and `/block` take exist only in the Requests pane and shift as the list
changes; a request cannot be dealt with from where it is read; and there
is no way to turn a stranger down short of blocking them. Underneath all
four is one thing: the client makes a person *say* an id where it should
let them *point* at one.

## 1. Decisions

**What a request is.** A chat you have not answered yet. Each stranger
who wrote gets an entry of their own in the sidebar, under a `requests`
divider, drawn dim and marked as not a contact; the entry shows their id
and nothing a stranger chose. Selecting it shows every message they
sent, not three. The Requests pane -- one list of everyone waiting --
goes; `/requests` prints that list into the System pane instead.

**Group invitations.** The same. An invitation is an entry under the
divider, labelled `invitation`, showing the group's name, who invited
you, how many are in it and when it came. Only strangers' invitations
wait (a contact's is taken at once, as today), so the inviter is always
shown by id. The name is the stranger's word for the group: sanitised as
today, and never the entry's identity on its own -- the label and the
inviter's id are.

**The commands on an entry.** `/accept`, `/decline` and `/block` take no
argument there and act on the entry you are looking at. Typing text and
pressing Enter on a request accepts it and sends the text, because
answering someone is accepting them. On an invitation, Enter with text
says to `/accept` first. With an argument the same commands work from
anywhere: a number, an id prefix, or an alias where one exists.

**Decline.** *Not now*, where block is *never*. The request and its held
messages are dropped and the sender is told nothing, exactly as with
block. If they write again the request reappears, quietly: no bell, no
notification, no toast, because you already said not now and a stranger
must not be able to ring you by repeating themselves. The quiet flag is
remembered on disk for the id and cleared when you accept or block them.
It is this device's alone: a block is synced to your other devices
because it is a fact about a person; a decline is a mood, and syncing it
would need a wire change for little. An invitation is declined as today,
and a declined inviter's later invitations are quiet in the same way.

**What rings.** The bell and the desktop notification are raised for a
message received, and for nothing else: a message in a chat, a message
in a group, a stranger's first message (that is what a request is), a
message reaching this device through a linked one. Not for an
invitation, for being added to a group, for joining by link, for a
device linking, for a key change, or for an update. Those go to the
System pane and the sidebar badge, and the window title's count still
includes what waits. This narrows the first decision of
`docs/design/notifications.md`, which listed invitations and group adds
among the events that ring; that table is corrected to point here.

**Naming a person.** One resolver, used by every command that names one:
an alias (case-insensitive), the full id, or a prefix of the id that
matches exactly one person; and with nothing given, the selected chat.
`/block`, `/unblock` (against the blocked list), `/accept` and
`/decline` (against what waits), `/go`, `/group add`, `/group remove`,
`/group admin`, `/copy id` and `/whois` all use it. An ambiguous prefix
says which people it matched and does nothing.

**Getting an id out.** `/copy id` copies yours, as today; `/copy id
<who>` copies theirs. `/whois [who]` prints their id, alias,
verification state and how messages with them are protected into the
System pane, as ordinary selectable text. A click on the title of a
contact's chat or of a request copies that id to the clipboard, with a
toast saying so.

**Completion.** Tab after a command that names a person or a chat cycles
through contact aliases and group names, the way it cycles through paths
after `/send`. The command table says which arguments those are, so the
help, the status line and the completion agree.

**Numbers.** They stay, for reader mode and for whoever prefers them,
and they hold still. A request or invitation gets its number when the
client first sees it, in one sequence for both kinds, and keeps it until
it is handled; a number is not reused within a run. `/accept 3` takes
entry 3 whichever kind it is; `/accept g3` takes it only if it is an
invitation, so an old habit cannot accept a person by mistake. The
number is in the entry's title, in the arrival line, and in `/requests`.

## 2. Goals and non-goals

Goals: no id ever has to be typed or copied to do the everyday things; a
request is dealt with from where it is read; a way to say no that is not
a block; a stranger cannot make a terminal ring more than once until they
are accepted; the terminal rings for messages and for nothing else.

Non-goals: names chosen by strangers, which are never shown as a name;
syncing declines between devices; any change to what the relay sees or
holds -- the relay and the protocol are untouched, and a client on 0.13.0
talks to one on 0.14.0 as before.

## 3. The sidebar, and what a request looks like

The client keeps a list of panes, in order: `System`, one `Thread` per
contact, one `Group` per group, then, when anything waits, one `Request`
per stranger and one `Invitation` per invitation in the order they were
first seen. The selection is an index into that list. The arithmetic
that today derives the selected contact or group from the index and the
counts goes, and with it the case where an index past the contacts is
taken for a contact. The sidebar draws a divider row, ` requests `, dim,
before the first waiting entry; the divider is not a pane and a click on
it does nothing. The sidebar scrolls so the selected entry is always on
screen (today it clips when the list is taller than the terminal, which
fifty waiting strangers would make it).

When an entry is handled the selection goes to the chat it became, on
accept, and to System on decline or block; when the list changes for any
other reason the selection stays on the same pane if it still exists.

A request entry reads `? 29cHxz2f…` -- the mark says stranger -- with the
number of messages held as its badge. Its title is

    request 3 · not a contact · 29cHxz2fipYEUQacUJH817ZNwXQ7cqoQwY8ZTuWe3Nsa · 4 messages

(the label before the id, so that a narrow pane, which cuts the end of a
title, never cuts the label)

and its status line

    /accept · /decline · /block · typing a reply accepts · F1 help

The message pane shows every held message with its time, laid out as a
chat, with no delivery marks since nothing was sent, and a file they
announced shown as waiting for acceptance, as it is today. `/alias`,
`/verify`, `/send`, `/react` and the rest of what a chat allows say to
accept first.

An invitation entry reads `? invitation · <name>`. Its title is

    invitation 4 · <name> · from 8PeGavsi… · 7 members · today 14:02

and its status line `/accept joins · /decline · /block the inviter · F1
help`. Its pane says who invited you, with their full id, and how many
members the group has, which is all the client knows before joining.

On arrival, the System pane says

    Request 3 from 29cHxz2f… (29cHxz2fipYEUQacUJH817ZNwXQ7cqoQwY8ZTuWe3Nsa) is in the sidebar; open it, or /accept 3, /decline 3, /block 3.

with a toast and, unless the id was declined before, the notification.
An invitation's arrival line is the same shape and rings nothing.
`/requests` prints one line per waiting entry with its number, in the
same order as the sidebar.

Reader mode reads an entry as `Request 3 from 29cHxz2f…, 4 messages held;
/accept, /decline or /block.` followed by the messages, and an invitation
as `Invitation 4 to <name> from 8PeGavsi…, 7 members; /accept or
/decline.`; `/requests` reads the list.

## 4. Naming a person

The resolver lives in the client's app, not in the groups code where it
grew, and is the one place that turns a word into a person: an alias,
compared without case; a full id; or a prefix of an id that exactly one
contact -- or, for the commands that act on what waits, exactly one
requester -- starts with. Given nothing, it is the selected chat, when
that is a contact or a request. Given a prefix that several people share
it names them and does nothing: `nima and nimrod both start with "ni"`.
A number is tried first where the command takes one.

The command table gains `/requests`, `/whois [who]`, and the argument
words `[n|who]` for `/accept`, `/decline` and `/block`, `<who>` for
`/unblock`, `[id [who]|link]` for `/copy`. Each entry says what kind its
argument is -- nothing, a path, a person, a chat -- and Tab completes
accordingly; `/group add`, `/group remove`, `/group admin add|remove` and
`/copy id` complete a person at their second word. Completion of a chat
offers aliases, group names and the words `system` and `requests`.

A click on the title row of the message pane, when the pane is a
contact's chat or a request, copies the id there to the clipboard through
the same path `/copy` uses, with the same toast. On a group's chat the
title is not a click target; `/group info` has what a group is.

## 5. What a stranger learns and can do

Nothing new is sent. Reading held messages sends no receipt; declining
sends nothing; blocking sends nothing; to the sender the three are
indistinguishable from silence, which `docs/THREAT_MODEL.md` ("Stranger
who knows your id") already promises and a test now pins.

A stranger can ring the terminal once, with their first message. After a
decline they cannot ring it again until they are accepted; after a block
nothing of theirs arrives. Today the choice was between ringing once and
never hearing from them, so decline closes the small nag that a repeated
request was.

A stranger has no name in the client; their id is their name, and no
alias can be set on a request. A group name in an invitation is
stranger-chosen text: sanitised as it is today, shown under the
`invitation` label beside the inviter's id, never as the entry's name on
its own. A request entry is never mistakable for a contact: the divider
above it, the `?` mark, the dim style, `not a contact` in its title.

The quiet list is on disk beside the requests: the ids you declined, with
the time, at most two hundred, the oldest dropped first. It reveals who
wrote to you and was declined, as the requests file already reveals who
wrote; it has the same permissions, and a thief with the disk learned
that from the requests file already.

## 6. Testing

Unit tests: the resolver on aliases, ids, prefixes, an ambiguous prefix,
nothing given with and without a selected chat; numbers held across a
handled entry and not reused; the quiet flag set by decline, cleared by
accept and block, and honoured on arrival; the pane list in order and
the selection following an accepted entry to its chat; the completion
candidates for each argument kind; and the ringing rule as a table --
each event against whether it announces, the way the notification note
tested each row of its environment table.

At a pty: a stranger's message becomes an entry Shift-Tab reaches, whose
messages are all readable; bare `/accept` on it opens the chat with the
messages in it; `/decline` on it, then a second message from the same
stranger, brings the entry back with no bell and no notification
sequence in the output; `/block` on it drops the third; Enter with text
on a request accepts and delivers the text; `/accept 29cH` by prefix from
System; `/copy id nima` and `/whois nima`; a click on the title copies;
`/block ni` then Tab completes the alias; `/requests` lists the numbers;
an invitation is an entry that bare `/accept` joins, and its arrival
rings nothing while a message does. The shared `befriend` step in the
harness keeps `/accept 1`, which still works, so the other tests do not
change for this. Reader mode reads an entry and `/requests`.

## 7. What ships, and in what order

One release, 0.14.0, since `/block` and `/accept` gain a meaning and the
ringing rule narrows. In order: the pane list and the scrolling sidebar;
requests and invitations as entries with the bare commands; decline and
the quiet rule; the ringing rule; the resolver under every command that
names a person; `/copy id <who>`, `/whois`, the title click; completion;
the numbers; the documents.
