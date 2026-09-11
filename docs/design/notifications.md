# Design note: desktop notifications

Roadmap item 59. Written before the code, as the record of the decisions;
what ships is described in README.md and docs/TERMINALS.md when the code
lands. Where this note and the code later disagree, the code wins and this
note is corrected.

## 1. Decisions

**What a notification says.** `Silver Messenger` as the title and `New
message` as the text, and nothing else, ever: not who wrote, not their
alias or id, not a group's name, not a device's, not a count, and never
a word of content. Every event that rings raises those same words. Which
events ring is decided in `docs/design/requests.md`: a message received
and nothing else (a message in a chat or a group, a stranger's first
message, a message reaching this device through a linked one). This is
enforced by construction, not by care: the call that raises a
notification takes no text, so there is no parameter through which a
name could reach one. The unread count stays where it is today, in the
terminal's window title, which is not a notification and does not leave
the terminal.

**Where it is raised.** Two paths, chosen from the environment at start.
*Terminal-raised*: the escape sequences the client has always written
(OSC 777, OSC 9, OSC 99), for the terminals that turn them into a toast
and for the one case nothing else can serve, a client running over SSH,
where the desktop is on the other end of the connection. *OS-raised*: a
request to the operating system's own notification service, for the
terminals that ignore the sequences — which are most of them: Windows
Terminal, the Windows console, Terminal.app, GNOME Terminal and every
VTE terminal, Konsole, Alacritty. Today only the first path exists, so
on those terminals `all` produced a bell and nothing more, which is the
bug this note answers.

**Choosing between them.** By terminal, from the environment (section
3). A terminal known to raise the sequences gets those alone; one known
not to gets the OS; one the client does not recognise gets both, because
a second toast on a rare terminal is a smaller failure than none on a
common one. Over SSH, the terminal path alone, whatever else the
environment says: a toast on the relay host or a jump box is a toast
nobody sees. `/notify terminal` and `/notify desktop` force one path for
a setup the detection gets wrong.

**Linux.** The `org.freedesktop.Notifications` service on the session
bus, called through `zbus`, which the client already links for the
Secret Service key store; no new crate joins the tree. Summary `New
message`, empty body, no icon, normal urgency, the service's default
timeout, and a `replaces_id` so a second notification replaces the first
rather than stacking. No session bus, as on a server or in a container:
the call fails once, is remembered as unavailable for ten minutes, and
the bell and title carry on.

**macOS.** A command-line program without an application bundle cannot
use the notification framework: `UNUserNotificationCenter` needs a
bundle identifier and aborts without one. The route every terminal tool
takes is `osascript -e 'display notification "New message" with title
"Silver Messenger"'`, which every Mac has. The script is a constant, so
there is nothing to escape; it is spawned detached, with no shell, its
standard streams closed. The notification appears under Script Editor's
name, which is cosmetic. `mac-notification-sys`, the crate that reaches
the older API directly, needs Objective-C, a bundle-identifier
workaround and `unsafe`; the constant script needs none of that.

**Windows.** A toast needs an AppUserModelID, which a bare executable
does not have and which is registered by a Start Menu shortcut the
client does not install. The established workaround is to post the toast
under PowerShell's own AppUserModelID, which `tauri-winrt-notification`
does; the toast then shows as from Windows PowerShell, which is
cosmetic. This is the one new dependency of the feature, and it is gated
to the Windows target and accepted only if `cargo deny` stays clean (its
`windows` crates must be the versions already in the tree, or the
duplicates are refused) and the Windows executable grows by an amount
recorded here after the first release that carries it. The alternative,
spawning `powershell.exe` with a script, needs no crate but takes a
third of a second, is refused by the execution policies and
application-control rules that managed machines run, and puts a script
on the command line of a process; it is the worse trade.

**Blocking and failure.** Never on the interface's thread. An OS
notification is asked for from a blocking task; whether it succeeds is
not waited for; a failure is logged once at debug level and that path is
not tried again for ten minutes, so a machine without a notification
service does not spawn a process, or open a bus connection, for every
message. The bell, the terminal sequences and the window title do not
depend on it.

**Bursts.** The existing rule holds: announcements within a second of
the last are folded into it, so a burst rings once and raises one
notification. Where the platform can replace a notification (D-Bus
`replaces_id`, a Windows toast tag), the client does, so the
notification area never fills with identical lines.

**tmux.** tmux swallows the sequences unless they are wrapped in its
passthrough (`DCS tmux ; ESC <sequence> ST`) and `allow-passthrough` is
on. The client wraps them when `TMUX` is set, and, since tmux hides the
outer terminal's identity, treats a local tmux session as an
unrecognised terminal: both paths.

**Modes.** `/notify` keeps `off`, `bell` and `all`, and gains `terminal`
and `desktop`. `all`, the default, is the automatic choice above. The
setting is stored as it is today.

**Reader mode and disappearing messages.** Unchanged. Reader mode keeps
the bell and leaves the title alone, as it does now. A disappearing
message raises nothing and counts as nothing unread, as
`docs/design/everyday.md` decided; the OS path sits behind the same gate
as the bell, so the rule covers it without new code.

## 2. Goals and non-goals

Goals:

* Someone using any of the common terminals gets a desktop notification
  for a message they are not looking at, without changing terminals or
  settings.
* The notification tells them exactly one thing: that there is a new
  message. Whoever reads the screen, the notification history or the lock
  screen learns that and nothing more.
* The interface never waits on the notification service, and a machine
  without one behaves as today.
* Nothing new is linked on Linux or macOS; on Windows, one crate, gated,
  measured and refused if it duplicates what is already there.

Non-goals:

* Registering the client with the desktop: no `.desktop` file, no
  AppUserModelID shortcut, no application bundle. Each is a packaging
  commitment for one cosmetic gain (the toast's icon and name), and the
  client is distributed as one file.
* Actions or buttons on a notification, a sound of the client's own, a
  notification per contact, or any per-contact setting. The notification
  is a knock on the door; the client is where the door opens.
* A user-supplied notification command. A configuration value that names
  a program to run makes the data directory a place where code execution
  is configured, which it is not today; the built-in paths cover the
  terminals in `docs/TERMINALS.md`, and this can be revisited if a setup
  they miss turns up.
* Localisation. The words are English, like the rest of the interface.

## 3. Choosing the path

Decided once at start, from the environment, in this order:

| Condition | Path | Why |
| --- | --- | --- |
| `SSH_CONNECTION`, `SSH_CLIENT` or `SSH_TTY` set | terminal only | The desktop is on the other end of the connection. |
| `TMUX` set | both, sequences wrapped in passthrough | The outer terminal is hidden; a local tmux session is on the desktop. |
| `TERM_PROGRAM` is `iTerm.app`, `WezTerm` or `ghostty`; `KITTY_WINDOW_ID` set or `TERM` begins `xterm-kitty`; `WEZTERM_EXECUTABLE` set; `TERM` begins `foot` or `rxvt-unicode`; `ConEmuPID` set | terminal only | Known to raise one of the sequences. |
| `WT_SESSION` set; `TERM_PROGRAM` is `Apple_Terminal` or `vscode`; `VTE_VERSION` or `KONSOLE_VERSION` set; `TERM` is `alacritty`; Windows with none of the above | OS only | Known to ignore all three. |
| Anything else | both | Unknown; a second toast is the smaller failure. |

`/notify terminal` and `/notify desktop` override the table. The choice is
a pure function of the environment, which is what the unit tests call.

## 4. What the operating system learns

A notification is metadata handed to the desktop. With the text fixed,
what it carries is: that this machine runs Silver Messenger, that a
message arrived, and when. The notification history — Notification
Center, Action Center, the GNOME tray — keeps those lines with their
times until the person clears them, and a lock screen may show the newest.
That is the same as what the terminal-raised toast has told kitty or
iTerm2 users since 0.4.0, and less than what the window title's unread
count already says to anyone who can see the window.

On macOS the request is a process whose arguments are visible to every
user of the machine for the moment it runs; the arguments are a constant
with no name in it, so that moment reveals the same thing as the toast.
On Linux the request is a message on the session bus, readable by the
session's own user, as every other program's notifications are. On Windows
the toast is posted through the WinRT API in-process.

The threat model's entry for this is one line under the device thief and
the shoulder surfer: a notification says a message arrived, not from whom
or what. `docs/THREAT_MODEL.md` carries it.

## 5. Testing

What can be checked without a desktop is checked in CI:

* Unit tests: the path chosen for each row of the table in section 3, from
  a fake environment; that the terminal sequences carry `New message` and
  the title and nothing else; that the raising call has no text parameter
  (a compile-time fact, and a test reads like one).
* Terminal tests at a pty: under the default test environment the
  sequences are written with the fixed text; with `WT_SESSION` set they
  are not; with `SSH_TTY` set they are and the OS path is not taken; with
  `TMUX` set they are wrapped. The OS path is observed through the seam,
  not through a desktop: on Linux the test environment has no session bus,
  and the test asserts the bell and title still work when the bus is
  absent.
* The existing CI build matrix compiles the Windows and macOS code, so a
  `cfg`-gated mistake fails a push, not a release.

What cannot: that a toast appears. That is verified by hand on Windows
11 with Windows Terminal, on macOS with Terminal.app, and on GNOME, and
recorded per terminal in `docs/TERMINALS.md` with the version it was
checked on, as the other columns there are. On Windows it was checked
the day 0.13.0 shipped: a contact request sent to the maintainer over
the public relay raised a toast reading `Silver Messenger` and `New
message` under the Windows PowerShell header, and the maintainer accepted
it as it is — the header says where the notification is from, which is
all it has to do.

## 6. What ships, and in what order

One release, 0.13.0, since the words a notification carries change for
everyone. Within it, in order of certainty: the fixed text and the
no-text API (a change every platform gets, and the strictest part);
the path choice and the tmux wrapping; Linux over the bus already linked;
macOS through the constant script; Windows through the gated crate, kept
only if `cargo deny` and the size measurement allow.

Measured on the release. `cargo deny` stayed clean: the crate's one
dependency of weight, `windows`, is the version already in the tree, so
nothing was duplicated. `silver-v0.13.0-x86_64-pc-windows-msvc.exe` is
13,222,912 bytes against 13,180,928 for `silver-v0.12.5`, 41,984 bytes
more for the whole item (the crate, the route, the tmux wrapping and
the rest together), so the crate stays.

## 7. Corrections

* This note first listed a group invitation and being added to a group
  among the events that ring (0.13.0). [requests.md](requests.md)
  narrowed the rule to a message received and nothing else (0.14.0),
  and the first decision above reads as the rule now stands.
