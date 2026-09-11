# Design note: the documents

Roadmap item 65. Written before the work, as the record of the decisions:
what each document in the repository is for, what shape serves that
purpose, and what is done to each one to get it back into that shape.
Nothing here changes code. Where this note and a document later disagree,
the document wins and this note is corrected.

## 1. What the review found

Thirty markdown documents, 15 590 lines, written over eight days of
releases. Each was right when it was written. What has gone wrong since
is not carelessness but accretion: every release added a paragraph to
the document nearest the change, and nobody took one out. The same
faults recur across the set, so the fixes are rules rather than
thirty separate edits:

* **One fact in several homes.** Relay deployment is in the README and in
  the operator's guide; the crypto summary is in the README, the threat
  model and the protocol; verifying a release is in the README twice.
  Each copy drifted from the others.
* **History where a description belongs.** "From 0.6.0…", "(0.9.0 on)",
  "until 0.16.0 this section said…": the README, the threat model and
  the protocol carry the changelog's job inside every paragraph, so a
  reader who wants to know what the program does now reads how it got
  there.
* **Paragraphs in tables.** The design notes' Decisions tables hold cells
  of one to three hundred words; the raw lines run past 1 500
  characters and the rendered table is a two-column wall no eye can
  scan. The Status and Gaps tables of the distribution note, the threat
  model and the assessment have the same fault.
* **Paragraphs of forty lines.** The threat model's actor sections are
  single paragraphs the length of a screen; the protocol's linking and
  Welcome sections likewise. The one section written as a list (the
  relay operator's *Can / Cannot*) is the shape the rest lost.
* **Claims that stopped being true.** A FAQ heading dropped in an edit,
  a security policy that says releases are unsigned, a README that says
  there is no reader mode five hundred lines after describing it and
  tells people to download archives the release page no longer carries,
  an assessment whose gaps table lists three closed items and a review
  that has happened twice. Section 4 lists every one found.
* **Cross-references to things that moved.** Two documents point at a
  README heading "Running a relay" that does not exist.

## 2. Decisions

**Six kinds of document, six shapes.** Every document is one of these,
says which in its first paragraph, and is shaped accordingly:

| Kind | Reader wants | Shape |
| --- | --- | --- |
| Front door | To decide, then to start | Short sections; a table where there is a choice; a command block where there is a step; no history, no argument |
| Reference | To look one thing up | Tables and code blocks, one item per row; prose only to state a rule; numbered sections that never renumber |
| Guide | To do one task in order | Numbered steps; one task per section; each section ends in a command or a check |
| Promise | To know what is claimed and what backs it | Claims as lists, short and checkable; a dated baseline; what backs each claim beside it |
| Argument | To know why | Decisions, reasons, alternatives not taken; dated; corrections kept apart from the original text |
| Record | To know what happened | Fixed shape, appended to, never rewritten for style |

**One home per fact.** The README describes, the operator's guide
operates, the protocol specifies, the threat model promises, the design
notes argue, the changelog records. A fact stated in two places is
stated in one and linked from the other. Section 3 says what moves.

**Version history goes to the changelog.** A document describes the
program as it is. A version appears only where a reader must act on it:
a compatibility rule in the protocol ("a client older than 0.16.0 cannot
be read"), a version note in the upgrade guide, a date on a claim.
"From 0.x" asides elsewhere are cut, and the changelog already holds
what they said.

**A table cell is a line.** A value, a phrase, at most two short
sentences. Anything longer is a list, or prose under a run-in heading
(`**Question.** Answer…`). The design notes' Decisions sections become
run-in lists; the Gaps and Status tables become lists or shorter rows.

**A paragraph makes one point** and fits in a dozen lines; a section
longer than a screen gets sub-headings. Rationale that repeats a design
note is cut to a sentence and a link; the note holds the argument.

**One typography.** British spelling; one dash (the em dash without
spaces, as most documents already use, never `--`); commands, flags,
file names and field names in code spans; *the client* and *the relay*
named that way; headings in sentence case; cross-references as
`PROTOCOL.md` section numbers or relative links, never "above" or
"below" across sections.

**Section numbers do not move.** `PROTOCOL.md` sections and roadmap
item numbers are cited by the code's comments, the tests, both audit
reports and every design note. Content within a section may be
restructured; no section is renumbered, split into a new number or
merged away.

**The records are not rewritten.** The two audit reports are published
whole, by policy, and are not touched. The changelog's past entries keep
their wording; only a wrong fact is corrected, and the intro gains a
sentence on the shape of an entry. The roadmap was restructured two
days ago on instruction and keeps that shape; it gets a tense pass and
the cross-references the moves change.

**A promise says when it was last checked.** The threat model and the
assessment each state the version they were checked against, and the
roadmap's Continuous line ("re-read at the end of each phase") becomes a
step of every release that changes what they claim: the release
checklist in `CONTRIBUTING.md` names it.

**Cross-references are checked by a script.** A small checker under
`tests/docs/` resolves every relative link and every "section N.M" or
"`docs/…`" mention against the target file's headings, and CI runs it,
so a moved section or a dropped heading is caught by the push that
moves it and not by a reader.

## 3. What moves where

| Content | From | To | Why |
| --- | --- | --- | --- |
| Deploying a relay (installer, release-page install, TLS routes, TLS front, metrics, admin, backups, container, pinning, Tor, onion) | README | `docs/OPERATING.md`, a new "Installing" section | One operator's guide; the README keeps ten lines and a link |
| Relay flags and environment variables | README "Options" | `docs/OPERATING.md`, beside the limits table | The operator looks there |
| Verifying a release, reproducing a build, signing releases, what a release page carries | README (three places) | new `docs/RELEASES.md` | Three audiences (user, auditor, maintainer), one subject, one place; the README keeps four commands |
| "How the crypto works" | README | cut to a short "What protects a message" list with links | The protocol and the threat model hold it; the README's copy is a history |
| Development section | README | `CONTRIBUTING.md` | It duplicates it |
| Memory protection per platform | `SECURITY.md` | `docs/THREAT_MODEL.md` (already there) | A policy points; a promise explains |
| Audit history (counts, releases, what waited for what) | `SECURITY.md`, assessment intro, README intro | the two audit-response notes (already there) | The policy links; the notes hold the story |
| The screen-reader protocol | stays in `docs/TERMINALS.md` | — | Right place already |
| Corrections written after the code landed | inside the design notes' tables and prose | a dated "Corrections" section at the end of each note | The `everyday.md` section 11 shape, applied to all |

Two documents are new: `docs/RELEASES.md` (above) and the checker under
`tests/docs/`. None is removed.

## 4. Every document

Verdicts: **keep** (wording pass only), **fix** (facts wrong, shape
right), **reshape** (structure changes), **split** (content moves out),
**re-baseline** (every claim re-checked against the code), **leave**
(not touched).

| Document | Kind | Lines | Verdict |
| --- | --- | --- | --- |
| `README.md` | Front door | 973 | split, fix |
| `CONTRIBUTING.md` | Guide | 100 | fix, keep |
| `SECURITY.md` | Promise | 161 | fix, split |
| `CHANGELOG.md` | Record | 2 485 | leave (intro sentence only) |
| `ROADMAP.md` | Record | 694 | keep (tense pass, cross-references) |
| `LICENSE` | — | — | leave |
| `docs/FAQ.md` | Guide | 225 | fix |
| `docs/OPERATING.md` | Guide | 366 | reshape (absorbs the README's deployment) |
| `docs/UPGRADING.md` | Guide | 336 | fix, reshape (version notes) |
| `docs/TERMINALS.md` | Reference | 136 | keep (status column) |
| `docs/PROTOCOL.md` | Reference | 2 447 | reshape (within sections) |
| `docs/THREAT_MODEL.md` | Promise | 1 080 | reshape, re-baseline |
| `docs/SECURITY_ASSESSMENT.md` | Promise | 277 | re-baseline |
| `docs/RELEASES.md` | Guide + reference | new | — |
| `docs/vectors/README.md` | Reference | 86 | keep |
| `formal/README.md` | Reference | 138 | keep |
| `docs/design/accessibility.md` | Argument | 208 | reshape (template) |
| `docs/design/audit-response.md` | Argument | 227 | keep |
| `docs/design/audit-response-2.md` | Argument | 211 | keep |
| `docs/design/consequential-commands.md` | Argument | 128 | reshape (template) |
| `docs/design/devices.md` | Argument | 722 | keep (one paragraph split, corrections gathered) |
| `docs/design/dh-rotation.md` | Argument | 325 | reshape (into the template) |
| `docs/design/distribution.md` | Argument | 170 | reshape (template, status table) |
| `docs/design/everyday.md` | Argument | 491 | reshape (template) |
| `docs/design/format-changes.md` | Argument | 439 | keep (corrections gathered) |
| `docs/design/groups.md` | Argument | 761 | keep (corrections gathered) |
| `docs/design/notifications.md` | Argument | 134 | reshape (template) |
| `docs/design/requests.md` | Argument | 181 | reshape (template) |
| `docs/design/robustness.md` | Argument | 183 | reshape (template); section 7 gains the day-long figures |
| `docs/design/updates.md` | Argument | 242 | reshape (template), fix |
| `docs/audits/2026-09-security-audit.md` | Record | 1 376 | leave |
| `docs/audits/2026-09-second-security-audit.md` | Record | 288 | leave |

### 4.1 The root

**`README.md`.** Purpose: the front door — what it is, how to install
it, how to start, the commands and keys, the options, where everything
else is. It has become five documents: a quick start of nine
subsections, a relay deployment guide, a crypto history, a development
guide and a release-engineering manual. Shape after: what it is (three
sentences and the links); install, per platform, with the four
verification commands; first steps; commands and keys (the table stays:
it is the manual); options for the client alone; "What protects a
message" in ten lines with links; "Running a relay" in ten lines with a
link; contributing and licence. Facts to fix: the quick start tells
people to download archives that left the release page in 0.12.2 (the
Development section, 800 lines later, says so); "What it does **not**
do yet: a screen-reader mode" while reader mode is described above it;
examples pinned at 0.13.0; the intro names one review where there are
two; the paragraph order under "By hand" describes the installer after
the alternative to it. What leaves: section 3.

**`CONTRIBUTING.md`.** Purpose: build, check, propose, what the code
holds to. The shape is right. Fix: it says `#![deny(unsafe_code)]` in
every crate where four of five are `forbid` and only the terminal binary
is `deny`, with one documented exception; the document map in the first
paragraph becomes a list; the paragraph after the check commands, which
holds five unrelated facts, becomes a list; the "Unreleased" changelog
convention says what to do when the heading is absent. Gains: the
README's Development section, and a "Releasing" checklist that names
the threat-model and assessment re-read (section 2).

**`SECURITY.md`.** Purpose: the policy — how to report, what to
expect, what is in scope, what is not a vulnerability, supported
versions, how to verify, how the code is assessed. A policy changes
rarely; this one carries a release-by-release audit narrative and a
platform table that belong elsewhere. Facts to fix: "`SHA256SUMS` is not
signed by the maintainer today" (signed since 0.12.0); the scope
paragraph names a relay host that no longer exists and, by the
convention the second review's published copy set, no live relay host
is published at all — the sentence becomes "the relay the maintainer
runs is in scope for protocol and relay bugs; do not load-test it".
What leaves: the memory-protection table (the threat model has it; two
lines and a link stay) and the two audit paragraphs (two sentences and
the four links stay).

**`CHANGELOG.md`.** Purpose: the record. Left as it is, except: the
intro says what an entry holds (a preamble, an **Upgrading** paragraph,
then Security, Added, Changed, Fixed in that order) so a reader knows
where to look, and future entries follow it. Section order is uneven in
the older entries and stays so; it is history.

**`ROADMAP.md`.** Purpose: the task list, restructured on 2026-09-11.
Keeps its shape. A tense pass on ticked items (each is its original
future-tense plan with "Shipped in…" appended, so the tense turns
mid-paragraph): past tense, one sentence of what shipped, the link. The
phase preambles stay (they say why a phase exists) and are cut to a
paragraph each. Cross-references follow the moves (item 36's "the
README's recipe" becomes the operator's guide). Gains item 65, this
note, with a box per wave of section 6.

### 4.2 For people who use it

**`docs/FAQ.md`.** Purpose: short answers, one per question, a link to
the long one. Fix: the heading "What happens if I lose my laptop?" was
dropped when the `/rekey` answer was added in 0.18.0, so its body now
dangles under the wrong question and the sentence "which the next answer
is about" points at the wrong answer — restore it; "the code has not yet
had an independent review" is two reviews stale; the key-store answer
is three paragraphs of reasoning where a FAQ gives the recipe and the
threat model the reasons. Every answer is re-read for length: an answer
longer than a screen is a link.

**`docs/TERMINALS.md`.** Purpose: what the client needs from a
terminal, which terminals give it, how each is checked, the
screen-reader protocol, the quirks. The shape is right. The Status
column of the terminal matrix carries version history ("Checked by hand
on 0.4.0; the 0.5.0 fixes and the 0.13.0 toast are expected") and
becomes status: *checked in CI*, *checked by hand on <version>*,
*expected*.

### 4.3 For people who run it

**`docs/OPERATING.md`.** Purpose: the operator's guide from install to
shutdown. The shape is right and stays; today it starts after the
install and points at a README heading that does not exist for it. It
gains "Installing" between "What you are running" and "A first
deployment": the routes as a list (the Debian package, the release
binary with its signature check, the installer, the container), then
TLS (built-in ACME, a certificate of your own, a TLS front, an onion
service), then the relay's flags and variables — all of it the README's
text, moved and cut to guide shape. Step 4 of the first deployment,
one twenty-line paragraph, becomes four lines that point at
"Installing". The "Devices" paragraph under "Day to day" loses its
audit-finding history and keeps the command and when to use it.

**`docs/UPGRADING.md`.** Purpose: move a relay between versions, roll
it back, move it between hosts; per-version notes. Fix: "the client
updates itself (`silver --update`)" — the command is `silver update`.
Reshape: the version notes gain one line saying that a version not
listed changed nothing for the relay; every note is split into
**Relay** and **Clients** (0.9.0 does it, the others do not); dashes
unified.

**`docs/RELEASES.md`** (new). Purpose: what a release page carries and
where the archives are; how to verify a download (the four commands,
then what each proves and what it does not); how to reproduce a build
and compare, signed executables included; how a release is made and
signed, and what the workflow-held key is worth against an offline one.
All of it exists in the README today, in three places and two tenses;
it is moved, not written. The threat model's *Supply chain* section
keeps the promise and links here for the procedure.

### 4.4 The promises

**`docs/THREAT_MODEL.md`.** Purpose: what is protected, against whom,
and where it falls short — the document every other one defers to.
Shape after: the *Can / Cannot* lists of the relay-operator section
applied to every actor, each bullet one claim of a few lines, with the
version history inside them cut ("From 0.11.0 the client remembers…"
becomes "The client remembers…"); the Gaps table becomes a list with a
run-in heading per gap, since its cells are paragraphs; the *Supply
chain* section rewritten to one state — today it says in one bullet
that the repository publishes no `minisign.pub` and the workflow holds
no key, and forty lines later that the workflow has signed every
release since 0.12.0. Re-baseline: the first paragraph names "the 0.12.3
line" and the document has been amended since without the baseline
moving; every claim is re-read against 0.18.0. Facts found stale: "a
maintainer's signature is designed for and not published yet"; "Not
yet: a review by anyone who did not write the code"; the gap "a panic
can leave the terminal in raw mode — next client pass" (closed in
0.10.0). The re-read is the last step, after the moves, so it checks the
final text.

**`docs/SECURITY_ASSESSMENT.md`.** Purpose: ASVS Level 2, control by
control, a verdict and its evidence. The shape (a table per chapter, a
gaps table) is right and stays. Re-baseline: it is dated "the 0.12.3
line" and has not been re-read since 0.16.0; every row is checked
against the code that ships. Found stale so far: the gaps table lists
"no independent review" (two), "received files stored unencrypted —
could follow if asked for" (`/files encrypt on`, 0.10.0) and "no
client-side history expiry — could follow" (`/timer`, 0.10.0); 10.3.1
"Met (by absence): there is no auto-update" (`silver update` exists and
what it checks is the evidence); 10.2.1 in the future tense for shipped
code; 7.3.1 "`silver.log` is not rotated" (bounded at 8 MiB since
0.16.0); 14.5 "noted for item 36" (done); 1.6.3 does not know `/rekey`;
5.1.3 says "4000-character messages" where 4000 is the cut on a held
request and a message is bounded by its 32 KiB body. The intro names
one review.

### 4.5 The specification

**`docs/PROTOCOL.md`.** Purpose: the wire format and the cryptography,
exact enough for a second implementation. The section structure, the
byte layouts, the JSON blocks and the frame tables are right and the
vectors pin the layouts; none of that moves. What changes, within
sections: paragraphs of thirty lines (13.7 "Add", 14.1 the
counter-signature, 14.6 linking) are split at their natural joints into
run-in paragraphs — the rule, the check, the failure, the compatibility
note; rationale that repeats a design note ("which is worth spelling out
because the opposite order is the tempting one") is cut to a sentence
and a link; the compatibility history in each rule becomes one "Since
0.x" note at the rule's end rather than a narrative through it; the
first paragraph's version list (v1, v2, v3) gains v4 and v5, which the
body section defines but the intro never mentions. The vectors harness
runs after every edit as proof that no layout moved.

### 4.6 The arguments

**The template.** Every design note keeps its shape — title, the
roadmap item and the "written before the code" preamble, Decisions,
Goals and non-goals, the mechanism, Tests, Implementation order — with
three changes: Decisions becomes a run-in list (`**Question.** Decision`)
instead of a two-column table; every "(Corrected when the code landed:
…)" aside and every inline "the note first said…" moves to a dated
**Corrections** section at the end, the shape `everyday.md` section 11
already has; a note's status or results table (distribution section 6,
robustness section 7) holds one line per row. The `devices.md` and
`groups.md` Decisions tables, whose cells are one to three sentences,
are the model the others are brought to.

Per note, beyond the template:

* **`accessibility.md`.** Section 3.2 carries a four-paragraph account
  of finding M-6; it keeps the rule and one paragraph, and links the
  response note.
* **`consequential-commands.md`.** Written alongside the code and
  narrative-first; it keeps that, with its Decisions table reshaped.
* **`devices.md`.** Section 7.1, one fifty-line paragraph, splits into
  the two sides and the failure cases. Otherwise kept.
* **`dh-rotation.md`.** The newest, and outside the template (a
  different title style, an italic preamble, no Decisions section). It
  is brought in: the standard title and preamble, its section 1
  argument kept as the first decision.
* **`distribution.md`.** Section 6's status table holds release-run
  diary ("the 0.14.0 build also showed what a release run costs when
  GitHub's artifact storage refuses one upload…"); the status becomes
  one line per channel and the diary is cut — the changelog has what
  matters. "As of 0.18.0" becomes "as of the latest release" so the
  heading stops needing a change per release. The README heading it
  cites is replaced by the operator's guide.
* **`everyday.md`.** The template; its section 11 is already the
  Corrections shape.
* **`format-changes.md`.** The "Corrected while writing it" paragraph in
  section 2 moves to Corrections. Otherwise kept.
* **`groups.md`.** Inline corrections (7.2, 7.6, 8.3, 5.2) gathered.
  Otherwise kept.
* **`notifications.md`, `requests.md`.** The template.
* **`robustness.md`.** The template; section 7 receives the day-long
  soak figures when that run finishes (roadmap 52).
* **`updates.md`.** Fix: "`/set update-check on`" names a command that
  does not exist; the setting is `update_check` in `config.json`.
  Section 10's I-1 account is cut to a sentence and a link.
* **`audit-response.md`, `audit-response-2.md`.** Their verdict tables
  are the one place a wide table is right: the row is the unit, and a
  reader wants the finding, the verdict and the decision side by side.
  Kept; wording pass only.

### 4.7 The references

**`docs/vectors/README.md`, `formal/README.md`.** Both are already the
shape a reference wants. Kept; a wording pass, and `formal/README.md`'s
"roadmap item 35" for the outside review becomes item 55.

### 4.8 The records

**`docs/audits/*.md`.** Published whole and unedited by the policy
`SECURITY.md` states. Not touched.

## 5. What is tested

* The vectors harness (`cargo test -p silver-protocol --test vectors`)
  after every edit to `PROTOCOL.md`: the byte layouts the vectors pin
  are the ones the text gives, and a layout that moved would be a
  protocol change, which this work does not make.
* The checker under `tests/docs/`: every relative link resolves to a
  file; every `docs/<name>.md` and `<NAME>.md` mention names a file that
  exists; every "section N" and "N.M" reference to `PROTOCOL.md`
  resolves to a heading; every design-note link from the roadmap and
  the changelog resolves. Run in CI on every push, and by hand before
  each wave's commit.
* The full test suite and the pseudo-terminal tests, which quote
  document paths in their docstrings, stay green; a docs-only commit
  cannot break them, and running them is what proves the commit was
  docs-only.
* A before-and-after table of line counts, recorded in the Corrections
  section of this note when the work is done, so the claim "shorter and
  no fact lost" is checkable: every fact cut is either moved (section 3)
  or in the changelog already.

## 6. Order of work

Each wave is one or more commits on `main`, CI green between waves,
the checker run before each commit. No wave changes code.

1. **The facts.** Every wrong or stale statement section 4 names, fixed
   where it stands, in one commit with each fix listed: the FAQ heading;
   the security policy's signature and relay-host sentences; the
   README's archives, "not yet", version pins and review count; the
   upgrade guide's `--update`; the updates note's `/set`; the assessment's
   gaps and rows; the threat model's supply-chain contradiction, review
   line and panic gap; the contributor guide's `deny`; the two dead
   "Running a relay" references, pointed for now at "Deploying a relay".
   Plus the checker and its CI step, and roadmap item 65. Small, safe,
   and worth having even if nothing else followed.
2. **The map.** `docs/RELEASES.md` written from the README's three
   sections; the operator's guide gains "Installing" from the README's
   deployment section; the README rebuilt around what is left; the
   contributor guide takes the Development section; every
   cross-reference in the roadmap, the FAQ, the policy, the design notes
   and the assessment follows. One commit per move, so each diff shows
   text leaving one file and arriving in another.
3. **The promises.** The threat model reshaped (lists per actor, gaps
   as a list, supply chain as one state) and then re-read claim by
   claim against 0.18.0 with the baseline sentence updated; the
   assessment re-read row by row with the evidence checked in the code.
   The re-read is a task of its own after the reshape, because it is
   the step that finds what the reshape cannot.
4. **The specification.** `PROTOCOL.md` within sections, as 4.5 says,
   with the vectors harness run after each section.
5. **The arguments.** The design notes brought to the template, one
   commit per note.
6. **The rest.** `CONTRIBUTING.md`, the FAQ's length pass, `TERMINALS.md`,
   the two reference READMEs, the upgrade guide's version notes, the
   roadmap's tense pass, the changelog's intro sentence.
7. **The close.** The checker run over everything; the line-count table
   and any correction into this note; the roadmap boxes ticked.

The soak result for item 52 lands in `robustness.md` section 7 whenever
the run finishes, independently of these waves.

## 7. Non-goals

* Renumbering `PROTOCOL.md` sections or roadmap items (section 2).
* Rewriting the changelog's past entries or the audit reports.
* Writing new content: nothing goes into a document that is not already
  true of the code; where a document turns out to describe something
  the code does not do, that is a defect to record here and fix in the
  code as its own item, not to paper over in prose.
* Publishing any name or address of the maintainer's infrastructure.
  The one such name found (a dead relay host in `SECURITY.md`) is
  removed rather than updated, as the second review's published copy
  did.
* A documentation site, generated pages, or any tool beyond the checker.
