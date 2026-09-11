#!/usr/bin/env python3
"""Every cross-reference in the documents resolves to something that
exists.

The documents refer to one another four ways, and each way has gone
stale at least once: a relative link, a file named by its path
(`docs/design/groups.md`, `tests/tui/soak.py`), a numbered section of
`docs/PROTOCOL.md` or of the document itself ("section 13.5", "(4.7)"),
and a roadmap item ("roadmap item 52"). This script finds each kind in
every tracked markdown file, resolves it, and fails on any that does
not. CI runs it on every push; run it by hand before committing a
document.

The two audit reports under docs/audits/ are published whole and cite
the tree at the commit they read, so they are not checked.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "docs" / "PROTOCOL.md"
ROADMAP = ROOT / "ROADMAP.md"
SKIP = ("docs/audits/",)

# A mention of a file by its path, for the directories the documents name.
PATH = re.compile(
    r"(?<![\w/.-])((?:docs|formal|deploy|tests|packaging|crates|fuzz|\.github)"
    r"/[A-Za-z0-9_./-]*[A-Za-z0-9_-]\.[A-Za-z0-9]+)"
)
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
# "section 13.5", "sections 4.7, 13.1 and 14.5", "sections 13 and 14".
SECTION = re.compile(
    r"\bsections? ((?:\d+(?:\.\d+){0,2})(?:(?:, | and | to |, and )\d+(?:\.\d+){0,2})*)", re.I
)
# Inside the protocol document a bare "(4.1)" or "(14.4, 14.5)" is a
# section too; sizes ("9.4 KiB") and versions ("0.16.0", "1.4") are not.
BARE = re.compile(r"(?<![\w.])(\d{1,2}\.\d{1,2}(?:\.\d)?)(?![\d.]| ?(?:KiB|KB|MiB|MB|bytes|GiB|%|x\b|k\b))")
NUMBERED_HEADING = re.compile(r"^#{1,6}\s+(\d+(?:\.\d+){0,2})[.\s]")
ROADMAP_ITEM = re.compile(r"\bitems? (\d+)(?:\.\d+)?")
ROADMAP_LINE = re.compile(r"^(\d+)\. \[")
FENCE = re.compile(r"^(```|~~~)")


def tracked_markdown():
    out = subprocess.run(
        ["git", "ls-files", "*.md", "**/*.md"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    return sorted(set(p for p in out if not p.startswith(SKIP)))


def numbered_headings(path):
    """The section numbers a document's headings carry. A changelog's
    "## 0.18.0" is a version, not a section, and is left out."""
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = NUMBERED_HEADING.match(line)
        if m and not m.group(1).startswith("0."):
            found.add(m.group(1))
    return found


def roadmap_items():
    return {
        m.group(1) for m in (ROADMAP_LINE.match(l) for l in ROADMAP.read_text(encoding="utf-8").splitlines()) if m
    }


def resolve_path(mention):
    if any(c in mention for c in "<>*…"):
        return True
    if (ROOT / mention).exists():
        return True
    # "tests/kill.rs" said of a crate's tests: take it if exactly one
    # file in the tree ends that way.
    hits = [p for p in ROOT.rglob(Path(mention).name) if str(p).endswith("/" + mention)]
    return len(hits) == 1


def prose_lines(path):
    """Lines outside fenced code blocks, with their numbers and the tail
    of the line before, since a reference often wraps ("…`PROTOCOL.md`
    / section 14")."""
    lines = path.read_text(encoding="utf-8").splitlines()
    fenced = False
    previous = ""
    for i, line in enumerate(lines):
        if FENCE.match(line.strip()):
            fenced = not fenced
            continue
        if not fenced:
            following = lines[i + 1][:64] if i + 1 < len(lines) else ""
            yield i + 1, line, previous[-120:], following
            previous = line


def markdown_named(path, mention):
    """The file a document means by `mention`: beside the document, at
    the root, or the one tracked file of that name."""
    for base in (path.parent, ROOT):
        candidate = (base / mention).resolve()
        if candidate.exists():
            return candidate
    hits = [ROOT / p for p in tracked_markdown() if p.endswith("/" + Path(mention).name) or p == Path(mention).name]
    return hits[0] if len(hits) == 1 else None


def check(rel, protocol_sections, items, problems):
    path = ROOT / rel
    own_sections = numbered_headings(path)
    heading_cache = {}

    def sections_of(target):
        if target not in heading_cache:
            heading_cache[target] = numbered_headings(target) if target.exists() else set()
        return heading_cache[target]

    for n, line, previous, following in prose_lines(path):
        where = f"{rel}:{n}"

        for m in LINK.finditer(line):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            file_part = target.split("#", 1)[0]
            if not (path.parent / file_part).exists():
                problems.append(f"{where}: link to {target} names nothing")

        for m in PATH.finditer(line):
            if not resolve_path(m.group(1)):
                problems.append(f"{where}: {m.group(1)} does not exist")

        for m in SECTION.finditer(line):
            before = (previous + " " + line[: m.start()])[-140:]
            after = (line[m.end() :] + " " + following)[:48]
            context = before[-72:] + m.group(0) + after
            # A document named just before the reference ("`groups.md`
            # section 4") is the one meant; a name further back is not.
            named = [
                m2.group(1)
                for m2 in re.finditer(r"(?<![\w./-])([\w./-]+\.md)", before)
                if m2.end() > len(before) - 80
            ] or re.findall(r"of (?:the )?`?([\w./-]+\.md)", after)
            if re.search(r"report|audit|note's|that note|this note|its section|RFC|FIPS|draft", context, re.I):
                continue
            if named:
                target = markdown_named(path, named[-1])
                if target is None:
                    problems.append(f"{where}: {named[-1]} names no document")
                    continue
                known = sections_of(target)
            elif re.search(r"protocol", context, re.I):
                known = protocol_sections
            elif own_sections:
                known = own_sections
            else:
                continue
            for number in re.findall(r"\d+(?:\.\d+){0,2}", m.group(1)):
                if number not in known:
                    problems.append(f"{where}: section {number} is not a heading of the document it names")

        if path == PROTOCOL:
            for m in BARE.finditer(line):
                number = m.group(1)
                before = line[max(0, m.start() - 12) : m.start()]
                if re.search(r"v\s?$|version|OpenMLS|Verifpal|RFC|draft", before, re.I):
                    continue
                if number.startswith("0."):
                    continue
                if number not in protocol_sections:
                    problems.append(f"{where}: {number} reads as a section reference but is not a heading")

        for m in ROADMAP_ITEM.finditer(line):
            before = line[max(0, m.start() - 24) : m.start()]
            if not re.search(r"roadmap", before, re.I) and rel != "ROADMAP.md":
                continue
            if m.group(1) not in items:
                problems.append(f"{where}: roadmap item {m.group(1)} does not exist")


def main():
    protocol_sections = numbered_headings(PROTOCOL)
    items = roadmap_items()
    problems = []
    files = tracked_markdown()
    for rel in files:
        check(rel, protocol_sections, items, problems)
    for p in problems:
        print(p)
    print(f"{len(files)} documents checked, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
