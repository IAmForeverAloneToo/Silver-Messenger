#!/usr/bin/env python3
"""The documents render on GitHub the way they read in the source.

GitHub renders the documents with cmark-gfm, and a document can be right
in the source and wrong on the page: a task box indented one column too
deep is glued onto the paragraph above it as literal text, a fence
without a language gets no highlighting, a table cell of two hundred
characters is a wall, a paragraph of three hundred words is another.
This script renders every tracked markdown file the way GitHub does,
through the `cmarkgfm` bindings to GitHub's own renderer, and fails on
what a reader would see wrong:

* a box in the source that did not render as a checkbox, and a list
  marker indented to a column no enclosing item starts its content at
  (the cause of the former);
* a fenced code block with no language;
* a heading that skips a level;
* in the documents written for people rather than as a record or a
  reference (`FOR_PEOPLE` below), a table cell over `CELL_MAX`
  characters or a paragraph over `PARA_MAX` words.

    pip install cmarkgfm            # GitHub's renderer; CI does this
    python3 tests/docs/check_render.py

Without `cmarkgfm` the source-level checks still run and the rendered
ones are skipped, and the script says so. The two audit reports under
docs/audits/ are published whole and are not checked. CHANGELOG.md and
ROADMAP.md are records: their markup is checked, their paragraphs are
not.
"""

import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP = ("docs/audits/",)
# Guides, promises and the front door: read by people, held to a screen.
FOR_PEOPLE = {
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/FAQ.md",
    "docs/OPERATING.md",
    "docs/UPGRADING.md",
    "docs/RELEASES.md",
    "docs/TERMINALS.md",
    "docs/THREAT_MODEL.md",
}
# Records: appended to, their words kept; their tables are still tables.
RECORDS = {"CHANGELOG.md", "ROADMAP.md"}
CELL_MAX = 120
PARA_MAX = 150

MARKER = re.compile(r"^(\s*)((?:[-*+])|(?:\d+[.)]))(\s+)(\S.*)?$")
BOX = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\[(?: |x|X)\]\s")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")

try:
    import cmarkgfm
    from cmarkgfm.cmark import Options

    RENDER = True
except ImportError:  # pragma: no cover - the fallback is the point
    RENDER = False


def tracked_markdown():
    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    return [p for p in out if not p.startswith(SKIP)]


def source_checks(rel, lines):
    """Nesting and fences, from the source alone."""
    problems = []
    stack = []  # (indent, content column) of the open list items
    in_fence = None
    for n, line in enumerate(lines, 1):
        fence = FENCE.match(line)
        if fence:
            if in_fence is None:
                in_fence = fence.group(1)[0]
                if not fence.group(2).strip():
                    problems.append(f"{rel}:{n}: code block with no language")
            elif fence.group(1)[0] == in_fence and not fence.group(2).strip():
                in_fence = None
            continue
        if in_fence:
            continue
        if not line.strip():
            continue
        m = MARKER.match(line)
        if m and not line.lstrip().startswith("|"):
            indent = len(m.group(1).expandtabs(4))
            content = indent + len(m.group(2)) + len(m.group(3))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if indent and (not stack or indent != stack[-1][1]):
                expected = stack[-1][1] if stack else 0
                problems.append(
                    f"{rel}:{n}: list marker at column {indent} does not start where its parent's "
                    f"content does (column {expected}), so GitHub reads it as text"
                )
            stack.append((indent, content))
            continue
        indent = len(line) - len(line.lstrip())
        if stack and indent < stack[-1][1]:
            # A line that is neither a marker nor a continuation ends
            # the list; a lazy continuation at column 0 does not, but
            # the documents here indent their continuations.
            while stack and indent < stack[-1][1]:
                stack.pop()
    return problems


class Walk(HTMLParser):
    def __init__(self):
        super().__init__()
        self.checkboxes = 0
        self.literal = []
        self.headings = []
        self.cells = []
        self.paras = []
        self.text = ""
        self.collect = None
        self.in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag == "input" and dict(attrs).get("type") == "checkbox":
            self.checkboxes += 1
        if tag == "pre":
            self.in_pre = True
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "td", "th"):
            self.collect = tag
            self.text = ""

    def handle_endtag(self, tag):
        if tag == "pre":
            self.in_pre = False
        if tag == self.collect:
            text = " ".join(self.text.split())
            if tag[0] == "h":
                self.headings.append((int(tag[1]), text))
            elif tag == "p":
                self.paras.append(text)
            else:
                self.cells.append(text)
            self.collect = None

    def handle_data(self, data):
        if self.collect:
            self.text += data
        if not self.in_pre:
            for m in re.finditer(r"(?<![\w`])\[(?: |x|X)\] ?(\S.{0,40})", data):
                self.literal.append(m.group(0).strip())


def rendered_checks(rel, text, lines):
    problems = []
    html = cmarkgfm.github_flavored_markdown_to_html(
        text, options=Options.CMARK_OPT_UNSAFE | Options.CMARK_OPT_GITHUB_PRE_LANG
    )
    w = Walk()
    w.feed(html)
    boxes = sum(1 for l in lines if BOX.match(l))
    if boxes != w.checkboxes:
        problems.append(
            f"{rel}: {boxes} task boxes in the source, {w.checkboxes} rendered as checkboxes"
        )
    for lit in w.literal[:3]:
        problems.append(f"{rel}: a box left as text on the page: {lit!r}")
    last = 0
    for level, heading in w.headings:
        if last and level > last + 1:
            problems.append(f"{rel}: heading skips a level: {heading!r} (h{last} to h{level})")
        last = level
    # A link to a heading in the same document resolves, by the anchor
    # GitHub gives the heading: lowercased, punctuation dropped, spaces
    # to hyphens, a repeated one numbered.
    anchors = set()
    seen = {}
    for _, heading in w.headings:
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        anchors.add(slug if n == 0 else f"{slug}-{n}")
    for m in re.finditer(r"\]\(#([^)\s]+)\)", text):
        if m.group(1) not in anchors:
            problems.append(f"{rel}: link to #{m.group(1)} names no heading in the document")
    if rel in FOR_PEOPLE or rel in RECORDS:
        for cell in w.cells:
            if len(cell) > CELL_MAX:
                problems.append(
                    f"{rel}: table cell of {len(cell)} characters (over {CELL_MAX}): {cell[:50]!r}"
                )
    if rel in FOR_PEOPLE:
        for para in w.paras:
            words = len(para.split())
            if words > PARA_MAX:
                problems.append(
                    f"{rel}: paragraph of {words} words (over {PARA_MAX}): {para[:50]!r}"
                )
    return problems


def main():
    problems = []
    files = tracked_markdown()
    for rel in files:
        text = (ROOT / rel).read_text(encoding="utf-8")
        lines = text.splitlines()
        problems += source_checks(rel, lines)
        if RENDER:
            problems += rendered_checks(rel, text, lines)
    for p in problems:
        print(p)
    how = "rendered and read" if RENDER else "read (cmarkgfm is not installed, so not rendered)"
    print(f"{len(files)} documents {how}, {len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
