# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns
"""Interim squash merge. Replaced by an ascm PR workflow at M4.

GitHub's default squash message pastes the pull request body in as written,
Markdown included. This script builds a plain-text commit message from the PR
and merges with it.

Usage, from the repository root:

    uv run python -m tools.interim.squash_merge PR [--dry-run]

The subject is the PR title plus ` (#N)`. It must still pass ``cog verify`` and
fit 72 characters, or the script stops. The body comes from the PR body:

- HTML comments and empty sections are dropped.
- Each ``## Heading`` becomes a plain line with its text directly beneath, and
  a blank line separates every block (paragraph, list, code, section).
- Prose wraps at 72 columns. A list item keeps its marker and gets a hanging
  indent. A fenced code block loses its fences, is indented by four spaces, and
  is never wrapped. Nothing breaks inside a word, an inline code span, or a URL.
- Emphasis markers go. Link text stays and its URL moves to a numbered
  reference list after the last section, because the URL usually is the issue or
  the spec the sentence points at, and a commit message cannot hold a link.
- The PR body's final Generated-by and Assisted-by paragraph becomes the
  commit's trailer block, as written and never wrapped. The script checks that
  ``git interpret-trailers --parse`` reads it back unchanged.

The script never adds Signed-off-by or Co-authored-by, and it refuses a PR body
that already holds one, whoever runs it.

Agents run this script to merge once the PR is approved. Branch rulesets keep
GitHub enforcing the human review. The script refuses a draft PR, one that is
not open or not mergeable, and one whose merge state gh reports as blocked,
behind, dirty or unknown (which includes failing required checks), and it names
any failing checks. It leaves the rules themselves to GitHub. The merge passes
``--match-head-commit`` so that a push after the preview cannot slip in.
``--dry-run`` previews the message and the command and merges nothing.

A pull request from the Renovate app is the exception to the body rule: its
release notes and configuration notes are dropped, and the body is one line
per update from Renovate's update table.
"""

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, cast

from tools.interim import agent_identity
from tools.interim import pull_request as pr

if TYPE_CHECKING:
    from collections.abc import Sequence

WIDTH = 72
CODE_INDENT = "    "
GH = "gh"
GIT = "git"
VIEW_FIELDS = (
    "title,body,headRefOid,baseRefName,state,isDraft,mergeable,"
    "mergeStateStatus,statusCheckRollup,author"
)
# gh's merge states that mean "not now", with the reason GitHub already computed.
REFUSED_STATES = frozenset({"BLOCKED", "BEHIND", "DIRTY", "DRAFT", "UNKNOWN"})
FAILED_CONCLUSIONS = frozenset(
    {"FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"}
)
FAILED_STATES = frozenset({"FAILURE", "ERROR"})
TOKEN = re.compile(r"(?:(`+).+?\1|\S)+")
ITEM = re.compile(r"( *)([-*+]|\d+[.)]) +(\S.*)")
MD_LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)(?: +\"[^\"]*\")?\)")
AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")
STRONG = re.compile(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1")
EMPHASIS = re.compile(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])")
PLACEHOLDER = re.compile("\x00(\\d+)\x00")
# Renovate's pull requests come from its GitHub App, whose gh login is
# ``app/<name>``; the name is the tbhb-dev-renovate app's.
RENOVATE = "renovate"


@dataclass(frozen=True)
class PullRequest:
    """What gh reports about the pull request."""

    title: str
    body: str
    head: str
    state: str
    draft: bool
    mergeable: str
    merge_state: str
    failing: list[str]
    renovate: bool = False


@dataclass(frozen=True)
class Message:
    """A commit message: the subject and the body that follows it."""

    subject: str
    body: str

    def text(self) -> str:
        """The whole message as git stores it."""
        return f"{self.subject}\n\n{self.body}" if self.body else f"{self.subject}\n"


def stop(message: str) -> NoReturn:
    """Exit with a one-line reason on stderr and status 1."""
    raise SystemExit(message)


def wrap(text: str, first: str, rest: str, width: int = WIDTH) -> list[str]:
    """Wrap ``text`` greedily; ``first`` and ``rest`` start the first and later lines.

    A token (a word, a URL, or a code span with its neighbors) is never split,
    so a token wider than the line gets a line of its own.
    """
    lines: list[str] = []
    current = first
    empty = True
    for match in TOKEN.finditer(text):
        token = match[0]
        if empty:
            current += token
        elif len(current) + 1 + len(token) <= width:
            current += " " + token
        else:
            lines.append(current)
            current = rest + token
        empty = False
    return [*lines, current]


def reference(url: str, refs: dict[str, int]) -> str:
    """The marker for a URL, numbering it on first use."""
    return f"[{refs.setdefault(url, len(refs) + 1)}]"


def prose(text: str, refs: dict[str, int]) -> str:
    """Plain text for Markdown prose: links to references, emphasis dropped."""

    def link(match: re.Match[str]) -> str:
        label, url = match[2], match[3]
        return url if label == url else f"{label} {reference(url, refs)}".strip()

    text = MD_LINK.sub(link, text)
    text = AUTOLINK.sub(r"\1", text)
    text = STRONG.sub(r"\2", text)
    return EMPHASIS.sub(r"\1", text)


def inline(text: str, refs: dict[str, int]) -> str:
    """Plain text for a Markdown line, with inline code left exactly as written."""
    spans: list[str] = []

    def hold(match: re.Match[str]) -> str:
        spans.append(match[0])
        return f"\x00{len(spans) - 1}\x00"

    held = pr.INLINE_CODE.sub(hold, text)
    return PLACEHOLDER.sub(lambda m: spans[int(m[1])], prose(held, refs))


@dataclass
class Pending:
    """Text lines collected for one paragraph or list item."""

    first: str
    rest: str
    parts: list[str]


def close_fence(raw: str, marker: str) -> bool:
    """True when ``raw`` closes a fence opened with ``marker``."""
    match = pr.FENCE.match(raw)
    return bool(
        match
        and raw.strip() == match[1]
        and match[1][0] == marker[0]
        and len(match[1]) >= len(marker)
    )


@dataclass
class Renderer:
    """Turns section lines into blocks of plain text, one string per block."""

    refs: dict[str, int]
    blocks: list[str]
    pending: Pending | None = None
    code: list[str] | None = None
    marker: str = ""
    # The last block is a list item with no blank line after it, so the next
    # item joins that block instead of starting one.
    in_list: bool = False

    def flush(self) -> None:
        """End the paragraph or list item being collected."""
        if self.pending is not None:
            text = inline(" ".join(self.pending.parts), self.refs)
            lines = "\n".join(wrap(text, self.pending.first, self.pending.rest))
            item = bool(self.pending.first)
            if item and self.in_list:
                self.blocks[-1] += "\n" + lines
            else:
                self.blocks.append(lines)
            self.in_list = item
        self.pending = None

    def feed_code(self, line: pr.Line, code: list[str]) -> None:
        """Take a line inside a fence: indent it, or close the block."""
        if close_fence(line.raw, self.marker):
            self.blocks.append("\n".join(code))
            self.code = None
        else:
            code.append(CODE_INDENT + line.raw if line.raw.strip() else "")

    def feed(self, line: pr.Line) -> None:
        """Take the next line of the section."""
        if self.code is not None:
            self.feed_code(line, self.code)
        elif line.code:
            self.flush()
            self.in_list = False
            self.marker = pr.FENCE.findall(line.raw)[0]  # line.code opens a fence
            self.code = []
        elif pr.is_blank(line):
            self.flush()
            self.in_list = False
        elif item := ITEM.fullmatch(line.text):
            self.flush()
            prefix = f"{item[1]}{item[2]} "
            self.pending = Pending(prefix, " " * len(prefix), [item[3]])
        elif self.pending is None:
            heading = pr.heading_of(line)
            text = heading[1] if heading else line.text.strip()
            self.pending = Pending("", "", [text])
        else:
            self.pending.parts.append(line.text.strip())


def render(lines: Sequence[pr.Line], refs: dict[str, int]) -> list[str]:
    """Render section lines as blocks of plain text, one string per block."""
    renderer = Renderer(refs, [])
    for line in lines:
        renderer.feed(line)
    renderer.flush()
    return renderer.blocks


def split_trailers(lines: Sequence[pr.Line]) -> tuple[list[pr.Line], list[str]]:
    """Split off the body's final paragraph when it is all LLM trailers."""
    end = len(lines)
    while end and pr.is_blank(lines[end - 1]):
        end -= 1
    start = end
    while (
        start
        and not lines[start - 1].code
        and agent_identity.LINE.match(lines[start - 1].text)
    ):
        start -= 1
    if start == end or (start and not pr.is_blank(lines[start - 1])):
        return list(lines), []
    return list(lines[:start]), [line.raw.rstrip() for line in lines[start:end]]


def body_blocks(lines: Sequence[pr.Line], refs: dict[str, int]) -> list[str]:
    """The sections of a PR body as plain-text parts, empty sections dropped.

    A section is its heading line, then its blocks with a blank line between.
    """
    preamble, sections, _ = pr.split_blocks(lines)
    parts = ["\n\n".join(render(preamble, refs))]
    for section in sections:
        content = render(section.lines, refs)
        if content:
            parts.append(section.heading + "\n" + "\n\n".join(content))
    return [part for part in parts if part]


def check_trailers(trailers: Sequence[str], text_lines: Sequence[pr.Line]) -> None:
    """Refuse a PR body with stray trailer lines or an invalid trailer block."""
    problems = [why for _, why in pr.trailer_problems(text_lines)]
    for trailer in trailers:
        # split_trailers kept only lines that match agent_identity.LINE.
        why = agent_identity.check_value(trailer.partition(":")[2].strip())
        if why:
            problems.append(f"invalid trailer {trailer!r}: {why}")
    if problems:
        message = "the PR body cannot be merged as is: " + "; ".join(problems)
        stop(message)


def check_round_trip(message: str, trailers: Sequence[str]) -> None:
    """Fail unless git reads back exactly the trailer block that was written."""
    done = pr.run([pr.find_tool(GIT), "interpret-trailers", "--parse"], stdin=message)
    if done.stdout != "\n".join(trailers) + "\n":
        reason = f"git interpret-trailers --parse read back: {done.stdout!r}"
        stop(f"the trailer block did not survive the message: {reason}")


def table_cells(row: str) -> list[str]:
    """The cells of one Markdown table row, stripped."""
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def plain_cell(cell: str) -> str:
    """A table cell as plain text: link labels kept, code backticks dropped."""
    return MD_LINK.sub(r"\2", cell).replace("`", "")


def renovate_body(body: str) -> str:
    """One list item per update from a Renovate PR body's update table.

    Renovate's body opens with a ``| Package | ... | Change |`` table, then
    release notes and its own configuration notes, which don't belong in a
    commit message. Only the table survives, as ``- name change (update)``.
    A body without that table gives none.
    """
    lines = body.splitlines()
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip().startswith("|")
            and table_cells(line)[0].lower() == "package"
        ),
        None,
    )
    if start is None:
        return ""
    header = [cell.lower() for cell in table_cells(lines[start])]
    items: list[str] = []
    for line in lines[start + 2 :]:
        if not line.strip().startswith("|"):
            break
        row = dict(zip(header, map(plain_cell, table_cells(line)), strict=False))
        update = f" ({row['update']})" if row.get("update") else ""
        items.append(f"- {row['package']} {row.get('change', '')}".rstrip() + update)
    # Renovate lists one dependency once per manager that found it.
    unique = list(dict.fromkeys(items))
    return "\n".join(unique) + "\n" if unique else ""


def build_message(title: str, number: int, body: str) -> Message:
    """The squash commit message for a PR.

    Raises:
        SystemExit: The subject is not a Conventional Commit header within 72
            characters, the body has an unclosed fence or a reserved trailer,
            or the trailer block does not survive git.
    """
    subject = f"{title} (#{number})"
    if problems := pr.title_problems(subject):
        stop(f"the squash subject {subject!r} fails: {'; '.join(problems)}")
    lines, _ = pr.scan(body.splitlines(), 1)
    _, unclosed = pr.fence_flags(body.splitlines())
    if unclosed is not None:
        stop(
            f"the PR body is malformed: line {unclosed + 1}: code fence is never closed"
        )
    rest, trailers = split_trailers(lines)
    check_trailers(trailers, rest)
    refs: dict[str, int] = {}
    parts = body_blocks(rest, refs)
    if refs:
        parts.append("\n".join(f"[{number}]: {url}" for url, number in refs.items()))
    if trailers:
        parts.append("\n".join(trailers))
    message = Message(subject, "\n\n".join(parts) + "\n" if parts else "")
    if trailers:
        check_round_trip(message.text(), trailers)
    return message


def refusals(request: PullRequest) -> list[str]:
    """Why this PR may not merge now, in gh's own words."""
    reasons: list[str] = []
    if request.state != "OPEN":
        reasons.append(f"the PR is {request.state.lower()}")
    if request.draft:
        reasons.append("the PR is a draft")
    if request.mergeable != "MERGEABLE":
        reasons.append(f"gh reports mergeable={request.mergeable}")
    if request.merge_state in REFUSED_STATES:
        reasons.append(f"gh reports mergeStateStatus={request.merge_state}")
    if reasons and request.failing:
        reasons.append("failing checks: " + ", ".join(request.failing))
    return reasons


def failed_name(entry: object) -> str | None:
    """The name of a failed statusCheckRollup entry, or None."""
    fields = cast("dict[str, object]", entry) if isinstance(entry, dict) else {}
    if (
        fields.get("conclusion") in FAILED_CONCLUSIONS
        or fields.get("state") in FAILED_STATES
    ):
        return str(fields.get("name") or fields.get("context"))
    return None


def failing_checks(rollup: object) -> list[str]:
    """Names of the failed entries in gh's statusCheckRollup."""
    entries = cast("list[object]", rollup) if isinstance(rollup, list) else []
    return [name for entry in entries if (name := failed_name(entry))]


def fetch(number: int) -> PullRequest:
    """Read the PR through gh.

    Raises:
        SystemExit: gh fails or does not return JSON.
    """
    argv = [pr.find_tool(GH), "pr", "view", str(number), "--json", VIEW_FIELDS]
    done = pr.run(argv)
    if done.returncode != 0:
        stop(f"gh pr view failed: {' '.join(done.stderr.split())}")
    try:
        data: dict[str, object] = json.loads(done.stdout)
    except ValueError as exc:
        stop(f"gh pr view returned something that is not JSON: {exc}")
    author = data.get("author")
    who = cast("dict[str, object]", author) if isinstance(author, dict) else {}
    return PullRequest(
        renovate=who.get("is_bot") is True and RENOVATE in str(who.get("login", "")),
        title=str(data.get("title", "")),
        body=str(data.get("body") or ""),
        head=str(data.get("headRefOid", "")),
        state=str(data.get("state", "")),
        draft=data.get("isDraft") is True,
        mergeable=str(data.get("mergeable", "")),
        merge_state=str(data.get("mergeStateStatus", "")),
        failing=failing_checks(data.get("statusCheckRollup")),
    )


def build_parser() -> argparse.ArgumentParser:
    """The command line."""
    parser = argparse.ArgumentParser(
        description="Squash-merge a PR with a clean message."
    )
    parser.add_argument("number", type=int, metavar="PR")
    parser.add_argument("--dry-run", action="store_true", help="show it, merge nothing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Preview or perform the squash merge."""
    args = build_parser().parse_args(argv)
    request = fetch(args.number)
    if reasons := refusals(request):
        stop(f"not merging PR #{args.number}: " + "; ".join(reasons))
    body = renovate_body(request.body) if request.renovate else request.body
    message = build_message(request.title, args.number, body)
    argv_gh = [
        GH, "pr", "merge", str(args.number), "--squash", "--subject", message.subject,
        "--body-file", "-", "--match-head-commit", request.head,
    ]  # fmt: skip
    if args.dry_run:
        print(shlex.join(argv_gh))
        print()
        print(message.text(), end="")
        return 0
    argv_gh[0] = pr.find_tool(GH)
    done = pr.run(argv_gh, stdin=message.body)
    print(done.stdout, end="")
    print(done.stderr, end="", file=sys.stderr)
    return done.returncode


if __name__ == "__main__":
    sys.exit(main())
