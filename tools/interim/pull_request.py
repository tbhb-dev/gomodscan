# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns
"""Interim pull-request tooling. Replaced by an ascm PR workflow at M4.

Agents draft a pull request as the gitignored .github/PULL_REQUEST_DRAFT.md.
Its YAML frontmatter is PR metadata (.github/schemas/pull-request-draft.schema.json),
its H1 is the PR title, and the rest is the description, shaped by
.github/PULL_REQUEST_TEMPLATE.md. This script checks the draft and opens the PR.

Usage, from the repository root:

    uv run python -m tools.interim.pull_request check [DRAFT]
    uv run python -m tools.interim.pull_request create [DRAFT] [--dry-run]
    uv run python -m tools.interim.pull_request edit [DRAFT] --pr N
    uv run python -m tools.interim.pull_request hook claude|codex|antigravity

DRAFT defaults to .github/PULL_REQUEST_DRAFT.md. Every failure prints as
`path:line: problem`, and the exit code is 1 when there is any.

``check`` validates the frontmatter against the schema, requires a title that
``cog verify`` accepts and that fits 72 characters (a squash merge turns it into
a commit header), checks the H2 sections against
.github/pull-request-sections.toml (names, order, required, word limits), rejects
leftover HTML comments and bare ``#N`` references, and lints the description
with vale, cspell and rumdl under the repository's own configs.

``hook`` is the harnesses' PostToolUse entry point (payload on stdin). When the
tool call wrote the draft it runs ``check``'s checks and, on problems, exits 2
with them on stderr so the agent fixes the draft. Other calls exit 0 at once.

``create`` and ``edit`` run ``check``, then append the ``Generated-by`` and
``Assisted-by`` trailers as the body's last paragraph, so a squash merge carries
them into the commit. They are the LLM trailers of the commits on the branch,
deduplicated by identity, plus the posting agent as ``Assisted-by``. They are
machine-written: a draft that contains one fails ``check``, because a person
cannot compute the session hashes by hand and a stripped line would hide what
the author thought they had written. Nothing is pushed: when the branch is not
on the remote, gh's own error is passed through.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import yaml
from jsonschema import Draft202012Validator

from tools.interim import agent_identity

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from jsonschema.exceptions import ValidationError

# Each `cast` below carries `pragma: no mutate`: it is a runtime no-op, so no test
# could tell a mutated type string from the original.
type Problem = tuple[int, str]

# Names live at module level, where mutmut leaves them alone.
ROOT = Path(__file__).resolve().parents[2]
DRAFT = Path(".github") / "PULL_REQUEST_DRAFT.md"
SCHEMA = Path(".github") / "schemas" / "pull-request-draft.schema.json"
SECTIONS = Path(".github") / "pull-request-sections.toml"
# Config files each linter reads, mirrored into the temp tree by symlink.
CONFIGS = (".vale.ini", ".vale", ".cspell.jsonc", ".cspell-words.txt", ".rumdl.toml")
MAX_TITLE = 72
GH = "gh"
CLAUDE = "claude"
CODEX = "codex"
ANTIGRAVITY = "antigravity"
AGY_EDITS = agent_identity.AGY_EDIT_TOOLS
# The exit code that makes a harness feed a PostToolUse hook's stderr to the agent.
HOOK_FEEDBACK = 2
COG = "cog"
MISE = "mise"
# The title is a commit header, so the sentence-case heading rule does not apply
# to line 1: a finding on it reads (1, "vale project.HeadingTitleCase: ...").
TITLE_ALERT = (1, "vale project.HeadingTitleCase")
HEADING = re.compile(r" {0,3}(#{1,6}) +(\S.*?) *")
FRONTMATTER = re.compile(r"---\n(?P<yaml>.*?)^---[ \t]*$\n?", re.DOTALL | re.MULTILINE)
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
INLINE_CODE = re.compile(r"(`+).+?\1")
LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
REF_LINK = re.compile(r"\[([^\]]*)\]\[[^\]]*\]")
REF_DEF = re.compile(r"^ {0,3}\[[^\]]+\]:.*$", re.MULTILINE)
URL = re.compile(r"<?https?://[^\s>]*>?")
RUMDL_LINE = re.compile(r"\S+?:(\d+):\d+: (.+)")
CSPELL_LINE = re.compile(r"\S+?:(\d+):\d+ - (.+)")
HUMAN_TRAILER = re.compile(r"(?:Signed-off-by|Co-authored-by):", re.IGNORECASE)
LIST_ITEM = re.compile(r" *(?:[-*+]|\d+[.)]) +\S")
# A ``#N`` that GitHub links to this repository's issue or pull request N. One
# written ``owner/repo#N`` has a name character before the ``#``.
BARE_REF = re.compile(r"(?<![\w./&-])#(\d+)\b")
BARE_REF_MESSAGE = (
    "#{number} links to this repository's #{number}; "
    "write owner/repo#{number}, even for this repository"
)
HUMAN_TRAILER_MESSAGE = (
    "Signed-off-by and Co-authored-by do not belong in the description; "
    "remove this line"
)
WRAPPED = (
    "paragraph is hard-wrapped; write each paragraph on one line "
    "(GitHub renders newlines as line breaks)"
)


@dataclass(frozen=True)
class Section:
    """One H2 section of the description, from the sections file."""

    heading: str
    required: bool
    max_words: int | None


@dataclass(frozen=True)
class Line:
    """One draft line: its number, its raw text, and what analysis sees of it.

    ``text`` has HTML comments removed and is empty inside a fenced block,
    where ``code`` is True.
    """

    no: int
    raw: str
    text: str
    code: bool


@dataclass(frozen=True)
class Block:
    """An H2 section: its heading line and the lines up to the next H2."""

    heading: str
    no: int
    lines: list[Line]


class FrontmatterError(ValueError):
    """The frontmatter block cannot be read."""


def keep_text(loader: yaml.SafeLoader, node: yaml.Node) -> str:
    """Construct a timestamp as the text the author wrote."""
    return loader.construct_scalar(node)  # pyrefly: ignore[bad-argument-type]


class Loader(yaml.SafeLoader):
    """SafeLoader that keeps timestamps as text, so the schema can check them."""


Loader.add_constructor("tag:yaml.org,2002:timestamp", keep_text)


def parse_frontmatter(text: str) -> tuple[object, str]:
    """Split a draft into its parsed frontmatter (None when absent) and body.

    Raises:
        FrontmatterError: The block is unterminated or is not valid YAML.
    """
    match = FRONTMATTER.match(text)
    if match is None:
        if text.startswith("---\n"):
            message = "unterminated frontmatter"
            raise FrontmatterError(message)
        return None, text
    try:
        # Loader is a SafeLoader.
        data: object = yaml.load(match["yaml"], Loader=Loader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as exc:
        message = f"invalid YAML: {' '.join(str(exc).split())}"
        raise FrontmatterError(message) from exc
    return data, text[match.end() :]


@dataclass(frozen=True)
class Checked:
    """Everything ``check`` learned. ``rendered`` runs from the title line on."""

    problems: list[Problem]
    title: str = ""
    rendered: list[str] = field(default_factory=list)
    meta: dict[str, object] = field(default_factory=dict)


def load_sections() -> list[Section]:
    """Read the section scheme."""
    data = tomllib.loads((ROOT / SECTIONS).read_text())
    rows = cast("list[dict[str, object]]", data["section"])  # pragma: no mutate
    return [
        Section(
            str(row["heading"]),
            row["required"] is True,
            cast("int | None", row.get("max_words")),  # pragma: no mutate
        )
        for row in rows
    ]


def load_schema() -> dict[str, object]:
    """Read the frontmatter schema."""
    text = (ROOT / SCHEMA).read_text()
    return cast("dict[str, object]", json.loads(text))  # pragma: no mutate


def schema_default(schema: Mapping[str, object], name: str) -> object:
    """The default the schema declares for a property."""
    props = cast(
        "dict[str, dict[str, object]]", schema["properties"]
    )  # pragma: no mutate
    return props[name]["default"]


def count_words(text: str) -> int:
    """Count prose words: code, link targets, and comments are free.

    A word is a whitespace-separated token with a letter or digit in it, so
    list markers and bare punctuation are not words.
    """
    text = COMMENT.sub(" ", text)
    text = INLINE_CODE.sub(" ", text)
    text = REF_DEF.sub(" ", text)
    text = LINK.sub(r" \1 ", text)
    text = REF_LINK.sub(r" \1 ", text)
    text = URL.sub(" ", text)
    return sum(any(char.isalnum() for char in token) for token in text.split())


def fence_flags(raw: Sequence[str]) -> tuple[list[bool], int | None]:
    """Flag the lines inside fenced code, delimiters included.

    Also returns the index of the opening fence that is never closed, if any.
    """
    flags: list[bool] = []
    marker = ""  # pragma: no mutate -- None is as falsy
    opened = 0  # pragma: no mutate -- read only once marker is set
    for index, line in enumerate(raw):
        match = FENCE.match(line)
        if not marker:
            if match:
                marker, opened = match[1], index
            flags.append(bool(marker))
            continue
        flags.append(True)
        if match and set(match[1]) == set(marker) and len(match[1]) >= len(marker):
            marker = "" if line.strip() == match[1] else marker
    return flags, (opened if marker else None)


def strip_comments(texts: Sequence[str]) -> tuple[list[str], list[int]]:
    """Blank out HTML comments, keeping line numbers.

    Returns the lines and the index of the line each comment starts on.
    """
    joined = "\n".join(texts)
    starts = [joined[: match.start()].count("\n") for match in COMMENT.finditer(joined)]
    clean = COMMENT.sub(lambda match: "\n" * match[0].count("\n"), joined)
    return clean.split("\n")[: len(texts)], starts


def scan(raw: Sequence[str], first: int) -> tuple[list[Line], list[Problem]]:
    """Turn raw body lines (the first is line ``first``) into analysis lines."""
    flags, unclosed = fence_flags(raw)
    texts, comments = strip_comments(
        ["" if flags[index] else line for index, line in enumerate(raw)]
    )
    problems = [
        (first + index, "HTML comment left in the description") for index in comments
    ]
    if unclosed is not None:
        problems.append((first + unclosed, "code fence is never closed"))
    lines = [
        Line(first + index, line, texts[index], flags[index])
        for index, line in enumerate(raw)
    ]
    return lines, problems


def heading_of(line: Line) -> tuple[int, str] | None:
    """The level and text of a heading line, or None."""
    match = None if line.code else HEADING.fullmatch(line.text)
    return (len(match[1]), match[2]) if match else None


def split_blocks(
    lines: Sequence[Line],
) -> tuple[list[Line], list[Block], list[Problem]]:
    """Split the lines after the title into the preamble and the H2 sections."""
    preamble: list[Line] = []
    blocks: list[Block] = []
    problems: list[Problem] = []
    for line in lines:
        found = heading_of(line)
        if found and found[0] == 1:
            problems.append((line.no, "only one H1 is allowed: the title"))
        if found and found[0] == 2:  # noqa: PLR2004 -- H2 is the section level
            blocks.append(Block(found[1], line.no, []))
        elif blocks:
            blocks[-1].lines.append(line)
        else:
            preamble.append(line)
    return preamble, blocks, problems


def is_blank(line: Line) -> bool:
    """True for a line with no text and no code."""
    return not line.code and not line.text.strip()


def block_problems(
    blocks: Sequence[Block], sections: Sequence[Section]
) -> list[Problem]:
    """Check section names, order, emptiness, and word limits."""
    order = {section.heading: index for index, section in enumerate(sections)}
    problems: list[Problem] = []
    last = -1  # pragma: no mutate -- indexes start at 0, so -2 behaves alike
    for block in blocks:
        index = order.get(block.heading)
        if index is None:
            known = ", ".join(order)
            problems.append(
                (block.no, f"unknown section '{block.heading}'; use: {known}")
            )
            continue
        if index <= last:
            problems.append(
                (block.no, f"section '{block.heading}' is duplicated or out of order")
            )
        last = max(last, index)
        if all(map(is_blank, block.lines)):
            problems.append((block.no, f"section '{block.heading}' is empty"))
        limit = sections[index].max_words
        words = count_words("\n".join(line.text for line in block.lines))
        if limit is not None and words > limit:
            problems.append(
                (
                    block.no,
                    f"section '{block.heading}' has {words} words (limit {limit})",
                )
            )
    return problems


def wrap_problems(lines: Sequence[Line]) -> list[Problem]:
    """Flag each paragraph or list item that continues onto a second line.

    GitHub renders a newline in a description as a line break, so wrapped prose
    shows as ragged short lines. Code, tables, headings, blank lines, and the
    start of a list item end a run, so each list item stays on its own line.
    """
    problems: list[Problem] = []
    start: Line | None = None  # first line of the prose run being read
    reported = False
    for line in lines:
        text = "" if line.code else line.text.strip()
        if (
            not text
            or HEADING.fullmatch(line.text)
            or text.startswith("|")
            or HUMAN_TRAILER.match(text)
            or agent_identity.LINE.match(text)
        ):
            start = None
        elif start is None or LIST_ITEM.match(line.text):
            start, reported = line, False
        elif not reported:
            problems.append((start.no, WRAPPED))
            reported = True
    return problems


def trailer_problems(lines: Sequence[Line]) -> list[Problem]:
    """Reject trailers in the draft: the script writes the LLM ones.

    Signed-off-by and Co-authored-by are rejected for everyone: the merge
    commit's author is the person who merges, and the script never writes them.
    """
    problems: list[Problem] = []
    for line in lines:
        if line.code:
            continue
        if agent_identity.LINE.match(line.text):
            problems.append(
                (
                    line.no,
                    "the script writes Generated-by and Assisted-by; remove this line",
                )
            )
        elif HUMAN_TRAILER.match(line.text):
            problems.append((line.no, HUMAN_TRAILER_MESSAGE))
    return problems


def ref_problems(lines: Sequence[Line]) -> list[Problem]:
    """Reject ``#N`` references that don't name their repository.

    GitHub links a bare ``#N`` to the repository it appears in, which is wrong
    for another repository's pull request and ambiguous once the squash commit
    is read elsewhere, so every reference is ``owner/repo#N``. Code and links
    are exempt: neither becomes a reference.
    """
    problems: list[Problem] = []
    for line in lines:
        if line.code:
            continue
        text = INLINE_CODE.sub(" ", line.text)
        text = LINK.sub(" ", text)
        text = REF_LINK.sub(" ", text)
        text = URL.sub(" ", text)
        problems += [
            (line.no, BARE_REF_MESSAGE.format(number=number))
            for number in BARE_REF.findall(text)
        ]
    return problems


def meta_problems(
    data: object, offset: int, text: str, validator: Draft202012Validator
) -> list[Problem]:
    """Validate the frontmatter, pointing each error at its key's line."""
    if data is None:
        return []
    frontmatter = text.splitlines()[:offset]
    return [
        (
            key_line(error, frontmatter),
            f"frontmatter {error.json_path}: {error.message}",
        )
        for error in sorted(
            validator.iter_errors(data), key=lambda found: found.json_path
        )
    ]


def key_line(error: ValidationError, frontmatter: Sequence[str]) -> int:
    """The line of the top-level key an error is about; 1 when it has none."""
    if not error.absolute_path:
        return 1
    key = f"{error.absolute_path[0]}:"
    return next(
        (index for index, line in enumerate(frontmatter, 1) if line.startswith(key)), 1
    )


def find_tool(name: str) -> str:
    """Find a tool on PATH, then through mise; exit with a clear message."""
    found = shutil.which(name)
    if found:
        return found
    mise = shutil.which(MISE)
    if mise:
        done = run([mise, "which", name])
        if done.returncode == 0 and done.stdout.strip():
            return done.stdout.strip()
    message = f"{name} not found on PATH or through `mise which`; run `mise install`"
    raise SystemExit(message)


def run(
    argv: Sequence[str], *, cwd: Path | None = None, stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    """Run a command with captured output.

    Stdin is a pipe, never a terminal, so gh cannot prompt, and a prompt could
    push a branch.
    """
    # Argv comes from fixed names and validated draft fields.
    return subprocess.run(  # nosec B603
        list(argv),
        capture_output=True,
        text=True,
        check=False,  # pragma: no mutate -- the default, spelled for the linter
        cwd=cwd,
        input=stdin,
    )


def title_problems(title: str) -> list[str]:
    """Why a title is not a Conventional Commit header that fits 72 characters."""
    problems = []
    if len(title) > MAX_TITLE:
        problems.append(f"title is {len(title)} characters; the limit is {MAX_TITLE}")
    done = run([find_tool(COG), "verify", "--file", "-"], cwd=ROOT, stdin=title)
    if done.returncode != 0:
        why = " ".join(done.stderr.split())
        problems.append(
            f"title is not a Conventional Commit header (cog verify): {why}"
        )
    return problems


def parse_vale(output: str) -> list[Problem]:
    """Vale's JSON alerts."""
    try:
        data = cast(
            "dict[str, list[dict[str, object]]]", json.loads(output)
        )  # pragma: no mutate
    except ValueError:
        return []
    return [
        (int(str(alert["Line"])), f"vale {alert['Check']}: {alert['Message']}")
        for alerts in data.values()
        for alert in alerts
    ]


def parse_lines(pattern: re.Pattern[str], tool: str) -> Callable[[str], list[Problem]]:
    """A parser for a tool that prints one `path:line:col...` finding per line."""

    def parse(output: str) -> list[Problem]:
        found = (pattern.fullmatch(line) for line in output.splitlines())
        return [(int(match[1]), f"{tool}: {match[2]}") for match in found if match]

    return parse


LINTERS: tuple[tuple[str, tuple[str, ...], Callable[[str], list[Problem]]], ...] = (
    ("vale", ("--output=JSON",), parse_vale),
    (
        "cspell",
        ("--config", ".cspell.jsonc", "--no-summary", "--no-progress"),
        parse_lines(CSPELL_LINE, "cspell"),
    ),
    ("rumdl", ("check",), parse_lines(RUMDL_LINE, "rumdl")),
)


def lint(rendered: Sequence[str], first: int) -> list[Problem]:
    """Lint the title and description with the repository's own configs.

    The text goes into a temp tree with the draft's relative path and symlinks
    to the configs, so the globs in those configs match. Rendered line N is
    draft line ``first + N - 1``.
    """
    tools = [(name, find_tool(name), args, parse) for name, args, parse in LINTERS]
    for name in CONFIGS:
        if not (ROOT / name).exists():
            message = f"missing lint config {name} in {ROOT}"
            raise SystemExit(message)
    problems: list[Problem] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in CONFIGS:
            (work / name).symlink_to(ROOT / name)
        (work / DRAFT).parent.mkdir()
        (work / DRAFT).write_text("\n".join(rendered) + "\n")
        for name, exe, args, parse in tools:
            done = run([exe, *args, str(DRAFT)], cwd=work)
            found = parse(done.stdout)
            # Exit 1 means findings in all three tools; anything else, or
            # exit 1 with nothing parsed, is the tool failing.
            if done.returncode not in {0, 1} or (done.returncode == 1 and not found):
                why = " ".join((done.stderr or done.stdout).split())
                found = [(1, f"{name} failed (exit {done.returncode}): {why}")]
            problems.extend(
                (first + line - 1, text)
                for line, text in found
                if (line, text.split(":")[0]) != TITLE_ALERT
            )
    return problems


def body_problems(lines: Sequence[Line], title: Line) -> list[Problem]:
    """Check what follows the title: sections, stray text, trailers."""
    preamble, blocks, problems = split_blocks(lines)
    stray = next((line for line in preamble if not is_blank(line)), None)
    if stray:
        problems.append(
            (stray.no, "text before the first section; put it under a heading")
        )
    sections = load_sections()
    problems += block_problems(blocks, sections)
    problems += wrap_problems(lines)
    present = {block.heading for block in blocks}
    problems += [
        (title.no, f"missing required section '{section.heading}'")
        for section in sections
        if section.required and section.heading not in present
    ]
    return problems + trailer_problems(lines)


def check_text(text: str) -> Checked:
    """Validate and lint a draft. The linters run only once there is a title."""
    try:
        data, body = parse_frontmatter(text)
    except FrontmatterError as exc:
        return Checked([(1, f"frontmatter: {exc}")])
    offset = text.count("\n") - body.count("\n")
    problems = meta_problems(data, offset, text, Draft202012Validator(load_schema()))
    meta = data if isinstance(data, dict) and not problems else {}
    lines, scanned = scan(body.splitlines(), offset + 1)
    problems += scanned
    start = next(
        (index for index, line in enumerate(lines) if not is_blank(line)), None
    )
    found = None if start is None else heading_of(lines[start])
    if start is None or found is None or found[0] != 1:
        where = offset + 1 if start is None else lines[start].no
        problems.append(
            (where, "the first line after the frontmatter must be the H1 title")
        )
        return Checked(sorted(problems))
    title = lines[start]
    problems += [(title.no, why) for why in title_problems(found[1])]
    problems += body_problems(lines[start + 1 :], title)
    problems += ref_problems(lines[start:])
    rendered = [line.raw for line in lines[start:]]
    problems += lint(rendered, title.no)
    return Checked(sorted(set(problems)), found[1], rendered, meta)


def body_of(rendered: Sequence[str]) -> str:
    """The description: everything after the title, trimmed."""
    return "\n".join(rendered[1:]).strip("\n") + "\n"


def identity_key(value: str) -> tuple[str, ...]:
    """Who an LLM trailer value names: harness slug, model, session, subagent."""
    blob = value.split()[1]
    attrs = {
        key: val for key, _, val in (pair.partition("=") for pair in blob.split(";"))
    }
    return (
        attrs["harness"].partition(":")[0],
        attrs.get("model", ""),
        attrs.get("session", ""),
        attrs.get("subagent", ""),
    )


def merge_trailers(
    found: Sequence[tuple[str, str]], posting: str | None
) -> list[tuple[str, str]]:
    """Deduplicate (key, value) trailers by identity; Generated-by wins.

    The posting agent's value is added as Assisted-by when its identity is
    absent. Generated-by lines come first, as the commit-msg check requires.
    """
    roles: dict[tuple[str, ...], tuple[str, str]] = {}
    for key, value in found:
        ident = identity_key(value)
        if ident not in roles or (
            key == agent_identity.KEY_GEN and roles[ident][0] != key
        ):
            roles[ident] = (key, value)
    if posting is not None and identity_key(posting) not in roles:
        roles[identity_key(posting)] = (agent_identity.KEY_ASSIST, posting)
    return sorted(roles.values(), key=lambda pair: pair[0] != agent_identity.KEY_GEN)


def branch_trailers(base: str) -> list[tuple[str, str]]:
    """The LLM trailers of the commits on this branch, oldest first.

    The range is BASE..HEAD, which starts at the merge base. The PR targets the
    remote branch, so origin/BASE is the base when it exists. Git runs in the
    current directory, because the branch belongs to the repository the script
    is run from, which need not be the one that holds the script (ROOT).
    """
    remote = f"origin/{base}"
    code, _ = agent_identity.git("rev-parse", remote)
    span = f"{remote if code == 0 else base}..HEAD"
    code, out = agent_identity.git(
        "log", "--reverse", "--format=%x1e%(trailers:only,unfold)", span
    )
    if code != 0:
        message = f"cannot list the commits in {span}; is {base} fetched?"
        raise SystemExit(message)
    found = (agent_identity.LINE.match(line) for line in out.splitlines())
    return [(match[1], match[2]) for match in found if match]


def posting_value(env: Mapping[str, str]) -> str | None:
    """The trailer value for the agent running this script, or None for a human."""
    committer = agent_identity.committer_identity(env)
    if committer is None:
        return None
    return agent_identity.format_value(committer.ident.attrs())


def base_of(meta: Mapping[str, object]) -> str:
    """The PR's base branch: the frontmatter's, or the schema's default."""
    return str(meta.get("base", schema_default(load_schema(), "base")))


def description(checked: Checked, env: Mapping[str, str]) -> str:
    """The final body: the description plus the trailers as its last paragraph.

    Raises:
        SystemExit: A trailer fails the commit-trailer grammar.
    """
    found = branch_trailers(base_of(checked.meta))
    posting = posting_value(env)
    values = [value for _, value in found]
    errors = [
        f"{value}: {why}"
        for value in values
        if (why := agent_identity.check_value(value))
    ]
    if errors:
        raise SystemExit("invalid LLM trailer: " + "; ".join(errors))
    merged = merge_trailers(found, posting)
    body = body_of(checked.rendered)
    if not merged:
        return body
    return body + "\n" + "\n".join(f"{key}: {value}" for key, value in merged) + "\n"


def gh_args(meta: Mapping[str, object]) -> list[str]:
    """The gh pr create flags the frontmatter asks for."""
    args = ["--base", base_of(meta)]
    if meta.get("draft"):
        args.append("--draft")
    for flag, key in (
        ("--label", "labels"),
        ("--reviewer", "reviewers"),
        ("--assignee", "assignees"),
    ):
        names = cast("list[str]", meta.get(key, []))  # pragma: no mutate
        args += [item for name in names for item in (flag, name)]
    if "milestone" in meta:
        args += ["--milestone", str(meta["milestone"])]
    return args


def load_checked(path: Path) -> Checked:
    """Check a draft file."""
    try:
        text = path.read_text()
    except OSError as exc:
        return Checked([(1, f"cannot read the draft: {exc.strerror}")])
    return check_text(text)


def read_checked(path: Path) -> Checked:
    """Check a draft file and print its problems."""
    checked = load_checked(path)
    for line, why in checked.problems:
        print(f"{path}:{line}: {why}")
    return checked


def invoke_gh(argv: list[str], body: str, *, dry_run: bool = False) -> int:
    """Run gh, or show what would run. gh's output and errors pass through."""
    if dry_run:
        print(shlex.join(argv))
        print()
        print(body, end="")
        return 0
    argv[0] = find_tool(GH)
    done = run(argv, stdin=body)
    print(done.stdout, end="")
    print(done.stderr, end="", file=sys.stderr)
    return done.returncode


def command(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Run the chosen subcommand."""
    checked = read_checked(args.draft)
    if checked.problems:
        return 1
    if args.command == "check":
        print("OK: the draft conforms")
        return 0
    body = description(checked, env)
    if args.command == "create":
        argv = [GH, "pr", "create", "--title", checked.title, "--body-file", "-"]
        argv += gh_args(checked.meta)
        return invoke_gh(argv, body, dry_run=args.dry_run)
    argv = [
        GH,
        "pr",
        "edit",
        str(args.pr),
        "--title",
        checked.title,
        "--body-file",
        "-",
    ]
    labels = cast("list[str]", checked.meta.get("labels", []))  # pragma: no mutate
    for label in labels:
        argv += ["--add-label", label]
    return invoke_gh(argv, body)


def touched_paths(harness: str, data: agent_identity.Json) -> list[str]:
    """Files a harness's PostToolUse payload says the tool call wrote."""
    inputs = agent_identity.tool_input_of(data)
    path: object
    if harness == CODEX:
        return agent_identity.patch_paths(inputs.get("command"))
    if harness == ANTIGRAVITY:
        tool, args = agent_identity.agy_tool(data)
        path = agent_identity.agy_edit_path(args) if tool in AGY_EDITS else None
    else:
        path = inputs.get("file_path")
    return [path] if isinstance(path, str) and path else []


def hook(harness: str) -> int:
    """PostToolUse entry point: check the draft when the tool call wrote it.

    Exit 2 with the problems on stderr is what each harness feeds back to the
    agent. Any other call exits 0 without running a linter. The hook fails open:
    a crash or a missing tool prints a warning and exits 0, because a broken
    hook must never stop the agent's work.
    """
    try:
        data = agent_identity.read_hook_stdin()
        cwd = agent_identity.cwd_of(data) or Path.cwd()
        target = (ROOT / DRAFT).resolve()
        if not any((cwd / p).resolve() == target for p in touched_paths(harness, data)):
            return 0
        problems = load_checked(target).problems
    except (Exception, SystemExit) as exc:  # noqa: BLE001  # fail open on any crash
        print(f"pull request hook skipped: {exc}", file=sys.stderr)
        return 0
    if not problems:
        return 0
    print(f"{DRAFT} has problems. Fix them and save the file again.", file=sys.stderr)
    for line, why in problems:
        print(f"{DRAFT}:{line}: {why}", file=sys.stderr)
    return HOOK_FEEDBACK


def build_parser() -> argparse.ArgumentParser:
    """The command line."""
    parser = argparse.ArgumentParser(description="Check a PR draft and open the PR.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook").add_argument("harness", choices=[CLAUDE, CODEX, ANTIGRAVITY])
    for name in ("check", "create", "edit"):
        one = sub.add_parser(name)
        one.add_argument("draft", nargs="?", type=Path, default=DRAFT)
        if name == "create":
            one.add_argument("--dry-run", action="store_true")
        if name == "edit":
            one.add_argument("--pr", type=int, required=True)
    return parser


def main(
    argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None
) -> int:
    """Parse the command line and run it."""
    args = build_parser().parse_args(argv)
    env = os.environ if env is None else env
    if args.command == "hook":
        return hook(args.harness)
    return command(args, env)


if __name__ == "__main__":
    sys.exit(main())
