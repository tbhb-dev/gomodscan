# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns
"""Interim PreToolUse hook: stop agents typing `gh pr create|edit|merge`.

Agents open, edit and merge pull requests through the interim scripts
(`mise run pr`, `mise run merge`), which add the machine-written trailers and
the plain-text squash message. This hook blocks the direct `gh` call and names
the command to run instead:

    gh pr create  ->  mise run pr -- check, then mise run pr -- create
    gh pr edit    ->  mise run pr -- edit --pr N
    gh pr merge   ->  mise run merge -- N   (--dry-run previews)

It reads the hook payload on stdin and takes no arguments. The payload shape
alone picks the output contract, so the hook behaves the same whoever runs it:

- Antigravity: ``toolCall.args.CommandLine``; denies with
  ``{"decision": "deny", "reason": ...}``.
- Claude Code and Codex: ``tool_input.command``; deny with
  ``hookSpecificOutput.permissionDecision`` and
  ``permissionDecisionReason``, which both harnesses show to the model.

Allowing prints nothing. The hook fails open: unreadable input or any crash
allows the command and prints nothing, because a broken hook must never stop
the agent's work. The permission rules in .claude/settings.json and
.codex/rules/pull-request.rules stay as backstops.

Matching is by shell word, not by regex over the text. A small scanner splits
the command into simple commands at ``;``, ``&``, ``|``, newlines, parentheses,
``$(...)`` and backticks (inside double quotes too), drops heredoc bodies, and
removes quoting. A simple command matches when, after leading ``NAME=value``
words, shell keywords and the wrappers env, command, exec, sudo, nohup, time,
builtin and xargs (with their options), the program is ``gh`` (any path) and,
after its global flags (``-R x``, ``--repo x``, ``--hostname x``, other
``-x``), the words are ``pr create|edit|merge``. ``bash|sh|zsh|dash|ksh -c
SCRIPT`` and ``eval ...`` are scanned recursively. Text inside a quoted
argument to any other command is not a command, so
``git commit -m 'docs: mention gh pr merge'`` and ``echo "gh pr merge"`` pass.

Known gaps, none of which the permission rules close either:

- Misses: a wrapper outside the list (``timeout 5 gh ...``, ``mise x -- gh
  ...``, ``sudo -u root gh ...``), a script file or alias that runs gh, code a
  command runs from a quoted argument (``python -c``, ``ssh host '...'``), and
  ``gh api`` calls that do the same work. Substitutions inside an unquoted
  heredoc body are not scanned.
- False positives: only text the shell itself runs is read as a command, so
  quoted words never match. The remaining case is a deliberate one: a
  ``$(gh pr merge 1)`` inside ``echo`` or a commit message is run by the shell
  and is blocked.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from typing import NamedTuple

type Json = dict[str, object]

SUBCOMMANDS = ("create", "edit", "merge")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"env", "command", "exec", "sudo", "nohup", "time", "builtin", "xargs"}
KEYWORDS = {"if", "then", "do", "else", "elif", "while", "until", "!", "{", "}"}
VALUE_FLAGS = {"-R", "--repo", "--hostname"}
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
PR_NUMBER = re.compile(r"(?:\S*/pull/|#)?(\d+)")
SEPARATORS = ";&|"

DRAFT = ".github/PULL_REQUEST_DRAFT.md"
TEMPLATE = ".github/PULL_REQUEST_TEMPLATE.md"


class Match(NamedTuple):
    """A blocked `gh pr` call: the subcommand and the words after it."""

    sub: str
    args: list[str]


@dataclass
class Scanner:
    """Split shell text into simple commands, each a list of unquoted words."""

    text: str
    pos: int = 0
    quote: str = ""
    word: list[str] = field(default_factory=list)
    in_word: bool = False
    words: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    # One (kind, quote to restore) per open `$(`, `(` or backtick.
    nesting: list[tuple[str, str]] = field(default_factory=list)
    heredocs: list[tuple[str, bool]] = field(default_factory=list)

    def end_word(self) -> None:
        """Close the word being read, if any."""
        if self.in_word:
            self.words.append("".join(self.word))
        self.word = []
        self.in_word = False

    def end_command(self) -> None:
        """Close the word and the simple command being read."""
        self.end_word()
        if self.words:
            self.commands.append(self.words)
        self.words = []

    def add(self, char: str) -> None:
        """Append a literal character to the current word."""
        self.word.append(char)
        self.in_word = True

    def open_nesting(self, kind: str, width: int) -> None:
        """Enter ``$(``, ``(`` or a backtick: a new command, unquoted."""
        self.end_command()
        self.nesting.append((kind, self.quote))
        self.quote = ""
        self.pos += width

    def close_nesting(self) -> None:
        """Leave a ``)`` or a closing backtick, restoring the outer quote."""
        self.end_command()
        if self.nesting:
            self.quote = self.nesting.pop()[1]
        self.pos += 1

    def backtick(self) -> None:
        """A backtick opens a substitution, or closes the one that is open."""
        if self.nesting and self.nesting[-1][0] == "`":
            self.close_nesting()
        else:
            self.open_nesting("`", 1)

    def heredoc(self) -> None:
        """Read the delimiter after ``<<`` and queue the body to be skipped."""
        self.pos += 2
        strip = self.text.startswith("-", self.pos)
        self.pos += strip
        while self.text[self.pos : self.pos + 1] in {" ", "\t"}:
            self.pos += 1
        delim: list[str] = []
        quote = ""
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if quote:
                if char == quote:
                    quote = ""
                else:
                    delim.append(char)
            elif char in "'\"":
                quote = char
            elif char.isspace() or char in SEPARATORS + "()<>":
                break
            else:
                delim.append(char)
            self.pos += 1
        self.heredocs.append(("".join(delim), strip))

    def skip_heredoc_bodies(self) -> None:
        """After a newline, drop each queued heredoc body up to its delimiter."""
        for delim, strip in self.heredocs:
            while self.pos < len(self.text):
                end = self.text.find("\n", self.pos)
                end = len(self.text) if end < 0 else end
                line = self.text[self.pos : end]
                self.pos = min(end + 1, len(self.text))
                if (line.lstrip("\t") if strip else line) == delim:
                    break
        self.heredocs = []

    def quoted(self, char: str) -> None:
        """One character inside single or double quotes."""
        if char == self.quote:
            self.quote = ""
        elif self.quote == '"' and char == "\\":
            self.add(self.text[self.pos + 1 : self.pos + 2])
            self.pos += 1
        elif self.quote == '"' and self.text.startswith("$(", self.pos):
            self.open_nesting("$", 2)
            return
        elif self.quote == '"' and char == "`":
            self.backtick()
            return
        else:
            self.add(char)
        self.pos += 1

    def unquoted(self, char: str) -> None:
        """One character outside quotes."""
        if self.text.startswith("$(", self.pos):
            self.open_nesting("$", 2)
        elif self.text.startswith("<<<", self.pos):
            self.end_word()
            self.pos += 3
        elif self.text.startswith("<<", self.pos):
            self.end_word()
            self.heredoc()
        elif char == "`":
            self.backtick()
        elif char == "(":
            self.open_nesting("(", 1)
        elif char == ")":
            self.close_nesting()
        else:
            self.plain(char)

    def plain(self, char: str) -> None:
        """Quotes, escapes, separators, comments and ordinary characters."""
        self.pos += 1
        if char == "\\":
            if self.text[self.pos : self.pos + 1] != "\n":
                self.add(self.text[self.pos : self.pos + 1])
            self.pos += 1
        elif char in "'\"":
            self.quote, self.in_word = char, True
        elif char == "\n":
            self.end_command()
            self.skip_heredoc_bodies()
        elif char in SEPARATORS:
            self.end_command()
        elif char.isspace():
            self.end_word()
        elif char == "#" and not self.in_word:
            end = self.text.find("\n", self.pos)
            self.pos = len(self.text) if end < 0 else end
        else:
            self.add(char)

    def run(self) -> list[list[str]]:
        """Scan the whole text."""
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if self.quote:
                self.quoted(char)
            else:
                self.unquoted(char)
        self.end_command()
        return self.commands


def skip_prefix(words: list[str]) -> list[str]:
    """The command's words after env assignments, keywords and wrappers."""
    i = 0
    while i < len(words):
        word = words[i]
        if word in KEYWORDS or ASSIGNMENT.match(word):
            i += 1
        elif word.rsplit("/", 1)[-1] in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
        else:
            break
    return words[i:]


def gh_match(rest: list[str]) -> Match | None:
    """Match the words after ``gh``: global flags, then ``pr create|edit|merge``."""
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 2 if rest[i] in VALUE_FLAGS else 1
    if rest[i : i + 1] == ["pr"] and rest[i + 1 : i + 2] and rest[i + 1] in SUBCOMMANDS:
        return Match(rest[i + 1], rest[i + 2 :])
    return None


def shell_script(rest: list[str]) -> str | None:
    """The script word of ``-c`` among a shell's options, if it has one."""
    for i, word in enumerate(rest):
        if not word.startswith("-"):
            return None
        if not word.startswith("--") and "c" in word:
            return rest[i + 1] if i + 1 < len(rest) else None
    return None


def find(text: str) -> Match | None:
    """The first direct `gh pr create|edit|merge` call in a shell command."""
    for command in Scanner(text).run():
        words = skip_prefix(command)
        if not words:
            continue
        program = words[0].rsplit("/", 1)[-1]
        found: Match | None = None
        if program == "gh":
            found = gh_match(words[1:])
        elif program in SHELLS:
            script = shell_script(words[1:])
            found = find(script) if script is not None else None
        elif program == "eval":
            found = find(" ".join(words[1:]))
        if found:
            return found
    return None


def hint(found: Match) -> str:
    """The block message: what was blocked and the command to run instead."""
    blocked = f"`gh pr {found.sub}` is blocked."
    number = next((m[1] for w in found.args if (m := PR_NUMBER.fullmatch(w))), "<N>")
    if found.sub == "create":
        return (
            f"{blocked} Write {DRAFT} from {TEMPLATE}, check it with "
            "`mise run pr -- check`, then open the PR with `mise run pr -- create`."
        )
    if found.sub == "edit":
        return (
            f"{blocked} Update {DRAFT}, then run `mise run pr -- edit --pr {number}`."
        )
    return (
        f"{blocked} Once the PR is approved, run `mise run merge -- {number}` "
        "(add `--dry-run` to preview the squash message first)."
    )


def command_of(data: Json) -> tuple[str, bool]:
    """(shell command, whether the payload is Antigravity's) from hook stdin."""
    call = data.get("toolCall")
    if isinstance(call, dict):
        args = call.get("args")
        text = args.get("CommandLine") if isinstance(args, dict) else None
        return (text if isinstance(text, str) else ""), True
    inputs = data.get("tool_input")
    text = inputs.get("command") if isinstance(inputs, dict) else None
    return (text if isinstance(text, str) else ""), False


def decision(message: str, *, antigravity: bool) -> Json:
    """The deny output in the harness's own contract."""
    if antigravity:
        return {"decision": "deny", "reason": message}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }


def main() -> int:
    """Read the payload on stdin; print a deny decision for a direct gh pr call."""
    try:
        data = json.loads(sys.stdin.read())
        text, antigravity = command_of(data if isinstance(data, dict) else {})
        found = find(text)
        if found:
            print(json.dumps(decision(hint(found), antigravity=antigravity)))
    except Exception:  # noqa: BLE001  # fail open on any crash
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
