# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns
"""Interim agent-identity hooks. Stdlib only. Superseded by ascm at M4.

Until ascm writes commit trailers itself, this script stamps them from machine
sources, never from anything an agent types. Harness hooks record who is
working (session, model, effort) and which files they edit. Git hooks turn
those records into trailers and validate them:

    record <claude|codex|antigravity>  harness hook: reads hook JSON on stdin
    trailer <msgfile> [source]         prepare-commit-msg: stamp the trailers
    consume                            post-commit: consume the credited receipts
    check <msgfile>                    commit-msg and CI: validate the trailers
    stamp-docs                         pre-commit: stamp staged Markdown frontmatter

The trailer grammar is a subset of the ascm design's, with optional fields
omitted rather than guessed:

    <Key>: LLM effort=..;harness=..;model=..;session=..;subagent=..;surface=..

The key states the role. ``Generated-by`` goes to an agent holding an
unconsumed edit receipt for a staged path, or to the committer when no receipt
matches. ``Assisted-by`` goes to the committer or the root agent when they
wrote none of the staged content. ``check`` validates only the ``LLM``
trailers, the same for every committer: ``Signed-off-by`` and ``Co-authored-by``
are not checked (agents don't add them as a norm; the operator may sign off).

``stamp-docs`` sets the ``generated`` list of each staged document's frontmatter
(see docs/schemas/frontmatter.schema.json) to the same identities, from the same
edit receipts, read but not consumed. It replaces the previous commit's list, so
the list names only the latest generation. It rewrites the staged blob and the
work-tree file together, so prek's modified-files check passes. Only the
``generated`` block changes. Root-level files, AGENTS.md, CLAUDE.md, index.md
and log.md are skipped, as are fixtures under a ``testdata`` directory, files
without LF frontmatter, and files with a ``generated`` value that is not a plain
block list. Known limit: when a file is partially staged and an unstaged change
touches the line next to where the first stamp is inserted, prek cannot restore
that change and fails the commit ("Hook changes conflicted with the saved
unstaged changes"). Fix it with ``git add`` on the whole file, or stash the
unstaged change, then commit again.

State lives under ``$(git rev-parse --git-common-dir)/ascm-interim/`` and holds
hashes only (``sha-256-64`` of each raw ID), never raw session or agent IDs:

    sessions/<hex>.json         root and child agent records
    edits/<root-hex>/<id>.json  edit receipts
    cmds/<root-hex>/<id>.json   Claude Bash command records
    marks/<hex>.json            Codex rollout scan offsets
    claims/<tree>.json          receipts a pending commit's trailers credit
    lock                        held for every read-modify-write

Concurrent agents share the store. Every file is written whole (temp file plus
rename), so a reader never sees a partial one, and every read-modify-write
holds ``lock``, so concurrent hooks never lose each other's updates.

A receipt is consumed only by the post-commit hook of the commit whose trailers
credited it (``claims/``), so a failed or aborted commit attempt consumes
nothing, and an edit recorded after the trailers were stamped, or still
unstaged when they were, stays for the commit that does contain it. A receipt
matches by path, not blob: a formatter rewriting the file before the commit
keeps the credit.
"""

import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess  # nosec B404
import sys
import time
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from itertools import islice, takewhile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Mapping

KEY_GEN = "Generated-by"
KEY_ASSIST = "Assisted-by"

CLAUDE = "claude"
CODEX = "codex"
ANTIGRAVITY = "antigravity"

# Internal harness key -> trailer slug, and -> OpenTelemetry gen_ai.provider.name.
SLUGS = {CLAUDE: "claude-code", CODEX: "codex", ANTIGRAVITY: "antigravity"}
PROVIDERS = {CLAUDE: "anthropic", CODEX: "openai", ANTIGRAVITY: "gcp.gemini"}
EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
EDITS = "edits"
CLAIMS = "claims"
ATTR_ORDER = ["effort", "harness", "model", "session", "subagent", "surface"]
BAD_VALUE = re.compile(r"[\s;,]")
SURFACE_VALUE = re.compile(r"[^\s;,=]+")
HASH_RE = re.compile(r"sha-256-64:[0-9a-f]{16}")
CODEX_MODEL = re.compile(r"(gpt-|o\d|codex-)")
THREAD_ID = re.compile(r"[0-9a-fA-F-]{8,64}")

# Only used by the optional rewrite path, which stays off unless
# ASCM_AGENT_REWRITE=1 is set at hook time (it costs a permission prompt).
AGENT_ENV = "ASCM_AGENT_ID"
REWRITE_FLAG = "ASCM_AGENT_REWRITE"

# prek and pre-commit pass the commit source here, not as an argument.
SOURCE_ENV = "PRE_COMMIT_COMMIT_MSG_SOURCE"

CLAUDE_EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
# agy 1.4.12 -p (verified live) uses write_file and edit_file with the path in
# args.Path. The other names are the documented IDE-era tools, kept in case
# another mode uses them.
AGY_EDIT_TOOLS = {
    "write_file",
    "edit_file",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
}
AGY_PATH_KEYS = (
    "Path",
    "TargetFile",
    "AbsolutePath",
    "target_file",
    "file_path",
    "filePath",
    "path",
)

CMD_WINDOW = 2 * 3600
ANCESTRY_LIMIT = 16
CLAUDE_TAIL = 256 * 1024
CODEX_TAIL = 1024 * 1024
CODEX_MAX_AGE = 3 * 86400

# Antigravity model keys -> (provider, canonical model id, effort).
# Source of every entry: `agy models` on 1.4.12 (key plus display name, such as
# "Gemini 3.8 Flash (Medium)"). Effort is the key suffix, confirmed by the
# display-name parenthetical in each case. The gemini-* canonical IDs are
# inferred from display names and the old design, NOT verified against Google's
# API. Never regex-strip: unknown keys (gemini-3.8-flash-tiered, ...) pass
# through whole.
AGY_MODELS: dict[str, tuple[str, str, str]] = {
    f"{base}-{effort}": (provider, base, effort)
    for base, provider in (
        ("gemini-4-argon", "gcp.gemini"),
        ("gemini-3.8-flash", "gcp.gemini"),
        ("claude-opus-5-5", "anthropic"),
        ("claude-sonnet-5-5", "anthropic"),
    )
    for effort in ("low", "medium", "high")
}
AGY_MODELS["gpt-oss-120b-medium"] = ("openai", "gpt-oss-120b", "medium")

type Json = dict[str, object]


@dataclass(frozen=True)
class Ident:
    """One agent's final trailer values. ``root`` is the root session hash."""

    root: str
    harness: str
    subagent: str | None = None
    model: str | None = None
    effort: str | None = None
    surface: str | None = None

    @classmethod
    def from_receipt(cls, receipt: Json) -> Ident:
        """Rebuild an identity from a stored edit receipt."""
        return cls(
            root=str(receipt["root"]),
            harness=str(receipt["harness"]),
            subagent=as_str(receipt.get("subagent")),
            model=as_str(receipt.get("model")),
            effort=as_str(receipt.get("effort")),
            surface=as_str(receipt.get("surface")),
        )

    def attrs(self) -> dict[str, str]:
        """Trailer attributes; unknown values are omitted."""
        found = {
            "effort": self.effort,
            "harness": self.harness,
            "model": self.model,
            "session": self.root,
            "subagent": self.subagent,
            "surface": self.surface,
        }
        return {k: v for k, v in found.items() if v}

    def agent_key(self) -> tuple[str, str | None]:
        """Which agent this is, independent of its model or effort."""
        return (self.root, self.subagent)


@dataclass(frozen=True)
class Seen:
    """Raw, unvalidated observations about one agent (any JSON-ish value)."""

    version: object = None
    model: object = None
    effort: object = None
    surface: object = None


@dataclass(frozen=True)
class Committer:
    """The agent running ``git commit``, plus its root agent."""

    key: str
    ident: Ident
    root_ident: Ident


@dataclass(frozen=True)
class Repo:
    """A work tree and its shared interim store."""

    top: Path
    interim: Path


# ------------------------------------------------------------------ basics


def sha256_64(raw: object) -> str:
    """Hash a raw ID to ``sha-256-64:`` plus the first 16 hex of its SHA-256."""
    return "sha-256-64:" + hashlib.sha256(str(raw).encode()).hexdigest()[:16]


def hx(hashed: str) -> str:
    """The hex part of a ``sha-256-64:`` hash."""
    return hashed.split(":")[1]


def git(*args: str, cwd: Path | None = None) -> tuple[int, str]:
    """Run git; return its exit code and stdout without trailing newlines."""
    result = subprocess.run(  # nosec B603 B607
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
    )
    return result.returncode, result.stdout.strip("\n")


def interim_dir(cwd: Path | None = None) -> Path | None:
    """``<git-common-dir>/ascm-interim``, or None outside a repository."""
    code, out = git("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=cwd)
    return Path(out) / "ascm-interim" if code == 0 else None


def repo_info(cwd: Path | None = None) -> Repo | None:
    """The work tree and interim store containing ``cwd``, or None."""
    code, out = git(
        "rev-parse",
        "--path-format=absolute",
        "--show-toplevel",
        "--git-common-dir",
        cwd=cwd,
    )
    if code != 0:
        return None
    top, common = out.split("\n")
    return Repo(Path(top).resolve(), Path(common) / "ascm-interim")


def read_json(path: Path, default: Json | None = None) -> Json | None:
    """Parse a JSON file; return ``default`` when it is missing or invalid."""
    try:
        loaded = json.loads(path.read_text())
    except OSError, ValueError:
        return default
    return loaded if isinstance(loaded, dict) else default


def read_record(path: Path) -> Json:
    """Parse a JSON object file; an empty dict when missing or invalid."""
    return read_json(path) or {}


def write_json(path: Path, obj: Json) -> None:
    """Write JSON atomically, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj))
    tmp.replace(path)


@contextmanager
def locked(interim: Path) -> Generator[None]:
    """Hold the store's exclusive lock for one read-modify-write.

    Never nested: a second ``flock`` from the same process would deadlock.
    """
    interim.mkdir(parents=True, exist_ok=True)
    with (interim / "lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def as_str(value: object) -> str | None:
    """The value if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def as_dict(value: object) -> Json | None:
    """The value if it is a JSON object, else None."""
    if isinstance(value, dict):
        return cast("Json", value)  # pragma: no mutate -- a runtime no-op
    return None


def first_str(data: Json, *names: str) -> str | None:
    """The first of ``names`` whose value in ``data`` is a non-empty string."""
    for name in names:
        value = as_str(data.get(name))
        if value:
            return value
    return None


# ------------------------------------------------------- detection and values


def detect(env: Mapping[str, str]) -> tuple[str, str] | None:
    """Return (harness key, raw conversation ID), or None outside a harness.

    The innermost harness wins: agy, then codex, then claude. For agy this is
    the executing conversation (possibly a subagent); for codex, the root
    session.
    """
    for key, var in (
        (ANTIGRAVITY, "ANTIGRAVITY_CONVERSATION_ID"),
        (CODEX, "CODEX_SESSION_ID"),
        (CLAUDE, "CLAUDE_CODE_SESSION_ID"),
    ):
        if env.get(var):
            return key, env[var]
    return None


def version(key: str, env: Mapping[str, str]) -> str | None:
    """The harness version from its environment, or None."""
    if key == CLAUDE:
        path = env.get("CLAUDE_CODE_EXECPATH")
        return Path(path).name if path else None
    if key == CODEX:
        return env.get("CODEX_VERSION") or None
    if key == ANTIGRAVITY:
        ls_version = env.get("ANTIGRAVITY_LS_VERSION")
        return ls_version.removeprefix("cli-") if ls_version else None
    return None


def clean_value(value: object) -> str | None:
    """Lowercase a trailer value; None when empty or not grammar-safe."""
    text = str(value).strip().lower() if value is not None else ""
    if not text or BAD_VALUE.search(text) or text == "<synthetic>":
        return None
    return text


def surface_ok(value: object) -> str | None:
    """A raw vendor surface value (case preserved) if the grammar allows it."""
    if isinstance(value, str) and SURFACE_VALUE.fullmatch(value):
        return value
    return None


def surface(key: str, env: Mapping[str, str]) -> str | None:
    """The surface a harness runs on (IDE, CLI, SDK and so on), from its env.

    Codex has none in its env; its surface is the rollout's ``source``.
    """
    if key == CLAUDE:
        return surface_ok(env.get("CLAUDE_CODE_ENTRYPOINT"))
    if key == ANTIGRAVITY:
        ls_version = env.get("ANTIGRAVITY_LS_VERSION")
        return "cli" if ls_version and ls_version.startswith("cli-") else None
    return None


def agy_model(raw: str) -> tuple[str, str | None]:
    """Explicit table lookup only: (model value, effort or None).

    Unknown keys pass through whole.
    """
    entry = AGY_MODELS.get(raw)
    if entry:
        return f"{entry[0]}:{entry[1]}", entry[2]
    return raw, None


def provider_model(key: str, model: str | None) -> str | None:
    """``provider:model`` for a raw model name, or None if unusable."""
    if not model or model.startswith("<") or BAD_VALUE.search(model):
        return None
    if key == CLAUDE:
        return f"{PROVIDERS[CLAUDE]}:{model}"
    if key == CODEX and CODEX_MODEL.match(model):
        return f"{PROVIDERS[CODEX]}:{model}"
    if key == ANTIGRAVITY:
        return agy_model(model)[0]
    return model


def format_value(attrs: Mapping[str, str]) -> str:
    """Render ``LLM k=v;...`` in the grammar's attribute order."""
    return "LLM " + ";".join(f"{k}={attrs[k]}" for k in ATTR_ORDER if attrs.get(k))


def model_effort(
    key: str, raw_model: object, raw_effort: object
) -> tuple[str | None, str | None]:
    """Final (model, effort) trailer values from raw observations."""
    model, effort = as_str(raw_model), raw_effort
    if key == ANTIGRAVITY and model and not effort:
        effort = agy_model(model)[1]  # only from the verified table
    cleaned_effort = clean_value(effort)
    return provider_model(key, model), (
        cleaned_effort if cleaned_effort in EFFORTS else None
    )


def make_ident(
    key: str, session: str, seen: Seen, subagent: str | None = None
) -> Ident:
    """Final trailer values from raw-ish parts. Unknowns are omitted, never guessed."""
    model, effort = model_effort(key, seen.model, seen.effort)
    cleaned_version = clean_value(seen.version)
    return Ident(
        root=session,
        harness=SLUGS[key] + (f":{cleaned_version}" if cleaned_version else ""),
        subagent=subagent or None,
        model=model,
        effort=effort,
        surface=as_str(seen.surface),
    )


def parse_stdin(data: Json) -> tuple[str | None, str | None, str | None]:
    """Hook stdin -> (raw session ID, model, effort); each None if absent."""
    sid = first_str(
        data, "session_id", "sessionId", "conversationId", "conversation_id"
    )
    model = first_str(data, "model", "modelName", "to_model")
    effort = data.get("effort")
    nested = as_dict(effort)
    return sid, model, as_str(nested.get("level") if nested else effort)


def read_tail(path: Path, size: int) -> list[str] | None:
    """The lines in the last ``size`` bytes of a file, or None if unreadable."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - size))
            return handle.read().decode(errors="replace").splitlines()
    except OSError:
        return None


def parse_line(line: str) -> Json | None:
    """One JSON-lines record, or None if it is not a JSON object."""
    try:
        return as_dict(json.loads(line))
    except ValueError:
        return None


def transcript_model(path: object) -> str | None:
    """Claude: the last real assistant ``message.model`` in a transcript tail."""
    lines = read_tail(Path(path), CLAUDE_TAIL) if isinstance(path, str) else None
    for line in reversed(lines or []):
        message = as_dict((parse_line(line) or {}).get("message"))
        model = as_str(message.get("model")) if message else None
        if model and not model.startswith("<"):
            return model
    return None


# --------------------------------------------------------- records and commands


def write_record(sid_hash: str, updates: Json, cwd: Path | None = None) -> None:
    """Merge the non-empty ``updates`` into an agent's session record."""
    interim = interim_dir(cwd)
    if not interim:
        return
    path = interim / "sessions" / f"{hx(sid_hash)}.json"
    with locked(interim):
        rec = read_record(path)
        rec.update(
            {k: v for k, v in updates.items() if v}
        )  # never overwrite known with missing
        write_json(path, rec)


def load_record(hashed: str, cwd: Path | None = None) -> Json:
    """An agent's session record, or an empty dict."""
    interim = interim_dir(cwd)
    return read_record(interim / "sessions" / f"{hx(hashed)}.json") if interim else {}


def child_transcript(data: Json) -> str | None:
    """A Claude subagent's transcript path.

    ``agent_transcript_path`` (SubagentStop) is authoritative; otherwise the path
    derives from the main transcript:
    ``<main transcript sans .jsonl>/subagents/agent-<agent_id>.jsonl``.
    """
    explicit = as_str(data.get("agent_transcript_path"))
    transcript, agent_id = as_str(data.get("transcript_path")), data.get("agent_id")
    if explicit:
        return explicit
    if transcript and agent_id:
        return str(
            Path(transcript).with_suffix("") / "subagents" / f"agent-{agent_id}.jsonl"
        )
    return None


def rewrite_output(agent_hash: str, tool_input: Json) -> Json | None:
    """Optional comparison path: carry the executing agent into the command env."""
    cmd = tool_input.get("command")
    if not isinstance(cmd, str):
        return None
    updated = {**tool_input, "command": f"export {AGENT_ENV}={agent_hash}; {cmd}"}
    return {
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": updated}
    }


def record_child(data: Json, effort: str | None) -> str:
    """Record a Claude subagent from hook stdin; return its agent hash."""
    agent = sha256_64(data["agent_id"])
    transcript = child_transcript(data)
    write_record(
        agent,
        {
            "harness": SLUGS[CLAUDE],
            "root": sha256_64(data["session_id"]),
            "agent_type": data.get("agent_type"),
            "model": transcript_model(transcript),
            "effort": effort,
            "transcript": transcript,
        },
        cwd_of(data),
    )
    return agent


def cwd_of(data: Json) -> Path | None:
    """The hook's working directory, if it gave a usable one."""
    cwd = as_str(data.get("cwd"))
    return Path(cwd) if cwd else None


def cmd_hashes(cmd: str) -> list[str]:
    """SHA-256 of a command as given and stripped (the harness may trim it)."""
    return sorted({hashlib.sha256(c.encode()).hexdigest() for c in (cmd, cmd.strip())})


def rec_ts(rec: Json) -> float:
    """A stored record's timestamp (our own store: trusted to be a number)."""
    ts = rec.get("ts", 0)
    return cast("float", ts)  # pragma: no mutate -- a runtime no-op


def rec_hashes(rec: Json) -> set[str]:
    """A stored command record's command hashes (our own store: trusted)."""
    hashes = rec.get("cmd", [])
    return set(cast("list[str]", hashes))  # pragma: no mutate -- a runtime no-op


def command_records(interim: Path, root: str) -> Iterator[tuple[Path, Json]]:
    """Pending (not done) command records for a root session."""
    for path in (interim / "cmds" / hx(root)).glob("*.json"):
        rec = read_record(path)
        if rec and not rec.get("done"):
            yield path, rec


def record_command(
    root: str, agent: str | None, cmd: object, cwd: Path | None = None
) -> None:
    """Record a Bash command about to run, by hash, with the agent running it."""
    interim = interim_dir(cwd)
    if not interim or not isinstance(cmd, str):
        return
    write_json(
        interim / "cmds" / hx(root) / f"{uuid.uuid4().hex}.json",
        {"agent": agent, "cmd": cmd_hashes(cmd), "ts": time.time(), "done": None},
    )


def finish_command(
    root: str, cmd: object, agent: str | None, cwd: Path | None = None
) -> None:
    """Mark the newest pending record for (agent, command) done.

    A later identical command is then unambiguous.
    """
    interim = interim_dir(cwd)
    if not interim or not isinstance(cmd, str):
        return
    hashes = set(cmd_hashes(cmd))
    with locked(interim):
        candidates = [
            (path, rec)
            for path, rec in command_records(interim, root)
            if rec.get("agent") == agent and hashes & rec_hashes(rec)
        ]
        best = max(candidates, key=lambda item: rec_ts(item[1]), default=None)
        if best:
            best[1]["done"] = time.time()
            write_json(*best)


def ps_row(pid: str) -> tuple[str, str] | None:
    """(parent PID, command line) of a process, or None if it is gone.

    Also None when ps can't run at all: a sandbox can deny starting it, not
    just its process lookup.
    """
    try:
        result = subprocess.run(  # nosec B603 B607
            ["ps", "-ww", "-o", "ppid=,command=", "-p", pid],
            capture_output=True,
            text=True,
            check=False,
        )
    except PermissionError:
        return None
    line = result.stdout.strip()
    if result.returncode != 0 or not line:
        return None
    ppid, _, cmd = line.partition(" ")
    return ppid.strip(), cmd.strip()


def ancestry(pid: int | None = None, limit: int = ANCESTRY_LIMIT) -> list[str]:
    """Command lines from this process up to and including the claude process."""
    out: list[str] = []
    current = str(pid or os.getpid())
    for _ in range(limit):
        row = ps_row(current)
        if row is None:
            break
        ppid, cmd = row
        out.append(cmd)
        if Path(cmd.partition(" ")[0]).name == "claude" or ppid in {"", "0", "1"}:
            break
        current = ppid
    return out


def command_candidates(cmdline: str) -> list[str]:
    """Strings that could equal ``tool_input.command`` in one ancestor's command line.

    Claude Code (2.1.316) runs ``<shell> -c 'source <snapshot> ... &&
    eval '<command>' < /dev/null && pwd -P >| <file>'``.
    ps flattens argv, but the ``-c`` argument is itself shell text, so shlex
    recovers the eval operand exactly (embedded single quotes survive the
    ``'"'"'`` escape).
    """
    try:
        tokens = shlex.split(cmdline)
    except ValueError:
        return []
    return [tokens[i + 1] for i, tok in enumerate(tokens[:-1]) if tok == "eval"]


def match_command_agent(
    root: str,
    command_lines: list[str],
    cwd: Path | None = None,
    now: float | None = None,
) -> tuple[str | None, bool]:
    """Match the process ancestry to a recorded command: (agent hash, ambiguous).

    None means the main agent (or no match).
    """
    interim = interim_dir(cwd)
    if not interim:
        return None, False
    now = now or time.time()
    hashes = {
        h
        for line in command_lines
        for cand in command_candidates(line)
        for h in cmd_hashes(cand)
    }
    agents = {
        as_str(rec.get("agent"))
        for _, rec in command_records(interim, root)
        if now - rec_ts(rec) < CMD_WINDOW and hashes & rec_hashes(rec)
    }
    if len(agents) == 1:
        return agents.pop(), False
    return None, bool(agents)  # exactly one agent returned above


# -------------------------------------------------------- repo and edit receipts


def rel_to_repo(path: object, base: Path | None = None) -> tuple[str, Repo] | None:
    """(repo-relative path, repo) of a file, or None when outside any repo."""
    if not isinstance(path, str) or not path:
        return None
    target = Path(path)
    if not target.is_absolute():
        target = (base or Path.cwd()) / target
    existing = next(p for p in target.parents if p.is_dir())
    repo = repo_info(existing)
    if not repo:
        return None
    rel = Path(
        os.path.relpath(existing.resolve() / target.relative_to(existing), repo.top)
    )
    return None if rel.parts[:1] == ("..",) else (rel.as_posix(), repo)


def blob_of(top: Path, rel: str, *, store: bool = False) -> str | None:
    """The git blob hash of a work-tree file, or None if it is not a file.

    ``store`` also writes the blob into the object database (``-w``).
    """
    path = top / rel
    if not path.is_file():
        return None
    flags = ("-w",) if store else ()
    code, out = git("hash-object", *flags, str(path), cwd=top)  # absolute path
    return out if code == 0 else None


def write_edit(
    ident: Ident,
    path: object,
    base: Path | None = None,
    *,
    store: bool = False,
) -> None:
    """Store one edit receipt for ``path``; nothing outside a repository.

    ``store`` also writes the blob into the object database.
    """
    found = rel_to_repo(path, base)
    if not found:
        return
    rel, repo = found
    receipt: Json = {
        "root": ident.root,
        "subagent": ident.subagent,
        "harness": ident.harness,
        "model": ident.model,
        "effort": ident.effort,
        "surface": ident.surface,
        "path": rel,
        "blob": blob_of(repo.top, rel, store=store),
        "consumed": False,
        "ts": time.time(),
    }
    write_json(
        repo.interim / EDITS / hx(ident.root) / f"{uuid.uuid4().hex}.json", receipt
    )


def diff_paths(text: str) -> list[str]:
    """File paths named by a unified or git diff."""
    return re.findall(r"^\+\+\+ (?:b/)?(\S.*)$", text, re.MULTILINE) + re.findall(
        r"^diff --git a/.+ b/(.+)$", text, re.MULTILINE
    )


def walk_paths(node: object) -> list[str]:
    """Paths found anywhere in a nested diff structure of dicts, lists and text."""
    if isinstance(node, str):
        return diff_paths(node)
    if isinstance(node, list):
        items = cast("list[object]", node)  # pragma: no mutate -- a runtime no-op
        return [p for item in items for p in walk_paths(item)]
    fields = as_dict(node)
    if fields is None:
        return []
    out = [
        path
        for k in ("filePath", "file_path", "path")
        if (path := as_str(fields.get(k)))
    ]
    return out + [p for value in fields.values() for p in walk_paths(value)]


def edit_paths_from_bash(resp: object) -> list[str]:
    """Paths from ``tool_response.bashEditDiff`` (undocumented shape).

    Accepts a dict, a list or diff text.
    """
    diff = (as_dict(resp) or {}).get("bashEditDiff")
    if diff is None:
        return []
    return [p for p in dict.fromkeys(walk_paths(diff)) if p != "/dev/null"]


def load_edits(repo: Repo, root: str) -> list[tuple[Path, Json]]:
    """Unconsumed edit receipts for a root session."""
    out = []
    for path in (repo.interim / EDITS / hx(root)).glob("*.json"):
        rec = read_record(path)
        if rec and not rec.get("consumed"):
            out.append((path, rec))
    return out


# ------------------------------------------------------------- Claude hook events


def claude_ident(data: Json, env: Mapping[str, str]) -> Ident:
    """The identity of the Claude agent (main or subagent) behind a tool hook."""
    root = sha256_64(data["session_id"])
    agent = data.get("agent_id")
    effort = parse_stdin(data)[2]
    if agent:
        model, sub = transcript_model(child_transcript(data)), sha256_64(agent)
    else:
        model, sub = transcript_model(data.get("transcript_path")), None
    ver = version(CLAUDE, env) or load_record(root, cwd_of(data)).get("version")
    return make_ident(CLAUDE, root, Seen(ver, model, effort, surface(CLAUDE, env)), sub)


def tool_input_of(data: Json) -> Json:
    """The hook's ``tool_input`` object, or an empty dict."""
    return as_dict(data.get("tool_input")) or {}


def handle_claude_bash(
    event: str, data: Json, env: Mapping[str, str], agent: str | None
) -> None:
    """Bash command records, plus edit receipts when Claude reports a bash edit."""
    root, cwd = sha256_64(data["session_id"]), cwd_of(data)
    tool_input = tool_input_of(data)
    cmd = tool_input.get("command")
    if event == "PreToolUse":
        record_command(root, agent, cmd, cwd)
        if env.get(REWRITE_FLAG) == "1" and agent:
            out = rewrite_output(agent, tool_input)
            if out:
                print(json.dumps(out))
        return
    finish_command(root, cmd, agent, cwd)
    if event == "PostToolUse":
        paths = edit_paths_from_bash(data.get("tool_response"))
        if paths:
            ident = claude_ident(data, env)
            for path in paths:
                write_edit(ident, path, cwd)


def handle_claude(data: Json, env: Mapping[str, str]) -> None:
    """Record a Claude Code hook event: agent record, commands and edits."""
    event, tool = data.get("hook_event_name"), data.get("tool_name")
    effort = parse_stdin(data)[2]
    agent = None
    if data.get("agent_id"):
        agent = record_child(data, effort)
    else:
        write_record(
            sha256_64(data["session_id"]),
            {
                "harness": SLUGS[CLAUDE],
                "version": version(CLAUDE, env),
                "model": transcript_model(data.get("transcript_path")),
                "effort": effort,
            },
            cwd_of(data),
        )
    if tool == "Bash" and event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
        handle_claude_bash(event, data, env, agent)
    elif event == "PostToolUse" and tool in CLAUDE_EDIT_TOOLS:
        tool_input = tool_input_of(data)
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if file_path:
            write_edit(claude_ident(data, env), file_path, cwd_of(data))


# ----------------------------------------------------------------- Codex rollouts


def codex_home(env: Mapping[str, str]) -> Path:
    """The Codex home directory."""
    return Path(env.get("CODEX_HOME") or Path("~/.codex").expanduser())


def codex_rollout(thread_id: str, env: Mapping[str, str]) -> Path | None:
    """The newest ``<home>/sessions/Y/M/D/rollout-<ts>-<thread>.jsonl`` (read only)."""
    if not THREAD_ID.fullmatch(thread_id):
        return None
    hits = list(codex_home(env).glob(f"sessions/*/*/*/rollout-*-{thread_id}.jsonl"))
    return max(hits, key=lambda p: p.stat().st_mtime) if hits else None


def rollout_turn_context(path: Path) -> tuple[str | None, str | None]:
    """(model, effort) from the latest ``turn_context`` record in the rollout tail."""
    for line in reversed(read_tail(path, CODEX_TAIL) or []):
        record = parse_line(line) or {}
        payload = as_dict(record.get("payload"))
        if record.get("type") == "turn_context" and payload is not None:
            return as_str(payload.get("model")), as_str(payload.get("effort"))
    return None, None


def rollout_meta(path: Path) -> Json:
    """The ``session_meta`` payload on a rollout's first line, or an empty dict."""
    try:
        with path.open() as handle:
            first = parse_line(handle.readline()) or {}
    except OSError:
        return {}
    payload = first.get("payload") if first.get("type") == "session_meta" else None
    return as_dict(payload) or {}


PATCH_END = r"(?:\\n|\\r|\n|\r|\"|'|`|$)"
PATCH_FILE = re.compile(rf"\*\*\* (?:Add|Update|Delete) File: (.+?){PATCH_END}")
PATCH_MOVE = re.compile(rf"\*\*\* Move to: (.+?){PATCH_END}")


def patch_paths(text: object) -> list[str]:
    """File paths from apply_patch text.

    Reads ``*** Add/Update/Delete File:`` and ``*** Move to:`` lines.

    The patch may sit raw in a custom tool call input, inside a JSON arguments
    string, or inside the JavaScript source of Codex's ``exec`` tool
    (``tools.apply_patch(patch)``), so newlines can be escaped.
    """
    if not isinstance(text, str) or "*** Begin Patch" not in text:
        return []
    found = (m.strip() for rx in (PATCH_FILE, PATCH_MOVE) for m in rx.findall(text))
    return list(dict.fromkeys(found))


def tool_call_paths(record: Json) -> list[str]:
    """apply_patch paths in one rollout line, counting only tool-call records."""
    payload = (
        as_dict(record.get("payload"))
        if record.get("type") == "response_item"
        else None
    )
    if payload is None:
        return []
    if payload.get("type") not in {
        "custom_tool_call",
        "function_call",
        "local_shell_call",
    }:
        return []
    body = payload.get("input")
    if not isinstance(body, str):
        body = payload.get("arguments")
    return patch_paths(
        body if isinstance(body, str) else json.dumps(payload.get("action"))
    )


def rollout_patch_edits(
    path: Path, offset: int = 0, skip_lines: int = 0
) -> tuple[list[str], int]:
    """(paths in order, new offset) for ``apply_patch`` lines after ``offset``.

    Only complete lines count.

    A forked Codex thread replays its parent's history first, including the
    parent's ``apply_patch`` calls. ``skip_lines`` is the length of that
    replayed prefix: reading starts after it, whatever ``offset`` says.
    """
    try:
        with path.open("rb") as handle:
            replayed = len(b"".join(islice(handle, skip_lines)))
            start = max(offset, replayed)
            handle.seek(start)
            data = handle.read()
    except OSError:
        return [], offset
    end = data.rfind(b"\n") + 1
    edits: list[str] = []
    for line in data[:end].decode(errors="replace").splitlines():
        if "Begin Patch" not in line:
            continue
        record = parse_line(line)
        if record:
            edits.extend(tool_call_paths(record))
    return edits, start + end


def codex_threads(root_raw: str, env: Mapping[str, str]) -> list[tuple[Path, Json]]:
    """(rollout path, meta) for the root session's rollouts: root and child threads."""
    out = []
    now = time.time()
    for path in codex_home(env).glob("sessions/*/*/*/rollout-*.jsonl"):
        try:
            if now - path.stat().st_mtime > CODEX_MAX_AGE:
                continue
        except OSError:
            continue
        meta = rollout_meta(path)
        if root_raw in {meta.get("session_id"), meta.get("id")}:
            out.append((path, meta))
    return out


def codex_ident(
    root_raw: str, meta: Json, rollout: Path | None, env: Mapping[str, str]
) -> Ident:
    """The identity of a Codex thread within its root session."""
    tid = as_str(meta.get("id")) or root_raw
    model, effort = rollout_turn_context(rollout) if rollout else (None, None)
    seen = Seen(
        version(CODEX, env) or meta.get("cli_version"),
        model,
        effort,
        # Only plain-string sources (such as exec) count; objects are subagents.
        surface_ok(meta.get("source")),
    )
    return make_ident(
        CODEX, sha256_64(root_raw), seen, sha256_64(tid) if tid != root_raw else None
    )


def replayed_lines(meta: Json) -> int:
    """How many leading rollout lines are a fork's replayed parent history."""
    # A fork's own history starts at this line; before it is the replayed parent.
    replayed = meta.get("subagent_history_start_ordinal")
    # Equivalent mutants: skipping 0 or 1 lines is the same, because line 0
    # is the session_meta and holds no patch, so `> 0` vs `> 1` and
    # `else 0` vs `else 1` cannot be told apart. The pragma has to sit on
    # the line mutmut mutates.
    fork = isinstance(replayed, int) and replayed > 0  # pragma: no mutate
    return replayed if fork else 0  # pragma: no mutate


def codex_scan(root_raw: str, repo: Repo, env: Mapping[str, str]) -> None:
    """Turn new apply_patch calls in this root's rollouts into edit receipts.

    A thread with a hook record (SessionStart/SubagentStart) is skipped: its
    PostToolUse hook already wrote its receipts with the edit-time blob.

    The per-rollout byte offset (``marks/``) advances here so a later commit
    never re-reads them. The receipts' ``consumed`` flag (set by post-commit)
    is what stops double credit, so an aborted commit loses nothing. The scan
    holds the lock, so two concurrent scans never turn one patch into two
    receipts.
    """
    with locked(repo.interim):
        for rollout, meta in codex_threads(root_raw, env):
            tid = as_str(meta.get("id")) or root_raw
            if (repo.interim / "sessions" / f"{hx(sha256_64(tid))}.json").exists():
                continue
            mark_path = repo.interim / "marks" / f"{hx(sha256_64(tid))}.json"
            mark = read_record(mark_path).get("offset", 0)
            offset = cast("int", mark)  # pragma: no mutate -- a runtime no-op
            edits, new = rollout_patch_edits(rollout, offset, replayed_lines(meta))
            if new != offset:
                write_json(mark_path, {"offset": new})
            if edits:
                ident = codex_ident(root_raw, meta, rollout, env)
                for path in dict.fromkeys(edits):
                    write_edit(ident, path, Path(as_str(meta.get("cwd")) or repo.top))


# ------------------------------------------------------------------ Codex hooks

CODEX_PATCH_TOOL = "apply_patch"
CODEX_START_EVENTS = {"SessionStart", "SubagentStart"}


def codex_hook_ident(root_raw: str, data: Json, env: Mapping[str, str]) -> Ident:
    """The identity of the Codex thread (root or subagent) behind a hook.

    The thread is ``agent_id`` or, for the root, ``session_id``. Its model is
    on stdin; version, surface and effort come from its own rollout, which
    ``transcript_path`` names.
    """
    agent = as_str(data.get("agent_id"))
    transcript = as_str(data.get("transcript_path"))
    rollout = Path(transcript) if transcript else None
    meta = {**(rollout_meta(rollout) if rollout else {}), "id": agent or root_raw}
    ident = codex_ident(root_raw, meta, rollout, env)
    model = provider_model(CODEX, parse_stdin(data)[1])
    return replace(ident, model=model or ident.model)


def handle_codex(data: Json, env: Mapping[str, str]) -> None:
    """Record a Codex hook event: thread records and apply_patch edit receipts.

    Anything else is ignored. Codex hooks have no ``CODEX_*`` environment, so
    identity comes from stdin alone.
    """
    root_raw, event = as_str(data.get("session_id")), data.get("hook_event_name")
    patching = event == "PostToolUse" and data.get("tool_name") == CODEX_PATCH_TOOL
    if not root_raw or not (patching or event in CODEX_START_EVENTS):
        return
    ident = codex_hook_ident(root_raw, data, env)
    cwd = cwd_of(data)
    if not patching:
        write_record(
            ident.subagent or ident.root,
            {
                "harness": ident.harness,
                "root": ident.root,
                "agent_type": data.get("agent_type"),
                "model": ident.model,
                "effort": ident.effort,
                "surface": ident.surface,
                "transcript": data.get("transcript_path"),
            },
            cwd,
        )
        return
    for path in patch_paths(tool_input_of(data).get("command")):
        write_edit(ident, path, cwd, store=True)


# --------------------------------------------------------------------------- agy


def agy_parent(brain_root: Path, cid: str) -> str | None:
    """Parent conversation ID of an agy child, from the child's own brain dir.

    The first ``invoke_subagent`` message addressed to the child names it.
    """
    messages_dir = brain_root / cid / ".system_generated" / "messages"
    try:
        paths = sorted(messages_dir.iterdir())
    except OSError:
        return None
    for path in paths:
        if path.suffix != ".json" or path.name == "read.json":
            continue
        try:
            message = json.loads(path.read_text())
            tool = message["sourceMetadata"]["tool"]
            if (
                message.get("recipient") == cid
                and tool["toolCall"]["name"] == "invoke_subagent"
            ):
                parent = message.get("sender") or tool.get("conversationId")
                return parent if parent and parent != cid else None
        except OSError, ValueError, KeyError, TypeError:
            continue
    return None


def agy_root(brain_root: Path, cid: str, max_depth: int = 8) -> str:
    """Walk parent links up to the root conversation (cycle- and depth-safe)."""
    seen, current = {cid}, cid
    for _ in range(max_depth):
        parent = agy_parent(brain_root, current)
        if not parent or parent in seen:
            break
        seen.add(parent)
        current = parent
    return current


def agy_brain_root(rec: Json, env: Mapping[str, str]) -> Path | None:
    """The agy ``brain`` directory: recorded, from app data, or the default."""
    app_data = env.get("ANTIGRAVITY_APP_DATA_DIR")
    candidates = (
        Path(brain) if (brain := as_str(rec.get("brain_root"))) else None,
        Path(app_data) / "brain" if app_data else None,
        Path("~/.gemini/antigravity-cli/brain").expanduser(),
    )
    return next((c for c in candidates if c and c.is_dir()), None)


def agy_tool(data: Json) -> tuple[object, object]:
    """(tool name, args) from agy hook stdin."""
    call = as_dict(data.get("toolCall")) or {}
    return (
        call.get("name") or data.get("toolName") or data.get("tool_name"),
        call.get("args") or data.get("toolInput"),
    )


def agy_edit_path(args: object) -> str | None:
    """The edited file's path from an agy tool call's args (dict or JSON text)."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return None
    fields = as_dict(args)
    if fields is None:
        return None
    return next((p for key in AGY_PATH_KEYS if (p := as_str(fields.get(key)))), None)


def agy_ident(
    cid: str, rec: Json, env: Mapping[str, str], brain: Path | None = None
) -> Ident:
    """The identity of an agy conversation, resolving its root through ``brain``."""
    root_raw = agy_root(brain, cid) if brain else cid
    seen = Seen(
        version(ANTIGRAVITY, env),
        rec.get("model"),
        rec.get("effort"),
        surface(ANTIGRAVITY, env),
    )
    return make_ident(
        ANTIGRAVITY,
        sha256_64(root_raw),
        seen,
        sha256_64(cid) if root_raw != cid else None,
    )


# ---------------------------------------------------------------- record entry point


def read_hook_stdin() -> Json:
    """Hook JSON from stdin; an empty dict if empty, invalid or not an object."""
    try:
        data = json.loads(sys.stdin.read())
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def record_agy(sid: str, data: Json, rec: Json, env: Mapping[str, str]) -> None:
    """agy: write an edit receipt for a successful edit tool call."""
    tool, args = agy_tool(data)
    # agy stdin has no event name; only PostToolUse carries an `error` key
    # (empty on success).
    if tool in AGY_EDIT_TOOLS and "error" in data and not data["error"]:
        path = agy_edit_path(args)
        if path:
            write_edit(
                agy_ident(sid, rec, env, agy_brain_root(rec, env)),
                path,
                cwd_of(data),
            )


def cmd_record(harness: str, env: Mapping[str, str]) -> int:
    """Harness hook entry point: persist what the event reveals."""
    if harness not in SLUGS:
        return 0
    data = read_hook_stdin()
    if harness == CODEX:
        handle_codex(data, env)
        return 0
    sid, model, effort = parse_stdin(data)
    if harness == CLAUDE:
        if sid:
            handle_claude({**data, "session_id": sid}, env)
        return 0
    sid = sid or (detect(env) or (None, None))[1]
    interim = interim_dir(cwd_of(data))
    if not sid or not interim:
        return 0
    path = interim / "sessions" / f"{hx(sha256_64(sid))}.json"
    with locked(interim):
        rec = read_record(path)
        rec["harness"] = SLUGS[harness]
        if model and not model.startswith("<"):
            rec["model"] = model
        if effort:
            rec["effort"] = effort
        brain = as_str(data.get("artifactDirectoryPath"))
        if brain:
            rec["brain_root"] = str(Path(brain).parent)
        write_json(path, rec)
    record_agy(sid, data, rec, env)
    return 0


# ------------------------------------------------------------- committer identity


def claude_committer(
    raw: str, env: Mapping[str, str], command_lines: list[str] | None
) -> Committer:
    """The Claude agent running git commit, found by process-ancestry matching."""
    root = sha256_64(raw)
    root_rec = load_record(root)
    ver = version(CLAUDE, env) or root_rec.get("version")
    surf = surface(CLAUDE, env)
    if env.get(AGENT_ENV) and HASH_RE.fullmatch(env[AGENT_ENV]):
        sub = env[AGENT_ENV]  # rewrite path (comparison only)
    else:
        sub, _ambiguous = match_command_agent(
            root, ancestry() if command_lines is None else command_lines
        )
    child_rec: Json = load_record(sub) if sub else {}
    if sub and child_rec.get("root") != root:
        # Unknown or foreign agent record: treat as the main agent.
        sub, child_rec = None, dict[str, object]()
    root_ident = make_ident(
        CLAUDE, root, Seen(ver, root_rec.get("model"), root_rec.get("effort"), surf)
    )
    if sub:
        # Re-read the transcript at commit time: it can trail the hook that recorded it.
        model = child_rec.get("model") or transcript_model(child_rec.get("transcript"))
        ident = make_ident(
            CLAUDE, root, Seen(ver, model, child_rec.get("effort"), surf), sub
        )
    else:
        effort = env.get("CLAUDE_EFFORT") or root_rec.get("effort")
        ident = make_ident(CLAUDE, root, Seen(ver, root_rec.get("model"), effort, surf))
    return Committer(CLAUDE, ident, root_ident)


def codex_committer(raw: str, env: Mapping[str, str]) -> Committer:
    """The Codex thread running git commit, plus the root session."""
    thread = env.get("CODEX_THREAD_ID") or raw
    thread_rollout, root_rollout = codex_rollout(thread, env), codex_rollout(raw, env)
    thread_meta = rollout_meta(thread_rollout) if thread_rollout else {}
    root_meta = rollout_meta(root_rollout) if root_rollout else {}
    return Committer(
        CODEX,
        codex_ident(raw, {**thread_meta, "id": thread}, thread_rollout, env),
        codex_ident(raw, {**root_meta, "id": raw}, root_rollout, env),
    )


def agy_committer(raw: str, env: Mapping[str, str]) -> Committer:
    """The agy conversation running git commit, plus its root conversation."""
    rec = load_record(sha256_64(raw))
    brain = agy_brain_root(rec, env)
    ident = agy_ident(raw, rec, env, brain)
    root_raw = agy_root(brain, raw) if brain else raw
    if root_raw == raw:
        return Committer(ANTIGRAVITY, ident, ident)
    root_ident = agy_ident(root_raw, load_record(sha256_64(root_raw)), env)
    return Committer(ANTIGRAVITY, ident, root_ident)


def committer_identity(
    env: Mapping[str, str], command_lines: list[str] | None = None
) -> Committer | None:
    """Identity of the agent running git commit, or None outside a harness."""
    detected = detect(env)
    if not detected:
        return None
    key, raw = detected
    if key == CLAUDE:
        return claude_committer(raw, env, command_lines)
    if key == CODEX:
        return codex_committer(raw, env)
    return agy_committer(raw, env)


# ------------------------------------------------------------------ role decision


def staged_info(cwd: Path | None = None) -> tuple[list[str], dict[str, str]]:
    """(staged paths, path -> staged blob hash)."""
    _, out = git("diff", "--cached", "--name-only", "-z", cwd=cwd)
    paths = [p for p in out.split("\0") if p]  # empty output when git fails
    blobs: dict[str, str] = {}
    if paths:
        _, out = git("ls-files", "-s", "-z", "--", *paths, cwd=cwd)
        for entry in out.split("\0"):
            meta, _, path = entry.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[2] == "0":  # noqa: PLR2004 -- mode, blob, stage
                blobs[path] = parts[1]
    return paths, blobs


def receipt_rank(receipt: Json, blobs: Mapping[str, str]) -> tuple[int, float]:
    """Sort key: receipts whose blob is the staged blob first, then newest."""
    blob = receipt.get("blob")
    is_staged_blob = bool(blob) and blob == blobs.get(str(receipt["path"]))
    return (0 if is_staged_blob else 1, -rec_ts(receipt))


def decide(
    committer: Committer,
    receipts: list[Json],
    staged: set[str],
    blobs: Mapping[str, str],
) -> tuple[list[Ident], list[Ident]]:
    """Decide the trailer roles: (Generated-by identities, Assisted-by identities).

    Pure. See the plan's section 10a, "Which key".
    """
    matched = [r for r in receipts if r["path"] in staged]
    if matched:
        # The last writer (blob equals the staged blob) first, then everyone else
        # who edited staged paths.
        matched.sort(key=lambda r: receipt_rank(r, blobs))
        gen = list(dict.fromkeys(Ident.from_receipt(r) for r in matched))
    else:
        gen = [committer.ident]  # fallback: no edit evidence on staged paths
    gen_agents = {i.agent_key() for i in gen}
    assisted = []
    if committer.ident.agent_key() not in gen_agents:
        assisted.append(committer.ident)
    if committer.ident.subagent and committer.root_ident.agent_key() not in gen_agents:
        assisted.append(committer.root_ident)
    return gen, assisted


def enrich(ident: Ident, committer: Committer) -> Ident:
    """Fill what the edit-time hook could not see.

    The harness version (the hook env lacks ``CLAUDE_CODE_EXECPATH``) comes from
    the committer of the same harness. A Claude child's model and effort come
    from its record, because the child transcript can trail the first
    PostToolUse. Surface is per session, and an edit hook env may not expose it
    (agy). Never inherits a model from another agent.
    """
    slug = ident.harness.partition(":")[0]
    committer_harness = committer.ident.harness
    same_harness = committer_harness.partition(":")[0] == slug
    if same_harness and ":" not in ident.harness and ":" in committer_harness:
        ident = replace(ident, harness=committer_harness)
    if same_harness and not ident.surface and committer.ident.surface:
        ident = replace(ident, surface=committer.ident.surface)
    if (
        ident.subagent
        and committer.key == CLAUDE
        and not (ident.model and ident.effort)
    ):
        child_rec = load_record(ident.subagent)
        if child_rec.get("root") == ident.root:
            model, effort = model_effort(
                CLAUDE,
                child_rec.get("model") or transcript_model(child_rec.get("transcript")),
                child_rec.get("effort"),
            )
            ident = replace(
                ident, model=ident.model or model, effort=ident.effort or effort
            )
    return ident


LLM_LINE = re.compile(r"^(Generated-by|Assisted-by): (LLM\b.*)$", re.MULTILINE)
LLM_LINES = re.compile(r"^(?:Generated-by|Assisted-by): LLM\b.*\n?", re.MULTILINE)
AGENT_ATTR = re.compile(r"(?<![^\s;])(session|subagent)=([^\s;]+)")
AMEND_FLAGS = {"--am", "--ame", "--amen", "--amend"}  # git takes unique prefixes

type Trailer = tuple[str, str]


def llm_trailers(text: str) -> list[Trailer]:
    """The (key, value) of each ``LLM`` trailer line in a message."""
    return [(m[1], m[2]) for m in LLM_LINE.finditer(text)]


def trailer_agent(value: str) -> tuple[str | None, str | None]:
    """(session, subagent) named by a trailer value; None where absent."""
    attrs = dict(AGENT_ATTR.findall(value))
    return attrs.get("session"), attrs.get("subagent")


def merge_trailers(found: list[Trailer]) -> list[Trailer]:
    """Deduplicated, ``Generated-by`` first; Generated-by beats Assisted-by.

    An agent with any ``Generated-by`` loses its ``Assisted-by`` lines.
    """
    generated = {trailer_agent(v) for k, v in found if k == KEY_GEN}
    kept = [
        (k, v) for k, v in found if k == KEY_GEN or trailer_agent(v) not in generated
    ]
    return sorted(dict.fromkeys(kept), key=lambda kv: kv[0] != KEY_GEN)


def add_trailers(
    msgfile: Path,
    gen: list[Ident],
    assisted: list[Ident],
    kept: list[Trailer] | None = None,
) -> None:
    """Rewrite the message's ``LLM`` trailers as one merged, ordered set.

    The set is the message's own ``LLM`` trailers, ``kept`` (an amended
    commit's) and the new ones. A human's Signed-off-by (if any) is left where
    git put it.
    """
    text = msgfile.read_text()
    new = [(KEY_GEN, format_value(i.attrs())) for i in gen] + [
        (KEY_ASSIST, format_value(i.attrs())) for i in assisted
    ]
    merged = merge_trailers([*llm_trailers(text), *(kept or []), *new])
    args = [f"--trailer={key}: {value}" for key, value in merged]
    bare = msgfile.with_name(msgfile.name + ".ascm")
    bare.write_text(LLM_LINES.sub("", text))
    code, out = git(
        "interpret-trailers", "--if-exists", "addIfDifferent", *args, str(bare)
    )
    bare.unlink()
    if code == 0:
        msgfile.write_text(out + "\n")


def amending(command_lines: list[str]) -> bool:
    """Whether the nearest ``git ... commit`` in the ancestry has ``--amend``.

    ps flattens argv, so a message word ``--amend`` (``-m "fix --amend"``)
    reads as the flag too; the cost is only keeping the parent's trailers.
    """
    for line in command_lines:
        tokens = line.split()
        if tokens and Path(tokens[0]).name == "git" and "commit" in tokens:
            args = tokens[tokens.index("commit") + 1 :]
            return bool(AMEND_FLAGS & set(takewhile(lambda t: t != "--", args)))
    return False


def amended_trailers(top: Path) -> list[Trailer]:
    """HEAD's ``LLM`` trailers when this commit replaces HEAD (``--amend``)."""
    if not amending(ancestry()):
        return []
    _, msg = git("log", "-1", "--format=%B", "HEAD", cwd=top)
    return llm_trailers(msg)


def unstaged_blobs(top: Path, staged: set[str]) -> dict[str, str]:
    """The work-tree blob of each staged file whose work tree differs from the index."""
    _, out = git("diff", "--name-only", "-z", cwd=top)
    found = ((p, blob_of(top, p)) for p in out.split("\0") if p in staged)
    return {path: blob for path, blob in found if blob}


def committing(
    edits: list[tuple[Path, Json]], staged: set[str], unstaged: Mapping[str, str]
) -> list[tuple[Path, Json]]:
    """The receipts this commit contains: for a staged path, and not still unstaged.

    A receipt whose blob is exactly the path's unstaged work-tree content records
    an edit made after the path was staged. That edit is not in this commit, so
    it waits for the commit that stages it.
    """
    return [
        (path, rec)
        for path, rec in edits
        if rec["path"] in staged
        and not (rec["path"] in unstaged and rec.get("blob") == unstaged[rec["path"]])
    ]


def write_claim(repo: Repo, root: str, receipts: list[Path]) -> None:
    """Record the receipts the trailers credit, keyed by the tree being committed.

    Post-commit consumes them once a commit of exactly that tree exists. A
    failed attempt leaves only a claim that a retry of the same tree rewrites.
    """
    code, tree = git("write-tree", cwd=repo.top)
    if code == 0:
        write_json(
            repo.interim / CLAIMS / f"{tree}.json",
            {"root": root, "receipts": sorted(p.name for p in receipts)},
        )


def cmd_trailer(msgfile: str, source: str | None, env: Mapping[str, str]) -> int:
    """prepare-commit-msg: stamp ``Generated-by`` and ``Assisted-by``.

    An amend keeps every ``LLM`` trailer of the commit it replaces, even with a
    new ``-m``: post-commit consumed that commit's receipts, so they cannot be
    rebuilt. When no receipt matches and the message already has a
    ``Generated-by`` (such as a message-only amend), the committer fallback is
    left out.
    """
    if source in {"merge", "squash"}:
        return 0
    repo = repo_info()
    if not repo:
        return 0
    path = Path(msgfile)
    kept = amended_trailers(repo.top)
    committer = committer_identity(env)
    if not committer:
        if kept:
            add_trailers(path, [], [], kept)
        return 0
    refresh_codex(committer, repo, env)
    paths, blobs = staged_info(repo.top)
    staged = set(paths)
    edits = committing(
        load_edits(repo, committer.ident.root), staged, unstaged_blobs(repo.top, staged)
    )
    gen, assisted = decide(committer, [rec for _, rec in edits], staged, blobs)
    present = [*llm_trailers(path.read_text()), *kept]
    if not edits and any(key == KEY_GEN for key, _ in present):
        gen, assisted = list[Ident](), list[Ident]()
    add_trailers(path, [enrich(i, committer) for i in gen], assisted, kept)
    write_claim(repo, committer.ident.root, [p for p, _ in edits])
    return 0


def cmd_consume() -> int:
    """post-commit: consume the receipts HEAD's trailers credited (its claim).

    Only post-commit consumes, so nothing is consumed unless a commit exists.
    """
    repo = repo_info()
    if not repo:
        return 0
    _, tree = git("rev-parse", "HEAD^{tree}", cwd=repo.top)
    claim_path = repo.interim / CLAIMS / f"{tree}.json"
    with locked(repo.interim):
        claim = read_record(claim_path)
        if not claim:
            return 0
        folder = repo.interim / EDITS / hx(str(claim["root"]))
        for name in cast("list[str]", claim["receipts"]):
            rec = read_record(folder / name)
            if rec:
                rec["consumed"] = True
                write_json(folder / name, rec)
        claim_path.unlink()
    return 0


# ------------------------------------------------------------------ stamp-docs

type Entry = dict[str, str]

DOC_FIELDS = (
    "role",
    "harness",
    "model",
    "effort",
    "surface",
    "session",
    "subagent",
    "at",
)
DOC_REQUIRED = frozenset({"role", "harness", "model", "at"})
HASHED_ID = r"sha-256-64:[0-9a-f]{16}"
# The contributor patterns of docs/schemas/frontmatter.schema.json. A surface is
# further limited to printable ASCII so that it always round-trips through YAML.
DOC_PATTERNS = {
    name: re.compile(pattern)
    for name, pattern in {
        "role": r"generated|assisted",
        "harness": r"(claude-code|codex|antigravity)(:[0-9A-Za-z][0-9A-Za-z._+-]*)?",
        "model": r"(anthropic|openai|gcp\.gemini):[0-9A-Za-z][0-9A-Za-z._-]*",
        "effort": r"[a-z0-9][a-z0-9._-]*",
        "surface": r"(?:(?![;,])[!-~])+",
        "session": HASHED_ID,
        "subagent": HASHED_ID,
        "at": r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
    }.items()
}
PLAIN_SCALAR = re.compile(r"[A-Za-z]([A-Za-z0-9._:/+-]*[A-Za-z0-9._/+-])?")
YAML_WORDS = {"null", "true", "false", "yes", "no", "on", "off", "y", "n"}
# Reserved document names carry no `generated` list: AGENTS.md and CLAUDE.md are
# read verbatim by the harnesses, index.md and log.md follow the OKF index rules.
BARE_DOCS = {"AGENTS.md", "CLAUDE.md", "index.md", "log.md"}
# Fixtures, not documents: skipped like the docs checker (and Go's tooling) does.
TESTDATA = "testdata"
ITEM_LINE = re.compile(r"( *)- ([a-z]+): (.*)")
FIELD_LINE = re.compile(r"( *)([a-z]+): (.*)")
QUOTED = re.compile(r'"((?:[^"\\]|\\["\\])*)"')
SINGLE_QUOTED = re.compile(r"'([^']*)'")
PLAIN_VALUE = re.compile(r"[A-Za-z0-9][^\s#]*")
ESCAPED = re.compile(r'\\(["\\])')
DEFAULT_INDENT = 2


@dataclass
class DocEntry:
    """One parsed ``generated`` list item: its lines and its field values."""

    first: int
    last: int
    indent: int
    fields: Entry


def utc(timestamp: float) -> str:
    """A UTC ISO 8601 time with whole seconds and a Z suffix."""
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_entry(entry: Mapping[str, str]) -> bool:
    """True when the entry is a complete contributor the schema accepts."""
    return (
        entry.keys() >= DOC_REQUIRED
        and entry.keys() <= DOC_PATTERNS.keys()
        and all(DOC_PATTERNS[name].fullmatch(value) for name, value in entry.items())
    )


type ContributorKey = tuple[str, str, str | None, str | None]


def contributor_key(entry: Mapping[str, str]) -> ContributorKey:
    """Who a contributor is: harness slug (no version), model, session, subagent."""
    return (
        entry["harness"].partition(":")[0],
        entry["model"],
        entry.get("session"),
        entry.get("subagent"),
    )


def yaml_scalar(value: str) -> str:
    """A YAML scalar for a value: plain when safe, double-quoted otherwise.

    A timestamp (``at``) starts with a digit, so it is always quoted and no YAML
    parser turns it into a timestamp.
    """
    if PLAIN_SCALAR.fullmatch(value) and value.lower() not in YAML_WORDS:
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_entry(entry: Entry, indent: int) -> list[str]:
    """Block-style lines for one list item, fields in canonical order."""
    lines = []
    for number, name in enumerate(n for n in DOC_FIELDS if n in entry):
        lead = " " * indent + "- " if number == 0 else " " * (indent + 2)
        lines.append(f"{lead}{name}: {yaml_scalar(entry[name])}")
    return lines


def unquote(raw: str) -> str | None:
    """The string a plain or quoted YAML scalar holds, or None if unsupported."""
    value = raw.rstrip()
    if match := QUOTED.fullmatch(value):
        return ESCAPED.sub(r"\1", match[1])
    if match := SINGLE_QUOTED.fullmatch(value):
        return match[1]
    return value if PLAIN_VALUE.fullmatch(value) else None


def parse_entries(lines: list[str]) -> list[DocEntry] | None:
    """The list items in ``lines``; None if any line is not plain block YAML."""
    entries: list[DocEntry] = []
    for number, line in enumerate(lines):
        matched = ITEM_LINE.fullmatch(line)
        if matched:
            entries.append(DocEntry(number, number + 1, len(matched[1]), {}))
        else:
            matched = FIELD_LINE.fullmatch(line)
            if not (matched and entries and len(matched[1]) == entries[-1].indent + 2):
                return None
            entries[-1].last = number + 1
        value = unquote(matched[3])
        if value is None or matched[2] in entries[-1].fields:
            return None
        entries[-1].fields[matched[2]] = value
    return entries


def merge_entry(old: Entry, new: Entry) -> Entry:
    """``old`` updated with a newer or older sighting ``new`` of the same contributor.

    Generated beats assisted and never the reverse. Only a newer sighting moves
    ``at`` or replaces effort, surface and a harness version that is already
    known; an older one only fills what is missing.
    """
    if new["role"] == "assisted" and old["role"] == "generated":
        return old
    newer = new["at"] >= old["at"]
    merged = {**old, "role": new["role"]}
    if newer:
        merged["at"] = new["at"]
    for name in ("effort", "surface"):
        if name in new and (newer or name not in old):
            merged[name] = new[name]
    if ":" in new["harness"] and (newer or ":" not in old["harness"]):
        merged["harness"] = new["harness"]
    return merged


def frontmatter_end(lines: list[str]) -> int | None:
    """The index of the closing fence, or None without well-formed frontmatter."""
    if lines[0] != "---":
        return None
    return next(
        (n for n, line in enumerate(lines) if n and line.rstrip(" \t") == "---"), None
    )


def generated_key(lines: list[str], close: int) -> int:
    """The line of the top-level ``generated:`` key, added before the closing fence."""
    # Line 0 is the opening fence, which never starts with the key.
    found = next(
        (n for n, line in enumerate(lines[:close]) if line.startswith("generated:")),
        None,
    )
    if found is None:
        lines.insert(close, "generated:")
        return close
    return found


def latest_generation(entries: Iterable[Entry]) -> list[Entry]:
    """The valid contributors in ``entries``, each once, generated before assisted.

    Repeat sightings of one contributor are merged with ``merge_entry``.
    """
    merged: dict[ContributorKey, Entry] = {}
    for entry in entries:
        if valid_entry(entry):
            key = contributor_key(entry)
            merged[key] = merge_entry(merged[key], entry) if key in merged else entry
    return sorted(merged.values(), key=lambda e: e["role"] != "generated")


def stamp_text(text: str, entries: Iterable[Entry]) -> str:
    """``text`` with its frontmatter's ``generated`` list set to ``entries``.

    The list names only the latest generation: the contributors of this
    commit replace whatever it held, so it never grows past one commit's
    worth. Only the ``generated`` block changes; every other byte is
    preserved. The text comes back unchanged when there is nothing valid to
    stamp, when it has no (LF) frontmatter, when its ``generated`` value is
    not a plain block list, or when the list already holds exactly these
    contributors.
    """
    wanted = latest_generation(entries)
    lines = text.split("\n")
    close = frontmatter_end(lines)
    if not wanted or close is None:
        return text
    key = generated_key(lines, close)
    rest = lines[key].removeprefix("generated:").strip()
    if rest == "[]":
        lines[key] = "generated:"
    elif rest:
        return text
    body = takewhile(lambda line: line.startswith((" ", "- ")), lines[key + 1 :])
    stop = key + 1 + sum(1 for _ in body)
    parsed = parse_entries(lines[key + 1 : stop])
    if parsed is None:
        return text
    if [p.fields for p in parsed] == wanted:
        return text
    indent = parsed[0].indent if parsed else DEFAULT_INDENT
    lines[key + 1 : stop] = [
        line for entry in wanted for line in render_entry(entry, indent)
    ]
    return "\n".join(lines)


def contributor_of(ident: Ident | None, role: str, at: str) -> Entry | None:
    """A ``generated`` list item for an identity; None when its model is unknown."""
    if not ident or not ident.model:
        return None
    return {"role": role, **ident.attrs(), "at": at}


def keep_latest(group: dict[ContributorKey, Entry], entry: Entry | None) -> None:
    """Add the entry unless the group holds a later one for the same contributor."""
    if entry:
        key = contributor_key(entry)
        if key not in group or entry["at"] >= group[key]["at"]:
            group[key] = entry


def delegating_root(
    who: Ident, committer: Committer | None, base: Path
) -> Ident | None:
    """The root agent that delegated to subagent ``who``, if it can be identified."""
    if committer and committer.root_ident.root == who.root:
        return committer.root_ident
    if not who.harness.startswith(SLUGS[CLAUDE]):
        return None
    record = load_record(who.root, base)
    seen = Seen(
        record.get("version") or who.harness.partition(":")[2],
        record.get("model"),
        record.get("effort"),
        who.surface,
    )
    return make_ident(CLAUDE, who.root, seen)


def stamp_entries(
    receipts: list[Json], committer: Committer | None, now: float, base: Path
) -> list[Entry]:
    """The contributors to stamp into one document, from its edit receipts.

    Each receipt's agent is ``generated`` at its latest edit of the file. A
    writer subagent's delegating root is ``assisted`` unless it wrote the file
    too. An agent with no receipt for the file gets nothing, except that with no
    receipts at all the committing agent is ``generated`` at ``now`` (a shell edit).
    """
    generated: dict[ContributorKey, Entry] = {}
    assisted: dict[ContributorKey, Entry] = {}
    for receipt in receipts:
        who = (
            enrich(Ident.from_receipt(receipt), committer)
            if committer
            else Ident.from_receipt(receipt)
        )
        at = utc(rec_ts(receipt))
        keep_latest(generated, contributor_of(who, "generated", at))
        if who.subagent:
            root = delegating_root(who, committer, base)
            keep_latest(assisted, contributor_of(root, "assisted", at))
    if not receipts and committer:
        keep_latest(generated, contributor_of(committer.ident, "generated", utc(now)))
    rest = [e for key, e in assisted.items() if key not in generated]
    return sorted([*generated.values(), *rest], key=lambda e: e["at"])


def all_edits(repo: Repo) -> list[Json]:
    """Every unconsumed edit receipt in the repository, whatever the root session."""
    receipts = (read_record(p) for p in (repo.interim / EDITS).glob("*/*.json"))
    return [rec for rec in receipts if rec and not rec.get("consumed")]


def git_bytes(*args: str, cwd: Path, data: bytes | None = None) -> bytes:
    """Run git on raw bytes; return stdout. Content must not pass through text mode."""
    return subprocess.run(  # nosec B603 B607
        ["git", *args], capture_output=True, cwd=cwd, input=data, check=False
    ).stdout


def staged_docs(top: Path) -> list[tuple[str, str, str]]:
    """(path, mode, blob) of each staged added or modified stampable document."""
    _, out = git(
        "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
        "--diff-filter=AM", cwd=top,
    )  # fmt: skip
    fields = out.split("\0")
    docs = []
    for meta, path in zip(fields[::2], fields[1::2], strict=False):  # pragma: no mutate
        pure = PurePosixPath(path)
        if (
            pure.suffix.lower() == ".md"
            and len(pure.parts) > 1
            and pure.name not in BARE_DOCS
            and TESTDATA not in pure.parts
        ):
            modes = meta.split()
            docs.append((path, modes[1], modes[3]))
    return docs


def decode(raw: bytes) -> str:
    """Text that encodes back to exactly ``raw``, whatever bytes it holds."""
    return raw.decode(errors="surrogateescape")


def stamp_document(top: Path, doc: tuple[str, str, str], entries: list[Entry]) -> None:
    """Stamp the staged blob, then the work-tree file, with the same rewrite.

    Both change together so prek sees the index and work tree still agree.
    """
    rel, mode, blob = doc
    text = decode(git_bytes("cat-file", "blob", blob, cwd=top))
    stamped = stamp_text(text, entries)
    if stamped == text:
        return
    new_blob = (
        git_bytes(
            "hash-object",
            "-w",
            "--stdin",
            cwd=top,
            data=stamped.encode(errors="surrogateescape"),
        )
        .decode()
        .strip()
    )
    git("update-index", "--cacheinfo", f"{mode},{new_blob},{rel}", cwd=top)
    path = top / rel
    if path.is_file():
        current = decode(path.read_bytes())
        restamped = stamp_text(current, entries)
        if restamped != current:
            path.write_bytes(restamped.encode(errors="surrogateescape"))
    print(f"agent_identity: stamped {rel}", file=sys.stderr)


def refresh_codex(committer: Committer, repo: Repo, env: Mapping[str, str]) -> None:
    """Codex: turn rollout edits no hook recorded into receipts before using them."""
    if committer.key == CODEX:
        codex_scan(env["CODEX_SESSION_ID"], repo, env)


def cmd_stamp_docs(env: Mapping[str, str]) -> int:
    """pre-commit: stamp ``generated`` into the frontmatter of staged documents.

    Receipts are read, not consumed (post-commit consumes them).
    """
    repo = repo_info()
    if not repo:
        return 0
    committer = committer_identity(env)
    if committer:
        refresh_codex(committer, repo, env)
    receipts = all_edits(repo)
    now = time.time()
    # No cwd=None mutant matters below: the process already runs inside the repository.
    for doc in staged_docs(repo.top):  # pragma: no mutate
        mine = [r for r in receipts if r["path"] == doc[0]]
        entries = stamp_entries(mine, committer, now, repo.top)  # pragma: no mutate
        stamp_document(repo.top, doc, entries)
    return 0


# ------------------------------------------------------------------------- check

LINE = re.compile(r"^(Generated-by|Assisted-by):\s*(.*)$")
PAIR = re.compile(r"[a-z]+=[^\s;,]+")


def check_pair(pair: str) -> str | None:
    """Why one ``key=value`` attribute is invalid, or None."""
    if not PAIR.fullmatch(pair):
        return f"bad attribute {pair!r}"
    key, _, value = pair.partition("=")
    problem = None
    if key not in ATTR_ORDER:
        problem = f"unknown attribute {key}"
    elif key == "effort" and value not in EFFORTS:
        problem = f"bad effort {value}"
    elif key in {"session", "subagent"} and not HASH_RE.fullmatch(value):
        problem = f"bad {key} hash"
    elif key == "harness" and value.partition(":")[0] not in SLUGS.values():
        problem = f"unknown harness {value}"
    return problem


def check_value(value: str) -> str | None:
    """Why a trailer value is invalid under the grammar, or None."""
    tokens = value.split()
    blobs = [t for t in tokens[1:] if "=" in t]
    if not tokens or tokens[0] != "LLM":
        problem = "must start with literal LLM"
    elif len(blobs) != 1:
        problem = "need exactly one attribute blob"
    else:
        pairs = blobs[0].split(";")
        keys = [pair.partition("=")[0] for pair in pairs]
        problem = next(filter(None, map(check_pair, pairs)), None)
        if problem is None and "harness" not in keys:
            problem = "harness required"
        elif problem is None and (keys != sorted(keys) or len(set(keys)) != len(keys)):
            problem = "attributes out of order or duplicated"
    return problem


def check_message(text: str) -> list[str]:
    """Every problem in a commit message's LLM trailers."""
    errs: list[str] = []
    keys_seen: list[str] = []
    for line in text.splitlines():
        match = LINE.match(line)
        if match:
            problem = check_value(match.group(2))
            if problem:
                errs.append(f"{line}: {problem}")
            if match.group(1) == KEY_GEN and KEY_ASSIST in keys_seen:
                errs.append(f"{line}: Generated-by must come before Assisted-by")
            keys_seen.append(match.group(1))
    return errs


def cmd_check(msgfile: str) -> int:
    """commit-msg and CI: validate the LLM trailers, the same for every committer."""
    text = Path(msgfile).read_text()
    errs = check_message(text)
    for err in errs:
        print(f"agent_identity: {err}", file=sys.stderr)
    return 1 if errs else 0


USAGE = (
    "usage: record <harness> | trailer <msgfile> [source] | consume | check <msgfile>"
    " | stamp-docs"
)


def main(argv: list[str], env: Mapping[str, str]) -> int:
    """Dispatch a command line (``argv`` without the program name)."""
    match argv:
        case ["record", harness, *_]:
            return cmd_record(harness, env)
        case ["trailer", msgfile, *rest]:
            return cmd_trailer(msgfile, rest[0] if rest else env.get(SOURCE_ENV), env)
        case ["consume", *_]:
            return cmd_consume()
        case ["stamp-docs", *_]:
            return cmd_stamp_docs(env)
        case ["check", msgfile, *_]:
            return cmd_check(msgfile)
        case _:
            print(USAGE, file=sys.stderr)
            return 2


def run(argv: list[str], env: Mapping[str, str]) -> int:
    """``main``, reporting any crash as one line on stderr and exit status 1.

    The line names the exception type and where it was raised but not its
    message, which could quote a raw ID from hook input.
    """
    try:
        return main(argv, env)
    except Exception as exc:  # noqa: BLE001 -- every failure becomes one clear line
        where = traceback.extract_tb(exc.__traceback__)[-1]
        print(
            f"agent_identity {argv[0]}: failed: {type(exc).__name__} in "
            f"{where.name} (line {where.lineno})",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], os.environ))
