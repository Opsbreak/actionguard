"""Lightweight, conservative analysis of ``run:`` scripts.

This is deliberately not a shell parser. It recognises the idioms that matter for data
flow through the workflow command files ($GITHUB_ENV, $GITHUB_OUTPUT, $GITHUB_PATH)
across bash, PowerShell, cmd and JavaScript (actions/github-script), plus commands that
fetch pull-request code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "FileWrite",
    "fetches_pr_code",
    "git_ref_command",
    "iter_file_writes",
    "iter_set_output",
    "shell_var_refs",
    "strip_expressions",
]

_SHELL_VAR_RES = (
    re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?=[}:#%/^,@\[])"),  # ${NAME} ${NAME:-x}
    re.compile(r"\$(?!env:)([A-Za-z_][A-Za-z0-9_]*)"),  # $NAME
    re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE),  # PowerShell
    re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}", re.IGNORECASE),  # PowerShell braces
    re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%"),  # cmd
    re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"),  # JavaScript
    re.compile(r"process\.env\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]"),
)

_WRITE_VERB_RE = re.compile(
    r"\btee\b|Add-Content|Out-File|Set-Content|appendFileSync|writeFileSync|appendFile\b",
    re.IGNORECASE,
)
_REDIRECT_TAIL_RE = re.compile(r"\s*(?:>>?|\|\s*tee(?:\s+-a|\s+--append)?)\s*[\"']?\s*$")
_HEREDOC_RE = re.compile(r"\b(?:cat|tee)\b[^<\n]*<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
_NAME_RE = re.compile(r"(?:^|[\s\"'(,`])([A-Za-z_][A-Za-z0-9_\-]*)(<<|=)")
_CMD_PREFIX_RE = re.compile(
    r"^\s*(?:echo|printf|Write-Output|Write-Host|cat)\b\s*(?:-[A-Za-z]+\s+)*", re.IGNORECASE
)


def strip_expressions(text: str) -> str:
    """Blank out ``${{ ... }}`` blocks so shell regexes don't trip on them."""
    return re.sub(r"\$\{\{.*?\}\}", lambda m: " " * len(m.group(0)), text)


def shell_var_refs(text: str) -> list[str]:
    """Names of environment variables expanded by ``text`` (any supported shell)."""
    cleaned = strip_expressions(text)
    names: list[str] = []
    for rx in _SHELL_VAR_RES:
        for m in rx.finditer(cleaned):
            if m.group(1) not in names:
                names.append(m.group(1))
    return names


@dataclass(frozen=True)
class FileWrite:
    """One logical write to a workflow command file."""

    line_index: int  # 0-based line within the script
    name: str | None  # variable / output name (None for GITHUB_PATH or unknown)
    data: str  # the text being written (best effort)


def _target_re(target: str) -> re.Pattern[str]:
    t = re.escape(target)
    return re.compile(
        rf"(?:\$\{{{t}\}}|\${t}\b|\$env:{t}\b|\$\{{env:{t}\}}|%{t}%|process\.env\.{t}\b"
        rf"|process\.env\[\s*['\"]{t}['\"]\s*\])",
        re.IGNORECASE,
    )


def _is_write(line: str, m: re.Match[str]) -> bool:
    before = line[: m.start()].rstrip().rstrip("\"'").rstrip()
    return before.endswith(">") or bool(_WRITE_VERB_RE.search(line))


def iter_file_writes(script: str, target: str) -> list[FileWrite]:
    """Find writes to ``$<target>`` (e.g. ``GITHUB_ENV``) in a script.

    Handles single-line redirects, ``{ ...; } >> $T`` groups, ``cat <<EOF >> $T`` heredocs,
    the ``NAME<<DELIM`` multi-line value syntax, PowerShell and Node.js idioms.
    """
    target_re = _target_re(target)
    lines = script.split("\n")
    writes: list[FileWrite] = []
    pending: list[tuple[str, str]] = []  # (name, delimiter) of an open NAME<<DELIM value
    group_start: int | None = None

    def record(idx: int, data: str) -> None:
        body = _CMD_PREFIX_RE.sub("", data).strip()
        if pending:
            name, delim = pending[-1]
            if body.strip("\"'").strip() == delim:
                pending.pop()
                return
            writes.append(FileWrite(idx, name, data))
            return
        m = _NAME_RE.search(" " + body)
        if m and target != "GITHUB_PATH":
            name, op = m.group(1), m.group(2)
            if op == "<<":
                rest = body[body.find("<<") + 2 :].strip().strip("\"'")
                delim = re.split(r"[\s\"']", rest, maxsplit=1)[0] if rest else "EOF"
                pending.append((name, delim))
            writes.append(FileWrite(idx, name, data))
        else:
            writes.append(FileWrite(idx, None, data))

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped in ("{", "(") or re.match(r"^\{\s*$", stripped):
            group_start = i
        m = target_re.search(line)
        if m and _is_write(line, m):
            hd = _HEREDOC_RE.search(line)
            if hd:
                delim = hd.group(1)
                j = i + 1
                while j < len(lines) and lines[j].strip() != delim:
                    record(j, lines[j])
                    j += 1
                i = j + 1
                continue
            if (stripped.startswith(("}", ")"))) and group_start is not None:
                for j in range(group_start + 1, i):
                    record(j, lines[j])
                group_start = None
            else:
                before = _REDIRECT_TAIL_RE.sub("", line[: m.start()])
                after = re.sub(r"^[\"'}]", "", line[m.end() :])
                record(i, before + after)
        i += 1
    return writes


_SET_OUTPUT_RE = re.compile(r"::set-output\s+name=([A-Za-z_][A-Za-z0-9_\-]*)::(.*)")
_SET_ENV_RE = re.compile(r"::set-env\s+name=([A-Za-z_][A-Za-z0-9_\-]*)::(.*)")


def iter_set_output(script: str, legacy_env: bool = False) -> list[FileWrite]:
    """Deprecated ``::set-output`` / ``::set-env`` workflow commands."""
    rx = _SET_ENV_RE if legacy_env else _SET_OUTPUT_RE
    out = []
    for idx, line in enumerate(script.split("\n")):
        m = rx.search(line)
        if m:
            out.append(FileWrite(idx, m.group(1), m.group(2)))
    return out


_PR_FETCH_RES = (
    re.compile(r"\b(?:gh|hub)\s+pr\s+checkout\b"),
    re.compile(r"\bgit\b[^\n|;&]*\b(?:fetch|pull)\b[^\n|;&]*\b(?:refs/)?pull/"),
    re.compile(r"\bgit\b[^\n|;&]*\b(?:checkout|switch|reset|merge)\b[^\n|;&]*\bFETCH_HEAD\b"),
    re.compile(r"\bgit\b[^\n|;&]*\bclone\b[^\n|;&]*head\.repo"),
)
_GIT_REF_CMD_RE = re.compile(
    r"\bgit\b(?:\s+-[cC]\s+\S+)*\s+(?:fetch|checkout|switch|pull|reset|merge|worktree\s+add|clone)\b"
)


def fetches_pr_code(line: str) -> bool:
    """True for commands that check out pull-request code regardless of arguments."""
    return any(rx.search(line) for rx in _PR_FETCH_RES)


def git_ref_command(line: str) -> bool:
    """True for git commands whose arguments select which code ends up in the workspace."""
    return bool(_GIT_REF_CMD_RE.search(line))
