"""``actionguard pin``: rewrite ``uses: owner/repo@tag`` to ``@<sha> # tag``.

Network access is isolated behind the :class:`Resolver` protocol so it can be replaced in
tests (or by callers that have their own mirror/cache). Two implementations ship:

* :class:`GitLsRemoteResolver` -- ``git ls-remote --tags --heads https://github.com/o/r``.
  No token needed. Also finds the most specific tag for a moving major tag
  (``v4`` -> ``v4.2.2``) so the trailing comment is precise.
* :class:`GitHubApiResolver` -- ``GET /repos/{o}/{r}/commits/{ref}`` with
  ``Accept: application/vnd.github.sha``; uses ``GITHUB_TOKEN`` if set.
"""

from __future__ import annotations

import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from actionguard.workflow import SHA_RE, build_workflow, parse_uses
from actionguard.yamlloader import YAMLParseError, load_yaml

__all__ = [
    "ChainResolver",
    "GitHubApiResolver",
    "GitLsRemoteResolver",
    "PinEdit",
    "Resolution",
    "ResolveError",
    "Resolver",
    "apply_pins",
    "make_resolver",
    "most_specific_tag",
    "plan_pins",
    "rewrite_line",
]


@dataclass(frozen=True)
class Resolution:
    sha: str
    version: str  # text for the trailing comment


class ResolveError(Exception):
    """Transient/transport failure (as opposed to "ref does not exist", which is ``None``)."""


class Resolver(Protocol):
    def resolve(self, owner: str, repo: str, ref: str) -> Resolution | None: ...


def _version_key(tag: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", tag)
    return tuple(int(n) for n in nums)


def most_specific_tag(sha: str, ref: str, tags: dict[str, str]) -> str:
    """Among tags pointing at ``sha`` that refine ``ref`` (v4 -> v4.2.2), pick the most precise."""
    candidates = [t for t, s in tags.items() if s == sha and (t == ref or t.startswith(ref + "."))]
    if not candidates:
        return ref
    return max(candidates, key=lambda t: (len(_version_key(t)), _version_key(t)))


Runner = Callable[[Sequence[str]], str]


def _default_runner(cmd: Sequence[str]) -> str:
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResolveError(f"failed to run {cmd[0]}: {exc}") from None
    if proc.returncode != 0:
        raise ResolveError(proc.stderr.strip() or f"{cmd[0]} exited with {proc.returncode}")
    return proc.stdout


class GitLsRemoteResolver:
    def __init__(self, runner: Runner | None = None, base_url: str = "https://github.com") -> None:
        self.runner = runner or _default_runner
        self.base_url = base_url.rstrip("/")
        self._cache: dict[str, tuple[dict[str, str], dict[str, str]]] = {}

    def _refs(self, owner: str, repo: str) -> tuple[dict[str, str], dict[str, str]]:
        key = f"{owner}/{repo}".lower()
        if key not in self._cache:
            out = self.runner(
                ["git", "ls-remote", "--tags", "--heads", f"{self.base_url}/{owner}/{repo}"]
            )
            tags: dict[str, str] = {}
            peeled: dict[str, str] = {}
            heads: dict[str, str] = {}
            for line in out.splitlines():
                parts = line.strip().split("\t")
                if len(parts) != 2:
                    continue
                sha, name = parts
                if name.startswith("refs/tags/"):
                    tag = name[len("refs/tags/") :]
                    if tag.endswith("^{}"):
                        peeled[tag[:-3]] = sha
                    else:
                        tags[tag] = sha
                elif name.startswith("refs/heads/"):
                    heads[name[len("refs/heads/") :]] = sha
            tags.update(peeled)  # annotated tags: use the commit, not the tag object
            self._cache[key] = (tags, heads)
        return self._cache[key]

    def resolve(self, owner: str, repo: str, ref: str) -> Resolution | None:
        tags, heads = self._refs(owner, repo)
        if ref in tags:
            sha = tags[ref]
            return Resolution(sha, most_specific_tag(sha, ref, tags))
        if ref in heads:
            return Resolution(heads[ref], ref)
        return None


Opener = Callable[[str, dict[str, str]], tuple[int, str]]


def _default_opener(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ResolveError(f"GitHub API request failed: {exc}") from None


class GitHubApiResolver:
    def __init__(
        self,
        opener: Opener | None = None,
        token: str | None = None,
        api_url: str = "https://api.github.com",
    ) -> None:
        self.opener = opener or _default_opener
        self.token = (
            token
            if token is not None
            else os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        )
        self.api_url = api_url.rstrip("/")

    def resolve(self, owner: str, repo: str, ref: str) -> Resolution | None:
        quoted = urllib.parse.quote(ref, safe="")
        url = f"{self.api_url}/repos/{owner}/{repo}/commits/{quoted}"
        headers = {
            "Accept": "application/vnd.github.sha",
            "User-Agent": "actionguard",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        status, body = self.opener(url, headers)
        if status in (404, 422):
            return None
        if status != 200:
            raise ResolveError(f"GitHub API returned HTTP {status} for {owner}/{repo}@{ref}")
        sha = body.strip()
        if not SHA_RE.match(sha):
            raise ResolveError(f"unexpected GitHub API response for {owner}/{repo}@{ref}")
        return Resolution(sha, ref)


class ChainResolver:
    """Try resolvers in order, falling through on transport errors."""

    def __init__(self, *resolvers: Resolver) -> None:
        self.resolvers = resolvers

    def resolve(self, owner: str, repo: str, ref: str) -> Resolution | None:
        errors = []
        for r in self.resolvers:
            try:
                return r.resolve(owner, repo, ref)
            except ResolveError as exc:
                errors.append(str(exc))
        raise ResolveError("; ".join(errors) or "no resolver available")


def make_resolver(kind: str = "auto") -> Resolver:
    if kind == "git":
        return GitLsRemoteResolver()
    if kind == "api":
        return GitHubApiResolver()
    # auto: git first (no rate limits, finds precise tags), API as a fallback
    return ChainResolver(GitLsRemoteResolver(), GitHubApiResolver())


@dataclass
class PinEdit:
    path: Path
    display: str
    line: int
    old: str
    new: str = ""
    version: str = ""
    error: str | None = None


_COMMENT_VERSION_RE = re.compile(r"^(?:v?\d[\w.\-+]*|[\w.\-/]+)$")


def rewrite_line(line: str, old_value: str, sha: str, version: str) -> str | None:
    """Rewrite one ``uses:`` line, preserving indentation, quoting and unrelated comments."""
    m = re.search(r"(uses\s*:\s*)([\"']?)" + re.escape(old_value) + r"\2([ \t]*#.*)?[ \t]*$", line)
    if not m:
        return None
    name = old_value.rsplit("@", 1)[0]
    quote = m.group(2)
    comment = (m.group(3) or "").strip()
    existing = comment[1:].strip() if comment.startswith("#") else ""
    new_comment = f"# {version}"
    if existing and not _COMMENT_VERSION_RE.match(existing):
        new_comment += f" # {existing.lstrip('#').strip()}"
    return f"{line[: m.start()]}{m.group(1)}{quote}{name}@{sha}{quote} {new_comment}"


def plan_pins(files: Sequence[tuple[Path, str]], resolver: Resolver) -> list[PinEdit]:
    edits: list[PinEdit] = []
    cache: dict[tuple[str, str, str], Resolution | ResolveError | None] = {}
    for path, display in files:
        try:
            data, source = load_yaml(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, YAMLParseError):
            continue
        wf = build_workflow(display, source, data)
        if wf is None:
            continue
        values: list[tuple[int, str]] = []
        for job in wf.jobs:
            if job.uses:
                values.append((job.raw.value_line("uses"), job.uses))
            for step in job.steps:
                if step.uses:
                    values.append((step.raw.value_line("uses"), step.uses))
        for line, value in values:
            ref = parse_uses(value)
            if ref.kind != "repo" or not ref.ref or ref.is_sha_pinned:
                continue
            edit = PinEdit(
                path,
                display,
                line,
                str(value).strip(),
            )
            key = (ref.owner.lower(), ref.repo.lower(), ref.ref)
            if key not in cache:
                try:
                    cache[key] = resolver.resolve(ref.owner, ref.repo, ref.ref)
                except ResolveError as exc:
                    cache[key] = exc
            res = cache[key]
            if isinstance(res, ResolveError):
                edit.error = f"could not resolve {ref.owner}/{ref.repo}@{ref.ref}: {res}"
            elif res is None:
                edit.error = (
                    f"`{ref.ref}` not found in {ref.owner}/{ref.repo} "
                    "(no such tag or branch, or the repository is missing/private)"
                )
            else:
                edit.new = f"{value.strip().rsplit('@', 1)[0]}@{res.sha}"
                edit.version = res.version
            edits.append(edit)
    return edits


def apply_pins(edits: Sequence[PinEdit]) -> int:
    """Write successful edits back to disk. Returns the number of lines changed."""
    changed = 0
    by_file: dict[Path, list[PinEdit]] = {}
    for e in edits:
        if e.error is None and e.new:
            by_file.setdefault(e.path, []).append(e)
    for path, file_edits in by_file.items():
        raw = path.read_bytes().decode("utf-8-sig")
        newline = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.split(newline)
        for e in file_edits:
            idx = e.line - 1
            if not 0 <= idx < len(lines):
                e.error = "line out of range"
                continue
            sha = e.new.rsplit("@", 1)[1]
            new_line = rewrite_line(lines[idx], e.old, sha, e.version)
            if new_line is None:
                e.error = "could not locate the `uses:` value on its line (flow-style YAML?)"
                continue
            if new_line != lines[idx]:
                lines[idx] = new_line
                changed += 1
        path.write_bytes(newline.join(lines).encode("utf-8"))
    return changed
