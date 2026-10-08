"""``.actionguard.yml`` configuration and inline suppression comments."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from actionguard.models import Finding, Severity
from actionguard.yamlloader import SourceText

__all__ = [
    "CONFIG_FILENAMES",
    "Config",
    "ConfigError",
    "IgnoreEntry",
    "glob_match",
    "is_suppressed_inline",
]

CONFIG_FILENAMES = (".actionguard.yml", ".actionguard.yaml")
_RULE_ID_RE = re.compile(r"^AG\d{3}$", re.IGNORECASE)
_KNOWN_KEYS = {
    "ignore",
    "select",
    "trusted-actions",
    "untrusted-contexts",
    "min-severity",
    "fail-on",
}


class ConfigError(ValueError):
    pass


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def glob_match(path: str, pattern: str) -> bool:
    """Gitignore-flavoured glob: ``*`` stays within a segment, ``**`` crosses segments.

    Patterns without a ``/`` also match against the file's basename.
    """
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    pattern = pattern.replace("\\", "/")
    if pattern.startswith("./"):
        pattern = pattern[2:]
    rx = _glob_to_regex(pattern)
    if rx.match(path):
        return True
    if "/" not in pattern:
        return bool(rx.match(PurePosixPath(path).name))
    return False


@dataclass(frozen=True)
class IgnoreEntry:
    rules: frozenset[str] = frozenset()  # empty = all rules
    paths: tuple[str, ...] = ()  # empty = all paths
    reason: str = ""

    def matches(self, finding: Finding, rel_path: str) -> bool:
        if self.rules and finding.rule_id.upper() not in self.rules:
            return False
        return not (
            self.paths
            and not any(
                glob_match(rel_path, p) or glob_match(finding.location.path, p) for p in self.paths
            )
        )


def _str_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return list(value)
    raise ConfigError(f"`{key}` must be a string or a list of strings")


@dataclass
class Config:
    ignores: list[IgnoreEntry] = field(default_factory=list)
    trusted_actions: list[str] = field(default_factory=list)
    untrusted_contexts: list[str] = field(default_factory=list)
    select: list[str] = field(default_factory=list)
    min_severity: Severity | None = None
    fail_on: Severity | None = None
    base_dir: Path = field(default_factory=Path.cwd)
    source: Path | None = None

    # -- loading --------------------------------------------------------------------------

    @classmethod
    def from_dict(
        cls, data: Any, base_dir: Path | None = None, source: Path | None = None
    ) -> Config:
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError("configuration must be a mapping")
        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            raise ConfigError(
                f"unknown configuration key(s): {', '.join(sorted(map(str, unknown)))}"
            )
        cfg = cls(base_dir=base_dir or Path.cwd(), source=source)
        for item in data.get("ignore") or []:
            cfg.ignores.append(cls._parse_ignore(item))
        cfg.trusted_actions = [
            s.lower() for s in _str_list(data.get("trusted-actions"), "trusted-actions")
        ]
        cfg.untrusted_contexts = _str_list(data.get("untrusted-contexts"), "untrusted-contexts")
        cfg.select = [s.upper() for s in _str_list(data.get("select"), "select")]
        for key, attr in (("min-severity", "min_severity"), ("fail-on", "fail_on")):
            if data.get(key) is not None:
                try:
                    setattr(cfg, attr, Severity.parse(str(data[key])))
                except ValueError as exc:
                    raise ConfigError(f"`{key}`: {exc}") from None
        return cfg

    @staticmethod
    def _parse_ignore(item: Any) -> IgnoreEntry:
        if isinstance(item, str):
            if _RULE_ID_RE.match(item.strip()):
                return IgnoreEntry(rules=frozenset({item.strip().upper()}))
            return IgnoreEntry(paths=(item.strip(),))
        if isinstance(item, dict):
            extra = set(item) - {"rule", "rules", "path", "paths", "reason"}
            if extra:
                raise ConfigError(f"unknown key(s) in ignore entry: {', '.join(sorted(extra))}")
            rules = _str_list(item.get("rule"), "rule") + _str_list(item.get("rules"), "rules")
            for r in rules:
                if not _RULE_ID_RE.match(r):
                    raise ConfigError(f"invalid rule id in ignore entry: {r!r}")
            paths = _str_list(item.get("path"), "path") + _str_list(item.get("paths"), "paths")
            if not rules and not paths:
                raise ConfigError("ignore entry needs at least one of `rule(s)` or `path(s)`")
            return IgnoreEntry(
                frozenset(r.upper() for r in rules), tuple(paths), str(item.get("reason", ""))
            )
        raise ConfigError("ignore entries must be a rule id, a path glob, or a mapping")

    @classmethod
    def load(cls, path: Path) -> Config:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from None
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path}: invalid YAML: {exc}") from None
        try:
            return cls.from_dict(data, base_dir=path.resolve().parent, source=path)
        except ConfigError as exc:
            raise ConfigError(f"{path}: {exc}") from None

    @classmethod
    def discover(cls, start: Path) -> Config:
        for name in CONFIG_FILENAMES:
            candidate = start / name
            if candidate.is_file():
                return cls.load(candidate)
        return cls(base_dir=start.resolve())

    # -- queries --------------------------------------------------------------------------

    def is_trusted_action(self, name: str) -> bool:
        name = name.lower()
        repo = "/".join(name.split("/")[:2])  # owner/repo of owner/repo/sub/path
        for pattern in self.trusted_actions:
            if glob_match(name, pattern) or glob_match(repo, pattern):
                return True
            if name.startswith(pattern.rstrip("/") + "/"):
                return True
        return False

    def relative(self, path: str) -> str:
        p = Path(path)
        try:
            return p.resolve().relative_to(self.base_dir).as_posix()
        except (ValueError, OSError):
            return p.as_posix()

    def is_ignored(self, finding: Finding) -> bool:
        rel = self.relative(finding.location.path)
        return any(entry.matches(finding, rel) for entry in self.ignores)


_SUPPRESS_RE = re.compile(
    r"(?:#|//)\s*actionguard\s*:\s*(?:ignore|disable)(?:\[([^\]]*)\])?", re.IGNORECASE
)


def is_suppressed_inline(finding: Finding, source: SourceText) -> bool:
    """``# actionguard: ignore[AG003]`` on the finding's line or the line above it."""
    for lineno in (finding.location.line, finding.location.line - 1):
        m = _SUPPRESS_RE.search(source.line(lineno))
        if not m:
            continue
        if m.group(1) is None or not m.group(1).strip():
            return True
        ids = {x.strip().upper() for x in m.group(1).split(",")}
        if finding.rule_id.upper() in ids:
            return True
    return False
