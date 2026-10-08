"""Core data types shared across the analyzer: severities, rules, findings."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered finding severity. Comparison operators follow the natural order."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def security_severity(self) -> str:
        """CVSS-like score used by GitHub code scanning to bucket alerts."""
        return {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.5",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }[self]


@dataclass(frozen=True)
class Rule:
    """Static metadata describing one detection rule."""

    id: str
    name: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def help_uri(self) -> str:
        return f"https://github.com/Opsbreak/actionguard/blob/main/docs/rules.md#{self.id.lower()}"


@dataclass(frozen=True)
class Location:
    path: str
    line: int = 1
    column: int = 1
    end_column: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Related:
    location: Location
    message: str


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    location: Location
    related: list[Related] = field(default_factory=list)
    job: str | None = None
    step: str | None = None
    snippet: str = ""
    fingerprint: str = ""

    def sort_key(self) -> tuple[Any, ...]:
        loc = self.location
        return (loc.path, loc.line, loc.column, self.rule_id, self.message)

    def compute_fingerprint(self, occurrence: int = 0) -> str:
        """A line-number independent fingerprint, stable across unrelated edits."""
        parts = [
            self.rule_id,
            self.location.path,
            self.job or "",
            self.step or "",
            " ".join(self.snippet.split()),
            str(occurrence),
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "message": self.message,
            "path": self.location.path,
            "line": self.location.line,
            "column": self.location.column,
            "job": self.job,
            "step": self.step,
            "snippet": self.snippet,
            "related": [
                {
                    "path": r.location.path,
                    "line": r.location.line,
                    "column": r.location.column,
                    "message": r.message,
                }
                for r in self.related
            ],
            "fingerprint": self.fingerprint,
        }
