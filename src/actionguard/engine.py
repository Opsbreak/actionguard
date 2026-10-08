"""File discovery and the scan pipeline: parse -> rules -> filters -> fingerprints."""

from __future__ import annotations

import os
import traceback
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from actionguard.analysis import AnalysisContext
from actionguard.config import Config, is_suppressed_inline
from actionguard.models import Finding, Location, Severity
from actionguard.rules import all_rules
from actionguard.workflow import build_workflow
from actionguard.yamlloader import SourceText, YAMLParseError, load_yaml

__all__ = [
    "FileResult",
    "ScanError",
    "ScanOptions",
    "ScanResult",
    "analyze_text",
    "discover",
    "display_path",
    "scan",
]

_YAML_SUFFIXES = (".yml", ".yaml")
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".nox",
    "dist",
    "build",
}


class ScanError(Exception):
    """A usage problem (missing path, nothing to scan)."""


@dataclass
class ScanOptions:
    select: Sequence[str] = ()
    ignore: Sequence[str] = ()
    min_severity: Severity = Severity.INFO

    def rule_enabled(self, rule_id: str) -> bool:
        if rule_id == "AG000":
            return rule_id not in self.ignore
        if self.select and rule_id not in self.select:
            return False
        return rule_id not in self.ignore


@dataclass
class FileResult:
    path: str
    kind: str | None  # "workflow" | "action" | None (skipped / parse error)
    findings: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    error: str | None = None


@dataclass
class ScanResult:
    files: list[FileResult] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out = [f for fr in self.files for f in fr.findings]
        return sorted(out, key=Finding.sort_key)

    @property
    def scanned(self) -> list[FileResult]:
        return [f for f in self.files if f.kind is not None or f.error]

    @property
    def suppressed(self) -> int:
        return sum(f.suppressed for f in self.files)

    def counts(self) -> dict[Severity, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in sorted(Severity, reverse=True)}

    def max_severity(self) -> Severity | None:
        sevs = [f.severity for f in self.findings]
        return max(sevs) if sevs else None


def display_path(path: Path, cwd: Path | None = None) -> str:
    """Path relative to ``cwd`` when the file is inside it, otherwise absolute."""
    cwd = cwd or Path.cwd()
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _yaml_files(directory: Path, recursive: bool) -> list[Path]:
    out: list[Path] = []
    if recursive:
        for root, dirs, files in os.walk(directory):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            out.extend(Path(root) / f for f in sorted(files) if f.lower().endswith(_YAML_SUFFIXES))
    else:
        out.extend(
            sorted(
                p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in _YAML_SUFFIXES
            )
        )
    return out


def discover(paths: Sequence[str | Path], cwd: Path | None = None) -> list[tuple[Path, bool]]:
    """Expand CLI paths into ``(file, explicit)`` pairs.

    * no paths: ``.github/workflows`` in the current directory
    * a repository root (contains ``.github/``): its workflows, ``action.yml`` at the root and
      composite actions under ``.github/actions/``
    * any other directory: every YAML file below it (non-workflow files are skipped)
    * a file: analysed as given
    """
    cwd = cwd or Path.cwd()
    if not paths:
        default = cwd / ".github" / "workflows"
        if not default.is_dir():
            raise ScanError(f"no .github/workflows directory in {cwd}; pass paths to scan")
        paths = [default]
    seen: set[Path] = set()
    out: list[tuple[Path, bool]] = []

    def add(p: Path, explicit: bool) -> None:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            out.append((p, explicit))

    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = cwd / p
        if p.is_file():
            add(p, True)
        elif p.is_dir():
            if (p / ".github").is_dir():
                wf_dir = p / ".github" / "workflows"
                if wf_dir.is_dir():
                    for f in _yaml_files(wf_dir, recursive=False):
                        add(f, False)
                for name in ("action.yml", "action.yaml"):
                    if (p / name).is_file():
                        add(p / name, False)
                actions_dir = p / ".github" / "actions"
                if actions_dir.is_dir():
                    for f in _yaml_files(actions_dir, recursive=True):
                        if f.name.lower() in ("action.yml", "action.yaml"):
                            add(f, False)
            else:
                for f in _yaml_files(p, recursive=True):
                    add(f, False)
        else:
            raise ScanError(f"path not found: {raw}")
    return out


def _parse_error(path: str, source: SourceText, message: str, line: int, column: int) -> Finding:
    return Finding(
        rule_id="AG000",
        severity=Severity.HIGH,
        message=f"Could not parse file: {message}",
        location=Location(path, line, column),
        snippet=source.line(line),
    )


def analyze_text(
    text: str,
    path: str = "workflow.yml",
    config: Config | None = None,
    options: ScanOptions | None = None,
    explicit: bool = True,
) -> FileResult:
    """Analyse one document. Pure function of its inputs (used by the CLI and the tests)."""
    config = config or Config()
    options = options or ScanOptions()
    result = FileResult(path=path, kind=None)
    try:
        data, source = load_yaml(text)
    except YAMLParseError as exc:
        source = SourceText(text)
        result.error = str(exc)
        raw = [_parse_error(path, source, exc.message, exc.line, exc.column)]
        return _finalize(result, raw, source, config, options)
    wf = build_workflow(path, source, data)
    if wf is None:
        if explicit and data is not None:
            result.error = "not a GitHub Actions workflow or action (no `jobs:` or `runs:`)"
        return result
    result.kind = wf.kind
    ctx = AnalysisContext(wf, config)
    raw_findings: list[Finding] = []
    for spec in all_rules():
        if spec.check is None or not options.rule_enabled(spec.id):
            continue
        try:
            raw_findings.extend(spec.check(ctx))
        except Exception as exc:  # pragma: no cover - defensive: one rule must not kill a scan
            result.error = f"internal error in {spec.id}: {exc!r}"
            if os.environ.get("ACTIONGUARD_DEBUG"):
                traceback.print_exc()
    return _finalize(result, raw_findings, source, config, options)


def _finalize(
    result: FileResult,
    findings: Iterable[Finding],
    source: SourceText,
    config: Config,
    options: ScanOptions,
) -> FileResult:
    unique: dict[tuple[object, ...], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.location.line, f.location.column, f.message)
        unique.setdefault(key, f)
    kept: list[Finding] = []
    for f in sorted(unique.values(), key=Finding.sort_key):
        if not options.rule_enabled(f.rule_id) or f.severity < options.min_severity:
            continue
        if is_suppressed_inline(f, source) or config.is_ignored(f):
            result.suppressed += 1
            continue
        kept.append(f)
    occurrences: Counter[str] = Counter()
    for f in kept:
        base = f.compute_fingerprint(0)
        f.fingerprint = f.compute_fingerprint(occurrences[base])
        occurrences[base] += 1
    result.findings = kept
    return result


def scan(
    paths: Sequence[str | Path],
    config: Config | None = None,
    options: ScanOptions | None = None,
    cwd: Path | None = None,
) -> ScanResult:
    cwd = cwd or Path.cwd()
    config = config or Config(base_dir=cwd)
    result = ScanResult()
    for file, explicit in discover(paths, cwd):
        shown = display_path(file, cwd)
        try:
            text = file.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            fr = FileResult(path=shown, kind=None, error=f"cannot read file: {exc}")
            src = SourceText("")
            result.files.append(
                _finalize(
                    fr,
                    [_parse_error(shown, src, f"cannot read file: {exc}", 1, 1)],
                    src,
                    config,
                    options or ScanOptions(),
                )
            )
            continue
        result.files.append(analyze_text(text, shown, config, options, explicit))
    return result
