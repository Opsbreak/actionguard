"""Human-readable terminal output, grouped by file, with source excerpts and carets."""

from __future__ import annotations

from itertools import groupby

from actionguard.engine import ScanResult
from actionguard.models import Finding, Severity

_RESET = "\x1b[0m"
_SEVERITY_STYLE = {
    Severity.CRITICAL: "\x1b[1;37;41m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[1;33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_CARET = "\x1b[1;31m"
_MAX_SNIPPET = 140


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, style: str) -> str:
        return f"{style}{text}{_RESET}" if self.enabled and text else text


def _excerpt(finding: Finding, paint: _Painter) -> list[str]:
    line = finding.snippet.rstrip()
    if not line.strip():
        return []
    indent = len(line) - len(line.lstrip())
    shown = line.lstrip()
    start = max(0, finding.location.column - 1 - indent)
    if finding.location.end_column:
        width = max(1, finding.location.end_column - finding.location.column)
    else:
        width = max(1, len(shown) - start)
    if len(shown) > _MAX_SNIPPET:
        if start + width > _MAX_SNIPPET:
            cut = max(0, start - 20)
            shown = "..." + shown[cut : cut + _MAX_SNIPPET]
            start = start - cut + 3
        else:
            shown = shown[:_MAX_SNIPPET] + "..."
    width = min(width, max(1, len(shown) - start))
    num = str(finding.location.line)
    pad = " " * len(num)
    gutter = paint(f"{pad} |", _DIM)
    return [
        f"    {gutter}",
        f"    {paint(num + ' |', _DIM)} {shown}",
        f"    {gutter} {' ' * start}{paint('^' * width, _CARET)}",
    ]


def render_text(result: ScanResult, color: bool = False, show_source: bool = True) -> str:
    paint = _Painter(color)
    out: list[str] = []
    findings = result.findings
    for path, group in groupby(findings, key=lambda f: f.location.path):
        out.append(paint(path, _BOLD + "\x1b[4m"))
        for f in group:
            sev = paint(f" {f.severity.label.upper()} ", _SEVERITY_STYLE[f.severity])
            loc = paint(f"{f.location.line}:{f.location.column}", _DIM)
            out.append(f"  {loc} {sev} {paint(f.rule_id, _BOLD)} {f.message}")
            if show_source:
                out.extend(_excerpt(f, paint))
            context = []
            if f.job:
                context.append(f"job: {f.job}")
            if f.step:
                context.append(f"step: {f.step}")
            if context:
                out.append(f"    {paint('= ' + ', '.join(context), _DIM)}")
            for rel in f.related:
                if rel.location.line != f.location.line:
                    out.append(f"    {paint(f'= line {rel.location.line}: {rel.message}', _DIM)}")
        out.append("")
    for fr in result.files:
        if fr.error and not fr.findings:
            out.append(paint(f"warning: {fr.path}: {fr.error}", "\x1b[33m"))
    out.append(_summary(result, paint))
    return "\n".join(out) + "\n"


def _summary(result: ScanResult, paint: _Painter) -> str:
    total = len(result.findings)
    files = len(result.scanned)
    affected = len({f.location.path for f in result.findings})
    if total == 0:
        msg = paint(f"No findings in {files} file{'s' if files != 1 else ''}.", "\x1b[1;32m")
    else:
        parts = [f"{n} {s.label}" for s, n in result.counts().items() if n]
        msg = (
            paint(f"Found {total} finding{'s' if total != 1 else ''}", _BOLD)
            + f" in {affected} of {files} file{'s' if files != 1 else ''} ({', '.join(parts)})."
        )
    if result.suppressed:
        msg += f" {result.suppressed} suppressed."
    return msg
