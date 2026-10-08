"""Markdown summary (e.g. for ``$GITHUB_STEP_SUMMARY`` or PR comments)."""

from __future__ import annotations

from actionguard import __version__
from actionguard.engine import ScanResult
from actionguard.rules import get_rule


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    findings = result.findings
    files = len(result.scanned)
    lines = ["## actionguard report", ""]
    if not findings:
        lines.append(f"No findings in {files} file{'s' if files != 1 else ''}.")
    else:
        lines.append(
            f"**{len(findings)} finding{'s' if len(findings) != 1 else ''}** in {files} "
            f"scanned file{'s' if files != 1 else ''}."
        )
        lines += ["", "| Severity | Count |", "|---|---:|"]
        lines += [f"| {s.label} | {n} |" for s, n in result.counts().items() if n]
        lines += ["", "| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in findings:
            spec = get_rule(f.rule_id)
            title = spec.meta.title if spec else f.rule_id
            lines.append(
                f"| {f.severity.label} | [{f.rule_id}]({spec.meta.help_uri if spec else ''} "
                f'"{_cell(title)}") | `{f.location.path}:{f.location.line}` | {_cell(f.message)} |'
            )
    if result.suppressed:
        lines += [
            "",
            f"{result.suppressed} finding(s) suppressed by configuration or inline comments.",
        ]
    errors = [fr for fr in result.files if fr.error]
    if errors:
        lines += ["", "### Errors", ""]
        lines += [f"- `{fr.path}`: {_cell(fr.error or '')}" for fr in errors]
    lines += ["", f"<sub>actionguard {__version__}</sub>", ""]
    return "\n".join(lines)
