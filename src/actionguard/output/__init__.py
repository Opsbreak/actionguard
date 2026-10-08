"""Report renderers."""

from __future__ import annotations

from actionguard.engine import ScanResult
from actionguard.output.json_out import render_json
from actionguard.output.markdown import render_markdown
from actionguard.output.sarif import build_sarif, render_sarif
from actionguard.output.text import render_text

FORMATS = ("text", "json", "sarif", "markdown")

__all__ = [
    "FORMATS",
    "build_sarif",
    "render",
    "render_json",
    "render_markdown",
    "render_sarif",
    "render_text",
]


def render(result: ScanResult, fmt: str, color: bool = False) -> str:
    if fmt == "text":
        return render_text(result, color=color)
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "markdown":
        return render_markdown(result)
    raise ValueError(f"unknown format {fmt!r}")
