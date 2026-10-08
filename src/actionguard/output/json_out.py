"""Machine-readable JSON output."""

from __future__ import annotations

import json
from typing import Any

from actionguard import __version__
from actionguard.engine import ScanResult


def build_json(result: ScanResult) -> dict[str, Any]:
    findings = result.findings
    return {
        "tool": {"name": "actionguard", "version": __version__},
        "summary": {
            "files_scanned": len(result.scanned),
            "findings": len(findings),
            "suppressed": result.suppressed,
            "by_severity": {s.label: n for s, n in result.counts().items()},
        },
        "findings": [f.to_dict() for f in findings],
        "errors": [{"path": f.path, "error": f.error} for f in result.files if f.error],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(build_json(result), indent=2) + "\n"
