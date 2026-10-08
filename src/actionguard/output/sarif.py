"""SARIF 2.1.0 output suitable for GitHub code scanning (``github/codeql-action/upload-sarif``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from actionguard import __version__
from actionguard.engine import ScanResult
from actionguard.models import Finding, Location
from actionguard.rules import all_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_INFO_URI = "https://github.com/Opsbreak/actionguard"


def _pascal(name: str) -> str:
    return "".join(part.capitalize() for part in name.replace("_", "-").split("-"))


def _rule_descriptor(spec_meta: Any) -> dict[str, Any]:
    meta = spec_meta
    refs = "\n".join(f"- {r}" for r in meta.references)
    markdown = (
        f"## {meta.id}: {meta.title}\n\n{meta.description}\n\n### Remediation\n\n{meta.remediation}"
        + (f"\n\n### References\n\n{refs}" if refs else "")
    )
    return {
        "id": meta.id,
        "name": _pascal(meta.name),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "help": {
            "text": f"{meta.description}\n\nRemediation: {meta.remediation}",
            "markdown": markdown,
        },
        "helpUri": meta.references[0] if meta.references else _INFO_URI,
        "defaultConfiguration": {"level": meta.severity.sarif_level},
        "properties": {
            "tags": list(meta.tags),
            "precision": "high" if meta.id in ("AG003", "AG004", "AG000") else "medium",
            "problem.severity": {"error": "error", "warning": "warning"}.get(
                meta.severity.sarif_level, "recommendation"
            ),
            "security-severity": meta.severity.security_severity,
        },
    }


def _physical(loc: Location, snippet: str | None = None) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": loc.line, "startColumn": max(1, loc.column)}
    if loc.end_column and loc.end_column > loc.column:
        region["endColumn"] = loc.end_column
    if snippet:
        region["snippet"] = {"text": snippet}
    return {
        "artifactLocation": {"uri": loc.path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
        "region": region,
    }


def _result(f: Finding, index: dict[str, int]) -> dict[str, Any]:
    res: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": index[f.rule_id],
        "level": f.severity.sarif_level,
        "message": {"text": f.message},
        "locations": [{"physicalLocation": _physical(f.location, f.snippet.strip() or None)}],
        "partialFingerprints": {
            "actionguardFingerprint/v1": f.fingerprint or f.compute_fingerprint()
        },
        "properties": {
            "severity": f.severity.label,
            "security-severity": f.severity.security_severity,
        },
    }
    if f.job or f.step:
        res["properties"]["job"] = f.job
        res["properties"]["step"] = f.step
    related = [r for r in f.related if r.location.line != f.location.line]
    if related:
        res["relatedLocations"] = [
            {"id": i + 1, "physicalLocation": _physical(r.location), "message": {"text": r.message}}
            for i, r in enumerate(related)
        ]
    return res


def build_sarif(result: ScanResult, root: Path | None = None) -> dict[str, Any]:
    specs = all_rules()
    index = {s.id: i for i, s in enumerate(specs)}
    root_uri = (root or Path.cwd()).resolve().as_uri().rstrip("/") + "/"
    notifications = [
        {
            "level": "error",
            "message": {"text": fr.error},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": fr.path, "uriBaseId": "%SRCROOT%"}
                    }
                }
            ],
        }
        for fr in result.files
        if fr.error
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "actionguard",
                "organization": "Opsbreak Inc.",
                "informationUri": _INFO_URI,
                "version": __version__,
                "semanticVersion": __version__,
                "rules": [_rule_descriptor(s.meta) for s in specs],
            }
        },
        "originalUriBaseIds": {"%SRCROOT%": {"uri": root_uri}},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "columnKind": "unicodeCodePoints",
        "results": [_result(f, index) for f in result.findings],
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2) + "\n"
