"""Renderers: SARIF shape, JSON, Markdown and text."""

from __future__ import annotations

import json
import re

from actionguard.engine import ScanResult, analyze_text
from actionguard.output import render
from actionguard.output.sarif import build_sarif
from actionguard.rules import all_rules

VULN = """\
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
"""


def _result() -> ScanResult:
    return ScanResult(files=[analyze_text(VULN, ".github/workflows/w.yml")])


def test_sarif_document_shape():
    doc = build_sarif(_result())
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "actionguard"
    assert re.match(r"^\d+\.\d+\.\d+$", driver["version"])
    rule_ids = [r["id"] for r in driver["rules"]]
    assert rule_ids == [s.id for s in all_rules()]
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["help"]["text"]
        assert rule["help"]["markdown"]
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")
        assert float(rule["properties"]["security-severity"]) > 0
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file://")
    results = run["results"]
    assert {r["ruleId"] for r in results} >= {"AG001", "AG003", "AG004"}
    for res in results:
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == ".github/workflows/w.yml"
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] >= 1
        assert loc["region"]["startColumn"] >= 1
        fp = res["partialFingerprints"]["actionguardFingerprint/v1"]
        assert re.fullmatch(r"[0-9a-f]{32}", fp)
    injection = next(r for r in results if r["ruleId"] == "AG001")
    region = injection["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 7
    assert region["endColumn"] > region["startColumn"]
    # serialisable and round-trips
    assert json.loads(render(_result(), "sarif"))["runs"][0]["results"]


def test_sarif_related_locations_for_pwn_request():
    text = """\
on: pull_request_target
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make
"""
    res = ScanResult(files=[analyze_text(text, "w.yml")])
    doc = build_sarif(res)
    pwn = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "AG002")
    related = pwn["relatedLocations"]
    assert related[0]["physicalLocation"]["region"]["startLine"] == 10
    assert related[0]["message"]["text"]


def test_json_output():
    data = json.loads(render(_result(), "json"))
    assert data["tool"]["name"] == "actionguard"
    assert data["summary"]["findings"] == len(data["findings"])
    assert data["summary"]["by_severity"]["critical"] == 1
    first = data["findings"][0]
    assert {"rule_id", "severity", "message", "path", "line", "column", "fingerprint"} <= set(first)


def test_markdown_output():
    md = render(_result(), "markdown")
    assert md.startswith("## actionguard report")
    assert "| critical | [AG001]" in md
    assert "`.github/workflows/w.yml:7`" in md


def test_text_output_has_excerpt_and_caret_without_color():
    text = render(_result(), "text", color=False)
    assert "\x1b[" not in text
    assert ".github/workflows/w.yml" in text
    assert "CRITICAL" in text
    assert '7 | - run: echo "${{ github.event.issue.title }}"' in text
    lines = text.splitlines()
    idx = next(
        i for i, line in enumerate(lines) if 'echo "${{ github.event.issue.title }}"' in line
    )
    caret_line = lines[idx + 1]
    assert caret_line.count("^") == len("${{ github.event.issue.title }}")
    assert caret_line.index("^") == lines[idx].index("${{")
    assert "Found 3 findings" in text


def test_text_output_color():
    text = render(_result(), "text", color=True)
    assert "\x1b[" in text


def test_clean_result_messages():
    clean = ScanResult(files=[analyze_text("on: push\npermissions: {}\njobs: {}\n", "w.yml")])
    assert "No findings in 1 file." in render(clean, "text")
    assert "No findings" in render(clean, "markdown")
    assert json.loads(render(clean, "sarif"))["runs"][0]["results"] == []
