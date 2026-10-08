"""Configuration file and inline suppressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from actionguard.config import Config, ConfigError, glob_match
from actionguard.engine import ScanOptions, analyze_text, scan
from actionguard.models import Severity
from tests.conftest import run_scan

UNPINNED = """
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/action@v1
"""


def test_inline_suppression_same_line():
    text = UNPINNED.replace("@v1", "@v1  # actionguard: ignore[AG003]")
    assert run_scan(text) == []


def test_inline_suppression_line_above_and_multiple_ids():
    text = UNPINNED.replace(
        "      - uses: some-org/action@v1",
        "      # actionguard: ignore[AG001, AG003]\n      - uses: some-org/action@v1",
    )
    assert run_scan(text) == []


def test_inline_suppression_for_other_rule_does_not_apply():
    text = UNPINNED.replace("@v1", "@v1  # actionguard: ignore[AG001]")
    assert [f.rule_id for f in run_scan(text)] == ["AG003"]


def test_bare_ignore_suppresses_everything_on_line():
    text = UNPINNED.replace("@v1", "@v1  # actionguard: ignore")
    result = analyze_text(text.lstrip("\n"), "w.yml")
    assert result.findings == []
    assert result.suppressed == 1


def test_config_from_dict_and_validation():
    cfg = Config.from_dict(
        {
            "ignore": ["AG004", "legacy/*.yml", {"rule": "AG003", "paths": ["**/release.yml"]}],
            "trusted-actions": ["My-Org/*"],
            "untrusted-contexts": ["github.event.client_payload.*"],
            "select": ["ag001"],
            "min-severity": "low",
            "fail-on": "high",
        }
    )
    assert len(cfg.ignores) == 3
    assert cfg.is_trusted_action("my-org/thing")
    assert cfg.select == ["AG001"]
    assert cfg.min_severity == Severity.LOW
    assert cfg.fail_on == Severity.HIGH
    with pytest.raises(ConfigError):
        Config.from_dict({"bogus": 1})
    with pytest.raises(ConfigError):
        Config.from_dict({"ignore": [{"rule": "nope"}]})
    with pytest.raises(ConfigError):
        Config.from_dict({"fail-on": "catastrophic"})


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        (".github/workflows/release.yml", "**/release.yml", True),
        (".github/workflows/release.yml", "release.yml", True),
        (".github/workflows/release.yml", ".github/*.yml", False),
        (".github/workflows/release.yml", ".github/**", True),
        ("examples/a/b.yml", "examples/**/*.yml", True),
        ("x.yaml", "*.yml", False),
    ],
)
def test_glob_match(path, pattern, expected):
    assert glob_match(path, pattern) is expected


def test_config_file_ignores_by_rule_and_path(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "a.yml").write_text(UNPINNED.lstrip("\n"), encoding="utf-8")
    (wf_dir / "legacy.yml").write_text(UNPINNED.lstrip("\n"), encoding="utf-8")
    (tmp_path / ".actionguard.yml").write_text(
        "ignore:\n  - rule: AG003\n    paths: ['.github/workflows/legacy.yml']\n",
        encoding="utf-8",
    )
    cfg = Config.discover(tmp_path)
    result = scan([str(tmp_path)], config=cfg, cwd=tmp_path)
    assert [f.location.path for f in result.findings] == [".github/workflows/a.yml"]
    assert result.suppressed == 1


def test_min_severity_and_select_options():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: other/x@v1
    """
    from textwrap import dedent

    body = dedent(text).lstrip("\n")
    res = analyze_text(body, "w.yml", options=ScanOptions(min_severity=Severity.MEDIUM))
    assert {f.severity for f in res.findings} == {Severity.MEDIUM}
    res = analyze_text(body, "w.yml", options=ScanOptions(select=["AG004"]))
    assert {f.rule_id for f in res.findings} == {"AG004"}
    res = analyze_text(body, "w.yml", options=ScanOptions(ignore=["AG003", "AG004"]))
    assert res.findings == []


def test_fingerprints_are_stable_across_line_shifts():
    text = UNPINNED.lstrip("\n")
    a = analyze_text(text, "w.yml").findings[0]
    b = analyze_text("# a new comment\n" + text, "w.yml").findings[0]
    assert a.location.line != b.location.line
    assert a.fingerprint == b.fingerprint
