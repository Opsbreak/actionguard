"""The shipped examples double as regression fixtures."""

from __future__ import annotations

from collections import Counter

from actionguard.engine import discover, scan
from actionguard.models import Severity
from tests.conftest import EXAMPLES, ROOT


def test_discovery_of_repo_root_includes_composite_actions():
    files = [
        p.relative_to(EXAMPLES).as_posix() for p, _ in discover([EXAMPLES / "vulnerable-repo"])
    ]
    assert "vulnerable-repo/.github/actions/setup-env/action.yml" in files
    assert sum(1 for f in files if "/workflows/" in f) == 5


def test_vulnerable_repo_triggers_every_rule():
    result = scan([EXAMPLES / "vulnerable-repo"], cwd=ROOT)
    rules = Counter(f.rule_id for f in result.findings)
    for rid in [f"AG{n:03d}" for n in range(1, 11)]:
        assert rules[rid] >= 1, f"{rid} not triggered by the vulnerable examples"
    assert "AG000" not in rules
    assert result.max_severity() == Severity.CRITICAL


def test_vulnerable_repo_key_findings():
    result = scan([EXAMPLES / "vulnerable-repo"], cwd=ROOT)
    by_file: dict[str, set[str]] = {}
    for f in result.findings:
        by_file.setdefault(f.location.path.rsplit("/", 1)[-1], set()).add(f.rule_id)
    assert {"AG002", "AG006", "AG009"} <= by_file["pr-preview.yml"]
    assert {"AG005", "AG010", "AG002", "AG001"} <= by_file["comment-ops.yml"]
    assert {"AG007", "AG008"} <= by_file["post-ci.yml"]
    assert {"AG004", "AG006", "AG010", "AG009"} <= by_file["release.yml"]
    # the "safe" shell-variable step in issue-triage.yml must not be reported
    triage = [f for f in result.findings if f.location.path.endswith("issue-triage.yml")]
    assert all("Title was" not in f.snippet for f in triage)


def test_hardened_repo_is_clean():
    result = scan([EXAMPLES / "hardened-repo"], cwd=ROOT)
    assert [f for f in result.findings if f.severity > Severity.INFO] == []
    assert len(result.scanned) == 8
