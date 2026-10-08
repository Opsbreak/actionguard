"""End-to-end CLI tests (in-process via main() and out-of-process via subprocess)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from actionguard import cli
from actionguard.pin import Resolution
from tests.conftest import EXAMPLES, ROOT

VULN = """\
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
"""


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "vuln.yml").write_text(VULN, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_scan_default_path_and_exit_code(repo: Path, capsys: pytest.CaptureFixture[str]):
    code = cli.main(["scan", "--color", "never"])
    out = capsys.readouterr().out
    assert code == 1
    assert ".github/workflows/vuln.yml" in out
    assert "AG001" in out


def test_fail_on_threshold(repo: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(["scan", "--fail-on", "critical"]) == 1
    assert cli.main(["scan", "--fail-on", "none"]) == 0
    assert cli.main(["scan", "--ignore", "AG001", "--fail-on", "high"]) == 0
    assert cli.main(["scan", "--select", "AG003", "--fail-on", "low"]) == 1
    capsys.readouterr()


def test_json_and_sarif_to_file(repo: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(["scan", "-f", "json", "--fail-on", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] >= 2
    out = repo / "report.sarif"
    assert cli.main(["scan", "-f", "sarif", "-o", str(out), "--fail-on", "none"]) == 0
    assert "wrote sarif report" in capsys.readouterr().err
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_config_file_is_discovered(repo: Path, capsys: pytest.CaptureFixture[str]):
    (repo / ".actionguard.yml").write_text("ignore: [AG001, AG003, AG004]\n", encoding="utf-8")
    assert cli.main(["scan", "--color", "never"]) == 0
    assert "No findings" in capsys.readouterr().out
    assert cli.main(["scan", "--no-config", "--fail-on", "high"]) == 1
    capsys.readouterr()


def test_usage_errors_exit_2(repo: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(["scan", "does-not-exist.yml"]) == 2
    assert cli.main(["scan", "--select", "AG999"]) == 2
    (repo / "bad.yml").write_text("ignore: [{rule: nope}]\n", encoding="utf-8")
    assert cli.main(["scan", "--config", "bad.yml"]) == 2
    assert cli.main([]) == 2
    err = capsys.readouterr().err
    assert "path not found" in err
    assert "unknown rule id" in err


def test_no_workflows_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan"]) == 2
    assert "no .github/workflows" in capsys.readouterr().err


def test_malformed_file_does_not_stop_scan(repo: Path, capsys: pytest.CaptureFixture[str]):
    (repo / ".github" / "workflows" / "broken.yml").write_text(
        "on: [push\njobs: {", encoding="utf-8"
    )
    code = cli.main(["scan", "-f", "json", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    paths = {f["path"] for f in data["findings"]}
    assert ".github/workflows/broken.yml" in paths
    assert ".github/workflows/vuln.yml" in paths
    assert any(f["rule_id"] == "AG000" for f in data["findings"])


def test_rules_command(capsys: pytest.CaptureFixture[str]):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    for rid in [f"AG{n:03d}" for n in range(1, 11)]:
        assert rid in out
    assert cli.main(["rules", "AG002"]) == 0
    assert "Remediation" in capsys.readouterr().out
    assert cli.main(["rules", "-f", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 11
    assert cli.main(["rules", "-f", "markdown"]) == 0
    assert '<a id="ag001"></a>' in capsys.readouterr().out


def test_pin_command_with_injected_resolver(repo: Path, capsys: pytest.CaptureFixture[str]):
    import argparse

    sha = "f" * 40

    class Fake:
        def resolve(self, owner, repo_, ref):
            return (
                Resolution(sha, "v4.9.9")
                if (owner, repo_, ref) == ("actions", "checkout", "v4")
                else None
            )

    args = argparse.Namespace(paths=[], write=False, resolver="auto", format="text")
    assert cli.cmd_pin(args, resolver=Fake()) == 0
    assert "can be pinned" in capsys.readouterr().out
    args.write = True
    assert cli.cmd_pin(args, resolver=Fake()) == 0
    text = (repo / ".github" / "workflows" / "vuln.yml").read_text(encoding="utf-8")
    assert f"actions/checkout@{sha} # v4.9.9" in text
    args.write = False
    assert cli.cmd_pin(args, resolver=Fake()) == 0
    assert "Nothing to pin" in capsys.readouterr().out


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, "-m", "actionguard", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )


def test_subprocess_version_and_examples():
    proc = _run("--version", cwd=ROOT)
    assert proc.returncode == 0
    assert proc.stdout.startswith("actionguard ")

    vuln = _run("scan", str(EXAMPLES / "vulnerable-repo"), "--fail-on", "high", cwd=ROOT)
    assert vuln.returncode == 1, vuln.stderr
    assert "AG002" in vuln.stdout

    hardened = _run("scan", str(EXAMPLES / "hardened-repo"), "--fail-on", "info", cwd=ROOT)
    assert hardened.returncode == 0, hardened.stdout
    assert "No findings" in hardened.stdout


def test_subprocess_dogfood_own_workflows():
    proc = _run("scan", ".github/workflows", "--fail-on", "info", cwd=ROOT)
    assert proc.returncode == 0, proc.stdout
