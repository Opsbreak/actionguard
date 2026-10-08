"""AG003 pinning, AG004 permissions, AG005 runners, AG007 artifacts, AG010 guards, AG000."""

from __future__ import annotations

from actionguard.config import Config
from actionguard.models import Severity
from tests.conftest import only, run_scan

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


# ----------------------------------------------------------------------------- AG003


def test_unpinned_first_party_and_third_party():
    text = f"""
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: some-org/some-action@v2
          - uses: some-org/other-action@main
          - uses: actions/setup-node@{SHA} # v4.0.0
          - uses: ./local-action
    """
    findings = only(run_scan(text), "AG003")
    sev = {f.location.line: f.severity for f in findings}
    assert sev == {6: Severity.LOW, 7: Severity.MEDIUM, 8: Severity.HIGH}
    assert findings[0].location.column == 15


def test_docker_images_and_reusable_workflows():
    text = """
    on: push
    jobs:
      reuse:
        uses: org/repo/.github/workflows/ci.yml@main
      b:
        runs-on: ubuntu-latest
        steps:
          - uses: docker://alpine:3.20
          - uses: docker://alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
    """
    findings = only(run_scan(text), "AG003")
    assert len(findings) == 2
    assert any("Reusable workflow" in f.message for f in findings)
    assert any("Container image" in f.message for f in findings)


def test_abbreviated_sha_is_not_pinned():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: some-org/x@abc1234
    """
    findings = only(run_scan(text), "AG003")
    assert "abbreviated SHA" in findings[0].message


def test_trusted_actions_allowlist():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: my-org/deploy@v1
          - uses: my-org/tools/setup@v1
          - uses: other/x@v1
    """
    cfg = Config(trusted_actions=["my-org/*"])
    findings = only(run_scan(text, config=cfg), "AG003")
    assert [f.location.line for f in findings] == [8]


# ----------------------------------------------------------------------------- AG004


def test_write_all_permissions():
    text = """
    on: push
    permissions: write-all
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: [{run: echo}]
    """
    findings = only(run_scan(text), "AG004")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].location.line == 2


def test_missing_permissions_is_info_and_low_when_privileged():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: [{run: echo}]
    """
    assert [f.severity for f in only(run_scan(text), "AG004")] == [Severity.INFO]
    priv = text.replace("on: push", "on: issue_comment")
    assert [f.severity for f in only(run_scan(priv), "AG004")] == [Severity.LOW]


def test_job_level_permissions_satisfy_requirement():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        permissions:
          contents: read
        steps: [{run: echo}]
    """
    assert only(run_scan(text), "AG004") == []


def test_write_scopes_in_privileged_workflow():
    text = """
    on: pull_request_target
    permissions:
      contents: read
      pull-requests: write
      issues: write
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: [{run: echo}]
    """
    findings = only(run_scan(text), "AG004")
    assert sorted(f.location.line for f in findings) == [4, 5]
    assert all(f.severity == Severity.MEDIUM for f in findings)


def test_reusable_only_workflow_without_permissions_not_reported():
    text = """
    on: workflow_call
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: [{run: echo}]
    """
    assert only(run_scan(text), "AG004") == []


# ----------------------------------------------------------------------------- AG005


def test_self_hosted_on_pull_request():
    text = """
    on: [push, pull_request]
    permissions: {}
    jobs:
      a:
        runs-on: [self-hosted, linux]
        steps: [{run: echo}]
      b:
        runs-on: ubuntu-latest
        steps: [{run: echo}]
    """
    findings = only(run_scan(text), "AG005")
    assert [f.job for f in findings] == ["a"]


def test_self_hosted_via_matrix_and_labels_mapping():
    text = """
    on: pull_request
    jobs:
      a:
        strategy:
          matrix:
            runner: [ubuntu-latest, self-hosted]
        runs-on: ${{ matrix.runner }}
        steps: [{run: echo}]
      b:
        runs-on:
          group: builders
          labels: [self-hosted, gpu]
        steps: [{run: echo}]
    """
    assert len(only(run_scan(text), "AG005")) == 2


def test_self_hosted_on_push_only_is_fine():
    text = """
    on: push
    jobs:
      a:
        runs-on: self-hosted
        steps: [{run: echo}]
    """
    assert only(run_scan(text), "AG005") == []


# ----------------------------------------------------------------------------- AG007


def test_artifact_into_workspace_root_then_executed():
    text = """
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/download-artifact@v4
            with:
              run-id: ${{ github.event.workflow_run.id }}
              github-token: ${{ github.token }}
          - run: make publish
    """
    findings = only(run_scan(text), "AG007")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].location.line == 7


def test_artifact_isolated_directory_is_fine():
    text = """
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: dawidd6/action-download-artifact@v6
            with:
              path: ${{ runner.temp }}/artifacts
          - run: make publish
    """
    assert only(run_scan(text), "AG007") == []


def test_gh_run_download_and_unsafe_read():
    text = """
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: gh run download ${{ github.event.workflow_run.id }} -D /tmp/art
          - run: echo "PR=$(cat /tmp/art/pr.txt)" >> "$GITHUB_ENV"
    """
    findings = only(run_scan(text), "AG007")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].location.line == 7


def test_same_run_download_artifact_is_not_cross_run():
    text = """
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/download-artifact@v4
            with:
              name: built-earlier-in-this-run
          - run: make
    """
    assert only(run_scan(text), "AG007") == []


# ----------------------------------------------------------------------------- AG010


def test_comment_gate_without_authorization():
    text = """
    on: issue_comment
    jobs:
      deploy:
        if: contains(github.event.comment.body, '/deploy')
        runs-on: ubuntu-latest
        steps:
          - run: ./deploy.sh
            env:
              KEY: ${{ secrets.KEY }}
    """
    findings = only(run_scan(text), "AG010")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # job uses secrets
    assert findings[0].location.line == 4


def test_comment_gate_with_author_association_is_fine():
    text = """
    on: issue_comment
    jobs:
      deploy:
        if: >-
          contains(github.event.comment.body, '/deploy') &&
          contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)
        runs-on: ubuntu-latest
        steps: [{run: ./deploy.sh}]
    """
    assert only(run_scan(text), "AG010") == []


def test_authorization_in_needed_job_is_recognised():
    text = """
    on: issue_comment
    jobs:
      authorize:
        runs-on: ubuntu-latest
        steps:
          - uses: actions-cool/check-user-permission@v2
      deploy:
        needs: authorize
        if: startsWith(github.event.comment.body, '/deploy')
        runs-on: ubuntu-latest
        steps: [{run: ./deploy.sh}]
    """
    assert only(run_scan(text), "AG010") == []


def test_always_true_if_condition():
    text = """
    on: push
    jobs:
      a:
        if: ${{ github.ref == 'refs/heads/main' }} && false
        runs-on: ubuntu-latest
        steps:
          - if: ${{ false }}
            run: echo fine
          - if: success() && github.event_name == 'push'
            run: echo fine
    """
    findings = only(run_scan(text), "AG010")
    assert len(findings) == 1
    assert findings[0].location.line == 4


# ----------------------------------------------------------------------------- AG000


def test_parse_error_reported_as_finding():
    findings = run_scan("on: push\njobs:\n  a:\n    run: echo: x\n")
    assert [f.rule_id for f in findings] == ["AG000"]
    assert findings[0].location.line == 4


def test_non_workflow_yaml_is_skipped():
    from actionguard.engine import analyze_text

    result = analyze_text("key: value\n", "config.yml", explicit=False)
    assert result.kind is None
    assert result.findings == []
    assert result.error is None
