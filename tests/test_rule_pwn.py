"""AG002 pwn request, AG006 secrets exposure, AG009 persisted credentials."""

from __future__ import annotations

from actionguard.models import Severity
from tests.conftest import only, run_scan

PWN = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""


def test_classic_pwn_request():
    findings = only(run_scan(PWN), "AG002")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.location.line == 8  # the ref: line
    assert {r.location.line for r in f.related} == {8, 9}
    assert "line 9" in f.message


def test_checkout_without_execution_is_not_a_pwn_request():
    text = """
    on: pull_request_target
    jobs:
      label:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - uses: actions/labeler@v5
    """
    assert only(run_scan(text), "AG002") == []


def test_checkout_of_base_is_safe():
    text = """
    on: pull_request_target
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - run: make lint
    """
    assert only(run_scan(text), "AG002") == []


def test_pull_request_trigger_is_not_privileged():
    text = PWN.replace("pull_request_target", "pull_request")
    assert only(run_scan(text), "AG002") == []


def test_issue_comment_with_refs_pull_merge_and_local_action():
    text = """
    on: issue_comment
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: refs/pull/${{ github.event.issue.number }}/merge
          - uses: ./.github/actions/test
    """
    findings = only(run_scan(text), "AG002")
    assert len(findings) == 1


def test_gh_pr_checkout_and_git_fetch_variants():
    text = """
    on: issue_comment
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: |
              git fetch origin pull/${{ github.event.issue.number }}/head:pr
              git checkout pr
              make
    """
    findings = only(run_scan(text), "AG002")
    assert len(findings) == 1
    assert findings[0].location.line == 7


def test_workflow_run_head_sha_through_env():
    text = """
    on: workflow_run
    jobs:
      a:
        runs-on: ubuntu-latest
        env:
          HEAD: ${{ github.event.workflow_run.head_sha }}
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ env.HEAD }}
          - uses: docker/build-push-action@v6
    """
    assert len(only(run_scan(text), "AG002")) == 1


def test_same_repo_guard_downgrades():
    text = """
    on: pull_request_target
    jobs:
      build:
        if: github.event.pull_request.head.repo.full_name == github.repository
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - run: npm test
    """
    findings = only(run_scan(text), "AG002")
    assert [f.severity for f in findings] == [Severity.LOW]


def test_secrets_after_untrusted_checkout():
    text = (
        PWN
        + """\
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
      - run: echo done
"""
    )
    findings = only(run_scan(text), "AG006")
    assert len(findings) == 1
    assert "NPM_TOKEN" in findings[0].message
    assert findings[0].severity == Severity.HIGH


def test_secrets_before_untrusted_checkout_are_fine():
    text = """
    on: pull_request_target
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: ./notify.sh
            env:
              TOKEN: ${{ secrets.SLACK }}
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.ref }}
    """
    assert only(run_scan(text), "AG006") == []


def test_secrets_inherit_to_unpinned_external_workflow():
    text = """
    on: push
    jobs:
      call:
        uses: other-org/workflows/.github/workflows/build.yml@v1
        secrets: inherit
      pinned:
        uses: other-org/workflows/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567
        secrets: inherit
      local:
        uses: ./.github/workflows/build.yml
        secrets: inherit
    """
    findings = only(run_scan(text), "AG006")
    assert len(findings) == 1
    assert findings[0].job == "call"


def test_persist_credentials_with_untrusted_code():
    findings = only(run_scan(PWN), "AG009")
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    safe = PWN.replace(
        "ref: ${{ github.event.pull_request.head.sha }}",
        "ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false",
    )
    assert only(run_scan(safe), "AG009") == []


def test_persist_credentials_with_workspace_upload():
    text = """
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/upload-artifact@v4
            with:
              name: all
              path: ${{ github.workspace }}
    """
    assert len(only(run_scan(text), "AG009")) == 1
    narrow = text.replace("${{ github.workspace }}", "dist/")
    assert only(run_scan(narrow), "AG009") == []
