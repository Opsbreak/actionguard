"""AG008 GITHUB_ENV / GITHUB_PATH injection."""

from __future__ import annotations

from actionguard.models import Severity
from tests.conftest import only, run_scan


def ag008(text: str):
    return only(run_scan(text, select=("AG008",)), "AG008")


def test_expression_written_to_github_env():
    findings = ag008(
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
        """
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "`TITLE`" in findings[0].message


def test_tainted_shell_variable_written_to_github_env():
    findings = ag008(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              T: ${{ github.event.issue.title }}
            steps:
              - run: echo "ISSUE_TITLE=$T" >> "$GITHUB_ENV"
        """
    )
    assert len(findings) == 1


def test_heredoc_and_group_writes():
    findings = ag008(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              BODY: ${{ github.event.issue.body }}
            steps:
              - run: |
                  {
                    echo "SAFE=1"
                    echo "BODY=$BODY"
                  } >> "$GITHUB_ENV"
              - run: |
                  cat <<EOF >> $GITHUB_ENV
                  X=${{ github.event.issue.title }}
                  EOF
        """
    )
    assert sorted(f.location.line for f in findings) == [11, 15]


def test_github_path_write():
    findings = ag008(
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.head_ref }}/bin" >> "$GITHUB_PATH"
        """
    )
    assert len(findings) == 1
    assert "PATH" in findings[0].message


def test_powershell_write():
    findings = ag008(
        """
        on: issue_comment
        jobs:
          a:
            runs-on: windows-latest
            steps:
              - shell: pwsh
                env:
                  C: ${{ github.event.comment.body }}
                run: Add-Content -Path $env:GITHUB_ENV -Value "CMD=$env:C"
        """
    )
    assert len(findings) == 1


def test_github_script_export_variable():
    findings = ag008(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    core.exportVariable('TITLE', context.payload.issue.title);
                    core.exportVariable('N', context.issue.number);
        """
    )
    assert len(findings) == 1
    assert findings[0].location.line == 9


def test_safe_writes_are_not_flagged():
    findings = ag008(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              N: ${{ github.event.issue.number }}
            steps:
              - run: |
                  echo "NUMBER=$N" >> "$GITHUB_ENV"
                  echo "SHA=${{ github.sha }}" >> "$GITHUB_ENV"
                  echo "$HOME/.local/bin" >> "$GITHUB_PATH"
                  cat "$GITHUB_ENV"
        """
    )
    assert findings == []


def test_node_fs_write_to_github_env():
    findings = ag008(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              T: ${{ github.event.issue.title }}
            steps:
              - run: |
                  node -e "require('fs').appendFileSync(process.env.GITHUB_ENV, 'X=' + process.env.T)"
        """
    )
    assert len(findings) == 1
    assert findings[0].location.line == 9
