"""AG001 script injection, including taint propagation."""

from __future__ import annotations

from actionguard.models import Severity
from tests.conftest import only, run_scan


def ag001(text: str, path: str = "workflow.yml"):
    return only(run_scan(text, path, select=("AG001",)), "AG001")


def test_direct_issue_title_in_run_is_critical():
    findings = ag001(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"
        """
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL  # `issues` is privileged
    assert f.location.line == 6
    assert f.location.column == 20
    assert "github.event.issue.title" in f.message


def test_pull_request_trigger_is_high_not_critical():
    findings = ag001(
        """
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo hi
                  git log ${{ github.head_ref }}
        """
    )
    assert [f.severity for f in findings] == [Severity.HIGH]
    assert findings[0].location.line == 8


def test_bracket_and_wildcard_access_detected():
    findings = ag001(
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event['head_commit']['message'] }}"
              - run: echo "${{ join(github.event.commits.*.author.name, ',') }}"
        """
    )
    assert len(findings) == 2


def test_tojson_of_untrusted_object_is_flagged():
    findings = ag001(
        """
        on: issue_comment
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo '${{ toJSON(github.event.comment) }}'
        """
    )
    assert len(findings) == 1


def test_boolean_functions_are_not_flagged():
    findings = ag001(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ contains(github.event.issue.title, 'bug') }}"
              - run: echo "${{ github.event.issue.number }} ${{ github.sha }}"
        """
    )
    assert findings == []


def test_env_taint_via_expression_is_flagged_but_shell_var_is_not():
    findings = ag001(
        """
        on: pull_request_target
        env:
          TITLE: ${{ github.event.pull_request.title }}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "$TITLE"
              - run: echo "${TITLE}"
              - run: echo "${{ env.TITLE }}"
        """
    )
    assert len(findings) == 1
    assert findings[0].location.line == 10
    assert "env.TITLE" in findings[0].message


def test_step_env_overrides_job_env():
    findings = ag001(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              X: ${{ github.event.issue.body }}
            steps:
              - env:
                  X: constant
                run: echo "${{ env.X }}"
              - run: echo "${{ env.X }}"
        """
    )
    assert [f.location.line for f in findings] == [11]


def test_step_output_taint_propagates():
    findings = ag001(
        """
        on: issue_comment
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - id: parse
                run: echo "cmd=${{ github.event.comment.body }}" >> "$GITHUB_OUTPUT"
              - run: ./run.sh ${{ steps.parse.outputs.cmd }}
        """
    )
    lines = sorted(f.location.line for f in findings)
    assert lines == [7, 8]
    later = next(f for f in findings if f.location.line == 8)
    assert "steps.parse.outputs.cmd" in later.message


def test_step_output_via_shell_variable_and_local_assignment():
    findings = ag001(
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - id: meta
                env:
                  REF: ${{ github.head_ref }}
                run: |
                  branch="${REF#refs/heads/}"
                  echo "branch=$branch" >> $GITHUB_OUTPUT
              - run: echo ${{ steps.meta.outputs.branch }}
        """
    )
    assert len(findings) == 1
    assert "$branch" in findings[0].message


def test_untainted_output_is_not_flagged():
    findings = ag001(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - id: v
                run: echo "version=1.2.3" >> "$GITHUB_OUTPUT"
              - run: echo ${{ steps.v.outputs.version }}
        """
    )
    assert findings == []


def test_job_outputs_propagate_through_needs():
    findings = ag001(
        """
        on: issue_comment
        jobs:
          parse:
            runs-on: ubuntu-latest
            outputs:
              target: ${{ steps.p.outputs.target }}
            steps:
              - id: p
                env:
                  BODY: ${{ github.event.comment.body }}
                run: echo "target=$BODY" >> $GITHUB_OUTPUT
          use:
            needs: parse
            runs-on: ubuntu-latest
            steps:
              - run: deploy ${{ needs.parse.outputs.target }}
        """
    )
    assert len(findings) == 1
    assert "needs.parse.outputs.target" in findings[0].message
    assert findings[0].job == "use"


def test_github_env_write_taints_later_env_reference():
    findings = ag001(
        """
        on: workflow_run
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  B: ${{ github.event.workflow_run.head_branch }}
                run: echo "BRANCH=$B" >> "$GITHUB_ENV"
              - run: echo "${{ env.BRANCH }}"
        """
    )
    assert len(findings) == 1
    assert "$GITHUB_ENV" in findings[0].message


def test_matrix_values_from_untrusted_input():
    findings = ag001(
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            strategy:
              matrix:
                name: ["${{ github.event.pull_request.title }}"]
            steps:
              - run: echo ${{ matrix.name }}
        """
    )
    assert len(findings) == 1


def test_github_script_injection_and_safe_alternative():
    findings = ag001(
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    const t = "${{ github.event.issue.title }}";
                    const ok = context.payload.issue.title;
        """
    )
    assert len(findings) == 1
    assert "JavaScript" in findings[0].message
    assert findings[0].location.line == 9


def test_workflow_dispatch_inputs_are_low_and_typed_inputs_ignored():
    findings = ag001(
        """
        on:
          workflow_dispatch:
            inputs:
              name: {type: string}
              count: {type: number}
              env: {type: choice, options: [a, b]}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ inputs.name }} ${{ inputs.count }} ${{ inputs.env }}
              - run: echo ${{ github.event.inputs.name }}
        """
    )
    assert len(findings) == 2
    assert {f.severity for f in findings} == {Severity.LOW}


def test_workflow_call_inputs_are_medium():
    findings = ag001(
        """
        on:
          workflow_call:
            inputs:
              ref: {type: string, required: true}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: git checkout ${{ inputs.ref }}
        """
    )
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_composite_action_inputs():
    findings = ag001(
        """
        name: x
        inputs:
          v: {description: version}
        runs:
          using: composite
          steps:
            - shell: bash
              run: install ${{ inputs.v }}
            - shell: bash
              env:
                V: ${{ inputs.v }}
              run: install "$V"
        """,
        path="action.yml",
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].location.line == 8


def test_known_tainted_action_outputs():
    findings = ag001(
        """
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - id: changed
                uses: tj-actions/changed-files@v46
              - run: for f in ${{ steps.changed.outputs.all_changed_files }}; do echo $f; done
        """
    )
    assert len(findings) == 1


def test_extra_untrusted_contexts_from_config():
    from actionguard.config import Config

    text = """
    on: repository_dispatch
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo ${{ github.event.custom_payload.cmd }}
    """
    assert only(run_scan(text, select=("AG001",)), "AG001") == []
    cfg = Config(untrusted_contexts=["github.event.custom_payload"])
    assert len(only(run_scan(text, config=cfg, select=("AG001",)), "AG001")) == 1
