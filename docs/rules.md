# actionguard rules

| ID | Name | Default severity | Title |
|---|---|---|---|
| [AG000](#ag000) | `parse-error` | high | File could not be parsed |
| [AG001](#ag001) | `script-injection` | critical | Script injection via untrusted input in run/script |
| [AG002](#ag002) | `pwn-request` | critical | Untrusted pull request code executed in a privileged context (pwn request) |
| [AG003](#ag003) | `unpinned-uses` | medium | Action or reusable workflow not pinned to an immutable commit SHA |
| [AG004](#ag004) | `excessive-permissions` | high | Excessive or implicit GITHUB_TOKEN permissions |
| [AG005](#ag005) | `self-hosted-runner` | high | Self-hosted runner reachable from pull request triggers |
| [AG006](#ag006) | `secrets-exposure` | high | Secrets exposed to untrusted code or unpinned reusable workflows |
| [AG007](#ag007) | `artifact-poisoning` | high | Artifact poisoning: untrusted artifacts extracted into the workspace |
| [AG008](#ag008) | `github-env-injection` | critical | Untrusted data written to GITHUB_ENV / GITHUB_PATH |
| [AG009](#ag009) | `persisted-credentials` | low | actions/checkout persists the GITHUB_TOKEN where untrusted code or artifacts can reach it |
| [AG010](#ag010) | `bypassable-if-guard` | high | Bypassable `if:` guard on a dangerous trigger |

<a id="ag000"></a>

## AG000: File could not be parsed

**Name:** `parse-error` | **Default severity:** high

The file is not valid YAML (or not a valid workflow/action document), so it could not be analysed. GitHub will also refuse to run it. actionguard keeps scanning other files.

**Remediation.** Fix the syntax error at the reported position; `actionlint` gives detailed schema errors.

**References**

- <https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions>

<a id="ag001"></a>

## AG001: Script injection via untrusted input in run/script

**Name:** `script-injection` | **Default severity:** critical

`${{ }}` expressions are expanded by the runner *before* the script is handed to the shell (or to Node.js for actions/github-script). When the expanded value is attacker-controlled -- an issue title, PR body, branch name, commit message -- the attacker can close the surrounding quotes and append their own commands, which then run with the job's GITHUB_TOKEN and secrets. actionguard follows untrusted data through env: blocks, $GITHUB_ENV, step outputs ($GITHUB_OUTPUT), job outputs (needs.*) and matrix values, and only reports expressions whose *value* can carry the data (a boolean `contains(...)` cannot). Referencing a tainted env var through the shell (`"$TITLE"`) is safe and is not reported.

**Remediation.** Never interpolate untrusted values into code. Bind the expression to an environment variable and reference that variable from the shell, quoted: `env: TITLE: ${{ github.event.issue.title }}` then `echo "$TITLE"`. In actions/github-script, read `process.env.TITLE` or `context.payload` instead of using `${{ }}` in `script:`.

**References**

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections>
- <https://securitylab.github.com/resources/github-actions-untrusted-input/>
- <https://cwe.mitre.org/data/definitions/78.html>

<a id="ag002"></a>

## AG002: Untrusted pull request code executed in a privileged context (pwn request)

**Name:** `pwn-request` | **Default severity:** critical

`pull_request_target`, `workflow_run` and `issue_comment` workflows run in the context of the base repository: they receive repository secrets and a GITHUB_TOKEN that is usually writable, even when triggered by a fork. Checking out the pull request's head (`ref: ${{ github.event.pull_request.head.sha }}`, `refs/pull/N/merge`, `gh pr checkout`, `git fetch origin pull/N/head`) and then running *anything* that reads the workspace -- `npm install`, `make`, `pip install .`, a local action, a build action -- lets the PR author execute arbitrary code with those privileges.

**Remediation.** Split the workflow: run untrusted code in an unprivileged `pull_request` workflow and hand results to a privileged `workflow_run` workflow as *data* (artifacts treated as untrusted). If you must check out PR code under pull_request_target, never execute it: check it out into a separate path, set `persist-credentials: false`, drop permissions to `contents: read`, and avoid build/test/install steps. Label or `if:` gates are not a fix -- an attacker can push new commits after approval (TOCTOU).

**References**

- <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
- <https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#pull_request_target>

<a id="ag003"></a>

## AG003: Action or reusable workflow not pinned to an immutable commit SHA

**Name:** `unpinned-uses` | **Default severity:** medium

Tags and branches are mutable: anyone with write access to the action's repository (or an attacker who compromises it) can repoint `v4` or `main` to malicious code, which every consumer then runs with their secrets -- as happened with tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154). Only a full 40-character commit SHA is immutable. The same applies to `docker://` images without an `@sha256:` digest and to reusable workflows referenced by branch. First-party `actions/*` and `github/*` actions are reported at lower severity.

**Remediation.** Pin to a full commit SHA and keep the human-readable version in a trailing comment, e.g. `uses: actions/checkout@<40-hex-sha> # v4.2.2`. `actionguard pin --write` does this automatically; Dependabot and Renovate keep such pins updated. Pin images by digest (`docker://alpine@sha256:...`).

**References**

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>
- <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>

<a id="ag004"></a>

## AG004: Excessive or implicit GITHUB_TOKEN permissions

**Name:** `excessive-permissions` | **Default severity:** high

Every job receives a GITHUB_TOKEN. Without a `permissions:` block the token gets the repository/organisation default, which for many repositories is read/write on every scope. `write-all` grants every scope explicitly. Write scopes are particularly dangerous in workflows triggered by `pull_request_target`, `issue_comment` or `workflow_run`, where outside contributors influence what the job does: any injection or pwn request becomes a repository takeover (push to branches, publish releases, approve PRs).

**Remediation.** Declare `permissions: {}` or `permissions: contents: read` at the workflow level and grant the minimum additional scopes per job. Move write operations in privileged workflows into separate, minimal jobs that never handle untrusted input.

**References**

- <https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token>
- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token>

<a id="ag005"></a>

## AG005: Self-hosted runner reachable from pull request triggers

**Name:** `self-hosted-runner` | **Default severity:** high

Jobs triggered by pull requests or PR comments execute contributor-controlled code. On GitHub-hosted runners that code runs in a fresh VM; on a self-hosted runner it runs on your infrastructure, can persist (backdoor the runner for later jobs that hold secrets), and can pivot into your network. In public repositories any GitHub user can open a PR.

**Remediation.** Use GitHub-hosted runners for workflows reachable from pull requests, or use ephemeral, isolated self-hosted runners (`--ephemeral`, one VM per job) in a dedicated runner group restricted to trusted workflows, and require approval for all outside contributors.

**References**

- <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>
- <https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/>

<a id="ag006"></a>

## AG006: Secrets exposed to untrusted code or unpinned reusable workflows

**Name:** `secrets-exposure` | **Default severity:** high

`secrets: inherit` forwards *every* repository and organisation secret to the called workflow. If that workflow lives in another repository and is referenced by a mutable tag or branch, whoever can move that ref receives all secrets. Separately, in a privileged workflow that has checked out pull request code, any later step that receives a secret (via env:, with: or the script) runs next to attacker-controlled files and processes that can read it.

**Remediation.** Pass only the secrets the callee needs (`secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`) and pin external reusable workflows to a full commit SHA. Never provide secrets to steps that run after untrusted code is checked out; move them to a separate job that does not check out the PR.

**References**

- <https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow>
- <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>

<a id="ag007"></a>

## AG007: Artifact poisoning: untrusted artifacts extracted into the workspace

**Name:** `artifact-poisoning` | **Default severity:** high

A `workflow_run` workflow runs with secrets and a writable token after an unprivileged workflow (often `pull_request` from a fork) completes. Artifacts produced by that triggering run are attacker-controlled. Downloading them into the workspace root lets a malicious artifact overwrite files the privileged job later executes or trusts (`package.json`, `Makefile`, scripts, `.git/hooks`), and reading artifact contents into $GITHUB_ENV/$GITHUB_OUTPUT or `eval` turns data into code.

**Remediation.** Download artifacts into an isolated directory such as `${{ runner.temp }}/artifacts`, treat every file as untrusted data, validate its contents strictly (e.g. a PR number must match `^[0-9]+$`) and never execute or `source` it.

**References**

- <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
- <https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust>

<a id="ag008"></a>

## AG008: Untrusted data written to GITHUB_ENV / GITHUB_PATH

**Name:** `github-env-injection` | **Default severity:** critical

Lines written to the $GITHUB_ENV file become environment variables for every later step; lines written to $GITHUB_PATH are prepended to PATH. If the written data is attacker-controlled, a newline lets the attacker define arbitrary variables such as `BASH_ENV`, `LD_PRELOAD` or `NODE_OPTIONS=--require=...`, or put an attacker-chosen directory in front of PATH -- turning data into code execution in subsequent steps. Unlike AG001, this applies even when the value is passed through a shell variable.

**Remediation.** Do not export untrusted values through $GITHUB_ENV/$GITHUB_PATH. Keep them in step-local `env:` and pass them explicitly to the steps that need them, or validate them against a strict allow-list (e.g. `^[0-9]+$`) before writing.

**References**

- <https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-an-environment-variable>
- <https://securitylab.github.com/research/github-actions-untrusted-input/>

<a id="ag009"></a>

## AG009: actions/checkout persists the GITHUB_TOKEN where untrusted code or artifacts can reach it

**Name:** `persisted-credentials` | **Default severity:** low

By default actions/checkout writes the job token into `.git/config` (`persist-credentials: true`). Code that later runs in the job can read it, and uploading the workspace (or `.git`) as an artifact publishes it to anyone who can download artifacts (the ArtiPACKED class of leaks).

**Remediation.** Set `persist-credentials: false` on actions/checkout unless a later step really needs to push with the token, and upload only explicit build output directories.

**References**

- <https://github.com/actions/checkout#usage>
- <https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/>

<a id="ag010"></a>

## AG010: Bypassable `if:` guard on a dangerous trigger

**Name:** `bypassable-if-guard` | **Default severity:** high

Comment-driven automation (`/deploy`, `/test`, `/release`) commonly gates jobs with `if: contains(github.event.comment.body, '/deploy')`. The comment text is chosen by the commenter, and on public repositories *anyone* can comment, so the condition is not an authorization check. Separately, an `if:` that mixes literal text with a `${{ }}` expression (`if: ${{ a }} && b`) is a non-empty string after substitution and therefore always true, silently disabling the guard.

**Remediation.** Combine the command check with an authorization check, e.g. `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`, or verify the commenter's repository permission via the API before doing anything privileged. Write `if:` conditions either entirely inside one `${{ }}` or without `${{ }}` at all.

**References**

- <https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/evaluate-expressions-in-workflows-and-actions>
- <https://docs.github.com/en/webhooks/webhook-events-and-payloads#issue_comment>
