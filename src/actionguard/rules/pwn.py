"""AG002 pwn request, AG006 secrets exposure, AG009 persisted checkout credentials."""

from __future__ import annotations

from collections.abc import Iterator

from actionguard.analysis import AnalysisContext, UntrustedCheckout
from actionguard.expressions import context_refs, fallback_refs, find_expressions, safe_parse
from actionguard.knowledge import PWN_REQUEST_TRIGGERS
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register
from actionguard.workflow import Job, Step, parse_uses

AG002 = Rule(
    id="AG002",
    name="pwn-request",
    title="Untrusted pull request code executed in a privileged context (pwn request)",
    severity=Severity.CRITICAL,
    description=(
        "`pull_request_target`, `workflow_run` and `issue_comment` workflows run in the context "
        "of the base repository: they receive repository secrets and a GITHUB_TOKEN that is "
        "usually writable, even when triggered by a fork. Checking out the pull request's head "
        "(`ref: ${{ github.event.pull_request.head.sha }}`, `refs/pull/N/merge`, `gh pr "
        "checkout`, `git fetch origin pull/N/head`) and then running *anything* that reads the "
        "workspace -- `npm install`, `make`, `pip install .`, a local action, a build action -- "
        "lets the PR author execute arbitrary code with those privileges."
    ),
    remediation=(
        "Split the workflow: run untrusted code in an unprivileged `pull_request` workflow and "
        "hand results to a privileged `workflow_run` workflow as *data* (artifacts treated as "
        "untrusted). If you must check out PR code under pull_request_target, never execute it: "
        "check it out into a separate path, set `persist-credentials: false`, drop permissions to "
        "`contents: read`, and avoid build/test/install steps. Label or `if:` gates are not a "
        "fix -- an attacker can push new commits after approval (TOCTOU)."
    ),
    references=(
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#pull_request_target",
    ),
    tags=("security", "supply-chain", "CWE-829", "CWE-94"),
)

AG006 = Rule(
    id="AG006",
    name="secrets-exposure",
    title="Secrets exposed to untrusted code or unpinned reusable workflows",
    severity=Severity.HIGH,
    description=(
        "`secrets: inherit` forwards *every* repository and organisation secret to the called "
        "workflow. If that workflow lives in another repository and is referenced by a mutable "
        "tag or branch, whoever can move that ref receives all secrets. Separately, in a "
        "privileged workflow that has checked out pull request code, any later step that "
        "receives a secret (via env:, with: or the script) runs next to attacker-controlled "
        "files and processes that can read it."
    ),
    remediation=(
        "Pass only the secrets the callee needs (`secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`) "
        "and pin external reusable workflows to a full commit SHA. Never provide secrets to steps "
        "that run after untrusted code is checked out; move them to a separate job that does "
        "not check out the PR."
    ),
    references=(
        "https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow",
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    ),
    tags=("security", "secrets", "CWE-200", "CWE-522"),
)

AG009 = Rule(
    id="AG009",
    name="persisted-credentials",
    title="actions/checkout persists the GITHUB_TOKEN where untrusted code or artifacts can reach it",
    severity=Severity.LOW,
    description=(
        "By default actions/checkout writes the job token into `.git/config` "
        "(`persist-credentials: true`). Code that later runs in the job can read it, and "
        "uploading the workspace (or `.git`) as an artifact publishes it to anyone who can "
        "download artifacts (the ArtiPACKED class of leaks)."
    ),
    remediation=(
        "Set `persist-credentials: false` on actions/checkout unless a later step really needs "
        "to push with the token, and upload only explicit build output directories."
    ),
    references=(
        "https://github.com/actions/checkout#usage",
        "https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
    ),
    tags=("security", "secrets", "CWE-522"),
)


def _exec_after(
    ctx: AnalysisContext, job: Job, checkout: UntrustedCheckout
) -> tuple[Step, int] | None:
    """First step (or line in the checkout step itself) that executes workspace code."""
    step = checkout.step
    run = step.run
    if run is not None:
        lines = run.split("\n")
        for idx, text in enumerate(lines):
            ln = run.line_of(idx)
            if ln > checkout.line and text.strip() and not text.strip().startswith("#"):
                return step, ln
    for later in job.steps[step.index + 1 :]:
        if ctx.executes_code(later):
            key = "run" if later.run is not None else "uses"
            return later, later.raw.key_line(key, later.line)
    return None


def _pwn_jobs(
    ctx: AnalysisContext,
) -> Iterator[tuple[Job, UntrustedCheckout, tuple[Step, int] | None]]:
    if not ctx.wf.has_trigger(*PWN_REQUEST_TRIGGERS):
        return
    for job in ctx.wf.jobs:
        checkouts = ctx.untrusted_checkouts(job)
        if checkouts:
            yield job, checkouts[0], _exec_after(ctx, job, checkouts[0])


@register(AG002)
def check_pwn_request(ctx: AnalysisContext) -> Iterator[Finding]:
    triggers = ", ".join(f"`{t}`" for t in sorted(set(ctx.wf.triggers) & PWN_REQUEST_TRIGGERS))
    for job, checkout, execution in _pwn_jobs(ctx):
        if execution is None:
            continue
        exec_step, exec_line = execution
        severity = Severity.CRITICAL
        note = ""
        if ctx.same_repo_guarded(job, exec_step) or ctx.same_repo_guarded(job, checkout.step):
            severity = Severity.LOW
            note = " (an `if:` restricts this to same-repository PRs, which limits exposure)"
        elif ctx.label_guarded(job, checkout.step):
            severity = Severity.HIGH
            note = (
                " (a label gate is present, but new commits can be pushed after the label is "
                "applied)"
            )
        yield ctx.finding(
            "AG002",
            severity,
            f"Pwn request: this {triggers} workflow checks out untrusted pull request code "
            f"({checkout.reason}) and executes it at line {exec_line} (step `{exec_step.label}`) "
            f"with repository secrets and a privileged GITHUB_TOKEN{note}",
            checkout.line,
            job=job,
            step=checkout.step,
            related=[
                (checkout.line, "untrusted code is checked out here"),
                (exec_line, "workspace code is executed here"),
            ],
        )


def _secret_refs(value: str) -> list[tuple[int, str]]:
    out = []
    for span in find_expressions(value):
        node = safe_parse(span.inner)
        refs = context_refs(node) if node is not None else fallback_refs(span.inner)
        for ref in refs:
            if ref.path and ref.path[0] == "secrets" and len(ref.path) > 1:
                out.append((span.start, ref.path[1].upper()))
    return out


def _step_secret_refs(step: Step) -> list[tuple[int, str]]:
    """(line, SECRET_NAME) for secrets passed to a step via env:, with: or the script."""
    found: list[tuple[int, str]] = []
    for mapping in (step.env, step.with_):
        for key, value in mapping.items():
            if isinstance(value, str):
                found.extend((mapping.key_line(str(key)), name) for _, name in _secret_refs(value))
    run = step.run
    if run is not None:
        for start, name in _secret_refs(run):
            found.append((run.locate(start, "secrets")[0], name))
    return found


@register(AG006)
def check_secrets_exposure(ctx: AnalysisContext) -> Iterator[Finding]:
    # (a) secrets: inherit to an external, unpinned reusable workflow
    for job in ctx.wf.jobs:
        secrets = job.secrets
        if job.uses and isinstance(secrets, str) and secrets.strip().lower() == "inherit":
            ref = parse_uses(job.uses)
            if ref.kind == "repo" and not ref.is_sha_pinned and not ctx.is_trusted_action(ref.name):
                yield ctx.finding(
                    "AG006",
                    Severity.HIGH,
                    f"`secrets: inherit` passes every secret to reusable workflow `{job.uses}`, "
                    "which lives in another repository and is not pinned to a commit SHA; "
                    "whoever can move that ref receives all of them",
                    job.raw.key_line("secrets", job.line),
                    job=job,
                )
    # (b) secrets reachable after an untrusted checkout in a privileged workflow
    for job, checkout, _ in _pwn_jobs(ctx):
        job_env_secrets = [
            (job.env.key_line(str(k)), name)
            for k, v in job.env.items()
            if isinstance(v, str)
            for _, name in _secret_refs(v)
        ]
        if job_env_secrets:
            names = ", ".join(sorted({n for _, n in job_env_secrets}))
            yield ctx.finding(
                "AG006",
                Severity.HIGH,
                f"Job-level env exposes secret(s) {names} to every step, including code from the "
                f"untrusted pull request checked out at line {checkout.line}",
                job_env_secrets[0][0],
                job=job,
                related=[(checkout.line, "untrusted code is checked out here")],
            )
        for step in job.steps[checkout.step.index :]:
            refs = _step_secret_refs(step)
            if not refs:
                continue
            names = sorted({n for _, n in refs})
            only_token = names == ["GITHUB_TOKEN"]
            yield ctx.finding(
                "AG006",
                Severity.MEDIUM if only_token else Severity.HIGH,
                f"Secret(s) {', '.join(names)} are provided to step `{step.label}`, which runs "
                f"after untrusted pull request code was checked out (line {checkout.line}); that "
                "code can read them from the environment, files or process memory",
                min(ln for ln, _ in refs),
                job=job,
                step=step,
                related=[(checkout.line, "untrusted code is checked out here")],
            )


_WORKSPACE_PATHS = frozenset({".", "*", "**", "**/*", "./*", "./**"})


def _uploads_workspace(step: Step) -> bool:
    """Does an upload-artifact step publish the whole workspace (or the .git directory)?"""
    if not step.uses_action("actions/upload-artifact"):
        return False
    path = step.with_.get("path")
    if not isinstance(path, str):
        return False
    for raw in path.splitlines():
        p = raw.strip().lower()
        if not p or p.startswith("!"):
            continue
        for ws in ("${{ github.workspace }}", "${{github.workspace}}", "$github_workspace"):
            p = p.replace(ws, ".")
        p = p.rstrip("/") or "."
        if p.startswith("./") and len(p) > 2 and p not in _WORKSPACE_PATHS:
            p = p[2:]
        if p in _WORKSPACE_PATHS or ".git" in p.split("/"):
            return True
    return False


@register(AG009)
def check_persist_credentials(ctx: AnalysisContext) -> Iterator[Finding]:
    pwn = {job.id: (checkout, execution) for job, checkout, execution in _pwn_jobs(ctx)}
    for job in ctx.wf.jobs:
        for step in job.steps:
            if not step.uses_action("actions/checkout"):
                continue
            with_ = step.with_
            if str(with_.get("persist-credentials", "true")).strip().lower() == "false":
                continue
            reasons: list[tuple[int, str]] = []
            if job.id in pwn and pwn[job.id][1] is not None:
                _, exec_line = pwn[job.id][1]  # type: ignore[misc]
                if exec_line > step.line:
                    reasons.append((exec_line, "untrusted pull request code runs here"))
            for later in job.steps[step.index + 1 :]:
                if _uploads_workspace(later):
                    reasons.append(
                        (
                            later.raw.key_line("uses", later.line),
                            "the workspace is uploaded as an artifact here",
                        )
                    )
            if not reasons:
                continue
            why = "; ".join(f"{msg.replace(' here', '')} (line {ln})" for ln, msg in reasons)
            yield ctx.finding(
                "AG009",
                Severity.LOW,
                "actions/checkout leaves the GITHUB_TOKEN in .git/config (persist-credentials "
                f"defaults to true) and {why}",
                step.raw.key_line("uses", step.line),
                job=job,
                step=step,
                related=reasons,
            )
