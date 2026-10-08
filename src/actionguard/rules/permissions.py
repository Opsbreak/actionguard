"""AG004 excessive or implicit GITHUB_TOKEN permissions."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from actionguard.analysis import AnalysisContext
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register
from actionguard.workflow import Job
from actionguard.yamlloader import YMap

AG004 = Rule(
    id="AG004",
    name="excessive-permissions",
    title="Excessive or implicit GITHUB_TOKEN permissions",
    severity=Severity.HIGH,
    description=(
        "Every job receives a GITHUB_TOKEN. Without a `permissions:` block the token gets the "
        "repository/organisation default, which for many repositories is read/write on every "
        "scope. `write-all` grants every scope explicitly. Write scopes are particularly "
        "dangerous in workflows triggered by `pull_request_target`, `issue_comment` or "
        "`workflow_run`, where outside contributors influence what the job does: any injection "
        "or pwn request becomes a repository takeover (push to branches, publish releases, "
        "approve PRs)."
    ),
    remediation=(
        "Declare `permissions: {}` or `permissions: contents: read` at the workflow level and "
        "grant the minimum additional scopes per job. Move write operations in privileged "
        "workflows into separate, minimal jobs that never handle untrusted input."
    ),
    references=(
        "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
    ),
    tags=("security", "least-privilege", "CWE-250", "CWE-732"),
)

_RISKY_TRIGGERS = ("pull_request_target", "issue_comment", "workflow_run")


def _write_scopes(perms: Any) -> list[str]:
    if isinstance(perms, dict):
        return [str(k) for k, v in perms.items() if str(v).strip().lower() == "write"]
    return []


def _is_write_all(perms: Any) -> bool:
    return isinstance(perms, str) and perms.strip().lower() == "write-all"


@register(AG004)
def check_permissions(ctx: AnalysisContext) -> Iterator[Finding]:
    wf = ctx.wf
    if wf.kind != "workflow":
        return
    risky = [t for t in _RISKY_TRIGGERS if t in wf.triggers]
    trig = ", ".join(f"`{t}`" for t in risky)

    scopes: list[tuple[Any, YMap, str, Job | None]] = []
    if wf.has_permissions:
        scopes.append((wf.permissions, wf.raw, "workflow", None))
    for job in wf.jobs:
        if job.has_permissions:
            scopes.append((job.permissions, job.raw, f"job `{job.id}`", job))

    for perms, owner, where, job in scopes:
        line = owner.key_line("permissions")
        if _is_write_all(perms):
            yield ctx.finding(
                "AG004",
                Severity.HIGH,
                f"`permissions: write-all` grants the {where} token write access to every scope"
                + (f" in a workflow triggered by {trig}" if risky else ""),
                line,
                job=job,
            )
            continue
        if risky and isinstance(perms, YMap):
            for scope in _write_scopes(perms):
                yield ctx.finding(
                    "AG004",
                    Severity.MEDIUM,
                    f"`{scope}: write` is granted to the {where} token in a workflow triggered by "
                    f"{trig}, where outside contributors control the event",
                    perms.key_line(scope, line),
                    job=job,
                )

    if not wf.has_permissions and not wf.is_reusable_only:
        missing = [j for j in wf.jobs if not j.has_permissions]
        if missing:
            names = ", ".join(f"`{j.id}`" for j in missing[:5]) + (
                " ..." if len(missing) > 5 else ""
            )
            severity = Severity.LOW if risky else Severity.INFO
            yield ctx.finding(
                "AG004",
                severity,
                f"No `permissions:` block at workflow level or for job(s) {names}; their token "
                "inherits the repository default, which may be read/write on all scopes"
                + (f" (triggered by {trig})" if risky else ""),
                wf.raw.key_line("jobs", 1),
            )
