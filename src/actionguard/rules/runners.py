"""AG005 self-hosted runners reachable from pull requests."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from actionguard.analysis import AnalysisContext
from actionguard.expressions import context_refs, find_expressions, safe_parse
from actionguard.knowledge import PUBLIC_PR_TRIGGERS
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register, strings_in
from actionguard.workflow import Job
from actionguard.yamlloader import YMap

AG005 = Rule(
    id="AG005",
    name="self-hosted-runner",
    title="Self-hosted runner reachable from pull request triggers",
    severity=Severity.HIGH,
    description=(
        "Jobs triggered by pull requests or PR comments execute contributor-controlled code. On "
        "GitHub-hosted runners that code runs in a fresh VM; on a self-hosted runner it runs on "
        "your infrastructure, can persist (backdoor the runner for later jobs that hold secrets), "
        "and can pivot into your network. In public repositories any GitHub user can open a PR."
    ),
    remediation=(
        "Use GitHub-hosted runners for workflows reachable from pull requests, or use ephemeral, "
        "isolated self-hosted runners (`--ephemeral`, one VM per job) in a dedicated runner group "
        "restricted to trusted workflows, and require approval for all outside contributors."
    ),
    references=(
        "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
        "https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/",
    ),
    tags=("security", "infrastructure", "CWE-269"),
)


def _matrix_values(job: Job, key: str | None) -> list[str]:
    matrix = job.strategy.get("matrix")
    if not isinstance(matrix, YMap):
        return []
    values: list[str] = []
    for k, v in matrix.items():
        k = str(k).lower()
        if k in ("include", "exclude"):
            if k == "include" and isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        for k2, v2 in item.items():
                            if key is None or str(k2).lower() == key:
                                values.extend(strings_in(v2))
            continue
        if key is None or k == key:
            values.extend(strings_in(v))
    return values


def runner_labels(job: Job) -> list[str]:
    runs_on: Any = job.runs_on
    raw: list[str] = []
    if isinstance(runs_on, dict):
        raw.extend(strings_in(runs_on.get("labels")))
        raw.extend(strings_in(runs_on.get("group")))
    else:
        raw.extend(strings_in(runs_on))
    labels: list[str] = []
    for label in raw:
        spans = find_expressions(label)
        if not spans:
            labels.append(label.strip().lower())
            continue
        for span in spans:
            node = safe_parse(span.inner)
            for ref in context_refs(node) if node is not None else []:
                if ref.path[0] == "matrix":
                    key = ref.path[1] if len(ref.path) > 1 else None
                    labels.extend(v.strip().lower() for v in _matrix_values(job, key))
            # literals inside the expression, e.g. fromJSON('["self-hosted","linux"]')
            if "self-hosted" in span.inner.lower():
                labels.append("self-hosted")
    return labels


@register(AG005)
def check_self_hosted(ctx: AnalysisContext) -> Iterator[Finding]:
    triggers = sorted(set(ctx.wf.triggers) & PUBLIC_PR_TRIGGERS)
    if not triggers:
        return
    trig = ", ".join(f"`{t}`" for t in triggers)
    for job in ctx.wf.jobs:
        if "self-hosted" not in runner_labels(job):
            continue
        yield ctx.finding(
            "AG005",
            Severity.HIGH,
            f"Job `{job.id}` runs on a self-hosted runner and is reachable from {trig}; "
            "pull request authors can execute code on the runner host and persist across jobs",
            job.raw.value_line("runs-on"),
            job=job,
        )
