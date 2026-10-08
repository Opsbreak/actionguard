"""AG003 unpinned actions, container images and reusable workflows."""

from __future__ import annotations

from collections.abc import Iterator

from actionguard.analysis import AnalysisContext
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register
from actionguard.workflow import Job, Step, parse_uses
from actionguard.yamlloader import YMap, YStr

AG003 = Rule(
    id="AG003",
    name="unpinned-uses",
    title="Action or reusable workflow not pinned to an immutable commit SHA",
    severity=Severity.MEDIUM,
    description=(
        "Tags and branches are mutable: anyone with write access to the action's repository "
        "(or an attacker who compromises it) can repoint `v4` or `main` to malicious code, which "
        "every consumer then runs with their secrets -- as happened with tj-actions/changed-files "
        "(CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154). Only a full 40-character "
        "commit SHA is immutable. The same applies to `docker://` images without an "
        "`@sha256:` digest and to reusable workflows referenced by branch. First-party "
        "`actions/*` and `github/*` actions are reported at lower severity."
    ),
    remediation=(
        "Pin to a full commit SHA and keep the human-readable version in a trailing comment, e.g. "
        "`uses: actions/checkout@<40-hex-sha> # v4.2.2`. `actionguard pin --write` does this "
        "automatically; Dependabot and Renovate keep such pins updated. Pin images by digest "
        "(`docker://alpine@sha256:...`)."
    ),
    references=(
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3",
    ),
    tags=("security", "supply-chain", "CWE-829", "CWE-1357"),
)


def _uses_entries(ctx: AnalysisContext) -> Iterator[tuple[YStr | str, YMap, Job, Step | None]]:
    for job in ctx.wf.jobs:
        if job.uses:
            yield job.uses, job.raw, job, None
        for step in job.steps:
            if step.uses:
                yield step.uses, step.raw, job, step


@register(AG003)
def check_unpinned(ctx: AnalysisContext) -> Iterator[Finding]:
    for value, owner, job, step in _uses_entries(ctx):
        ref = parse_uses(value)
        line = owner.value_line("uses")
        col = value.col if isinstance(value, YStr) else 1
        if ref.kind == "local":
            continue
        if ref.kind == "docker":
            if "@sha256:" not in ref.raw.lower():
                yield ctx.finding(
                    "AG003",
                    Severity.MEDIUM,
                    f"Container image `{ref.raw}` is referenced by a mutable tag; pin it by digest "
                    "(`@sha256:...`)",
                    line,
                    col,
                    job=job,
                    step=step,
                )
            continue
        if ref.is_sha_pinned or ctx.is_trusted_action(ref.name):
            continue
        what = "Reusable workflow" if ref.is_reusable_workflow else "Action"
        if not ref.ref:
            yield ctx.finding(
                "AG003",
                Severity.MEDIUM,
                f"{what} `{ref.raw}` has no ref at all; pin it to a full commit SHA",
                line,
                col,
                job=job,
                step=step,
            )
            continue
        branch = not ref.looks_like_version_tag
        if ref.is_first_party:
            severity = Severity.MEDIUM if branch else Severity.LOW
        else:
            severity = Severity.HIGH if branch else Severity.MEDIUM
        kind = "branch" if branch else "tag"
        if len(ref.ref) >= 7 and all(c in "0123456789abcdef" for c in ref.ref.lower()):
            kind = "abbreviated SHA (ambiguous, can be shadowed by a tag or branch)"
        party = "first-party" if ref.is_first_party else "third-party"
        yield ctx.finding(
            "AG003",
            severity,
            f"{what} `{ref.name}` ({party}) is pinned to mutable {kind} `{ref.ref}` instead of a "
            "full commit SHA",
            line,
            col,
            job=job,
            step=step,
        )
