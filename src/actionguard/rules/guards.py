"""AG010 bypassable ``if:`` guards on comment-triggered workflows."""

from __future__ import annotations

import re
from collections.abc import Iterator

from actionguard.analysis import AnalysisContext
from actionguard.expressions import context_refs, fallback_refs, find_expressions, safe_parse
from actionguard.knowledge import COMMENT_TRIGGERS, PERMISSION_CHECK_ACTIONS
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register, strings_in
from actionguard.workflow import Job

AG010 = Rule(
    id="AG010",
    name="bypassable-if-guard",
    title="Bypassable `if:` guard on a dangerous trigger",
    severity=Severity.HIGH,
    description=(
        "Comment-driven automation (`/deploy`, `/test`, `/release`) commonly gates jobs with "
        "`if: contains(github.event.comment.body, '/deploy')`. The comment text is chosen by the "
        "commenter, and on public repositories *anyone* can comment, so the condition is not an "
        "authorization check. Separately, an `if:` that mixes literal text with a `${{ }}` "
        "expression (`if: ${{ a }} && b`) is a non-empty string after substitution and therefore "
        "always true, silently disabling the guard."
    ),
    remediation=(
        "Combine the command check with an authorization check, e.g. "
        '`contains(fromJSON(\'["OWNER","MEMBER","COLLABORATOR"]\'), '
        "github.event.comment.author_association)`, or verify the commenter's repository "
        "permission via the API before doing anything privileged. Write `if:` conditions either "
        "entirely inside one `${{ }}` or without `${{ }}` at all."
    ),
    references=(
        "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/evaluate-expressions-in-workflows-and-actions",
        "https://docs.github.com/en/webhooks/webhook-events-and-payloads#issue_comment",
    ),
    tags=("security", "authorization", "CWE-285", "CWE-863"),
)

_AUTHZ_PATHS = (
    ("github", "event", "comment", "author_association"),
    ("github", "event", "review", "author_association"),
    ("github", "event", "comment", "user", "login"),
    ("github", "event", "sender", "login"),
    ("github", "actor"),
    ("github", "triggering_actor"),
    ("github", "event", "comment", "user", "type"),
)
_GATE_PATHS = (
    ("github", "event", "comment", "body"),
    ("github", "event", "review", "body"),
    ("github", "event", "discussion", "body"),
)
_AUTHZ_SCRIPT_RE = re.compile(
    r"getCollaboratorPermissionLevel|collaborators/[^/\s]+/permission|/collaborators/\$|"
    r"author_association|orgs/[^/\s]+/members/|checkMembershipForUser|teams/[^/\s]+/memberships",
    re.IGNORECASE,
)


def _refs(cond: object) -> list[tuple[str, ...]]:
    if not isinstance(cond, str):
        return []
    text = cond.strip()
    spans = find_expressions(text)
    inners = [s.inner for s in spans] if spans else [text]
    out: list[tuple[str, ...]] = []
    for inner in inners:
        node = safe_parse(inner)
        refs = context_refs(node) if node is not None else fallback_refs(inner)
        out.extend(r.path for r in refs)
    return out


def _has_prefix(paths: list[tuple[str, ...]], prefixes: tuple[tuple[str, ...], ...]) -> bool:
    return any(p[: len(pre)] == pre for p in paths for pre in prefixes)


def _job_authorizes(job: Job) -> bool:
    conds = [job.if_] + [s.if_ for s in job.steps]
    if any(_has_prefix(_refs(c), _AUTHZ_PATHS) for c in conds):
        return True
    if job.raw.get("environment") is not None:
        return True  # deployment environments can require reviewer approval
    for step in job.steps:
        if any(step.uses_action(a) for a in PERMISSION_CHECK_ACTIONS):
            return True
        texts = [str(step.run or ""), *list(strings_in(step.with_))]
        if any(_AUTHZ_SCRIPT_RE.search(t) for t in texts):
            return True
    return False


def _authorized(ctx: AnalysisContext, job: Job, seen: set[str] | None = None) -> bool:
    seen = seen or set()
    if job.id in seen:
        return False
    seen.add(job.id)
    if _job_authorizes(job):
        return True
    for dep in job.needs:
        other = ctx.wf.job(dep)
        if other is not None and _authorized(ctx, other, seen):
            return True
    return False


def _job_is_privileged(ctx: AnalysisContext, job: Job) -> bool:
    if ctx.untrusted_checkouts(job):
        return True
    if any("secrets." in s for s in strings_in(job.raw)):
        return True
    perms = [job.permissions, ctx.wf.permissions]
    for p in perms:
        if isinstance(p, str) and p.strip().lower() == "write-all":
            return True
        if isinstance(p, dict) and any(str(v).lower() == "write" for v in p.values()):
            return True
    return False


@register(AG010)
def check_if_guards(ctx: AnalysisContext) -> Iterator[Finding]:
    # (a) `if:` strings that are always truthy
    for job in ctx.wf.jobs:
        owners = [(job.raw, job, None)] + [(s.raw, job, s) for s in job.steps]
        for raw, j, step in owners:
            cond = raw.get("if")
            if not isinstance(cond, str):
                continue
            text = cond.strip()
            spans = find_expressions(text)
            if spans and not (
                len(spans) == 1 and spans[0].start == 0 and spans[0].end == len(text)
            ):
                yield ctx.finding(
                    "AG010",
                    Severity.HIGH,
                    f"`if: {text}` mixes literal text with a `${{{{ }}}}` expression; it evaluates to "
                    "a non-empty string, which is always true, so this guard never blocks",
                    raw.value_line("if"),
                    job=j,
                    step=step,
                )

    # (b) comment-text gates without an authorization check
    comment_triggers = sorted(set(ctx.wf.triggers) & COMMENT_TRIGGERS)
    if not comment_triggers:
        return
    trig = ", ".join(f"`{t}`" for t in comment_triggers)
    for job in ctx.wf.jobs:
        gates = [(job.raw, job.if_)] + [(s.raw, s.if_) for s in job.steps]
        gate = next(((raw, c) for raw, c in gates if _has_prefix(_refs(c), _GATE_PATHS)), None)
        if gate is None or _authorized(ctx, job):
            continue
        raw, cond = gate
        severity = Severity.HIGH if _job_is_privileged(ctx, job) else Severity.MEDIUM
        yield ctx.finding(
            "AG010",
            severity,
            f"Job `{job.id}` ({trig}) is gated only on the comment text (`{str(cond).strip()}`); any "
            "user who can comment can trigger it. Also check the commenter's author_association "
            "or repository permission",
            raw.value_line("if"),
            job=job,
        )
