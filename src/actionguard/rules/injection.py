"""AG001 script injection and AG008 GITHUB_ENV / GITHUB_PATH injection."""

from __future__ import annotations

import re
from collections.abc import Iterator

from actionguard.analysis import AnalysisContext
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import describe_taints, register, taint_severity, worst_level
from actionguard.shell import iter_file_writes, iter_set_output
from actionguard.workflow import Step
from actionguard.yamlloader import YStr

AG001 = Rule(
    id="AG001",
    name="script-injection",
    title="Script injection via untrusted input in run/script",
    severity=Severity.CRITICAL,
    description=(
        "`${{ }}` expressions are expanded by the runner *before* the script is handed to the "
        "shell (or to Node.js for actions/github-script). When the expanded value is "
        "attacker-controlled -- an issue title, PR body, branch name, commit message -- the "
        "attacker can close the surrounding quotes and append their own commands, which then "
        "run with the job's GITHUB_TOKEN and secrets. actionguard follows untrusted data through "
        "env: blocks, $GITHUB_ENV, step outputs ($GITHUB_OUTPUT), job outputs (needs.*) and "
        "matrix values, and only reports expressions whose *value* can carry the data (a "
        "boolean `contains(...)` cannot). Referencing a tainted env var through the shell "
        '(`"$TITLE"`) is safe and is not reported.'
    ),
    remediation=(
        "Never interpolate untrusted values into code. Bind the expression to an environment "
        "variable and reference that variable from the shell, quoted: `env: TITLE: ${{ "
        'github.event.issue.title }}` then `echo "$TITLE"`. In actions/github-script, read '
        "`process.env.TITLE` or `context.payload` instead of using `${{ }}` in `script:`."
    ),
    references=(
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        "https://securitylab.github.com/resources/github-actions-untrusted-input/",
        "https://cwe.mitre.org/data/definitions/78.html",
    ),
    tags=("security", "injection", "CWE-78", "CWE-94"),
)

AG008 = Rule(
    id="AG008",
    name="github-env-injection",
    title="Untrusted data written to GITHUB_ENV / GITHUB_PATH",
    severity=Severity.CRITICAL,
    description=(
        "Lines written to the $GITHUB_ENV file become environment variables for every later "
        "step; lines written to $GITHUB_PATH are prepended to PATH. If the written data is "
        "attacker-controlled, a newline lets the attacker define arbitrary variables such as "
        "`BASH_ENV`, `LD_PRELOAD` or `NODE_OPTIONS=--require=...`, or put an attacker-chosen "
        "directory in front of PATH -- turning data into code execution in subsequent steps. "
        "Unlike AG001, this applies even when the value is passed through a shell variable."
    ),
    remediation=(
        "Do not export untrusted values through $GITHUB_ENV/$GITHUB_PATH. Keep them in step-local "
        "`env:` and pass them explicitly to the steps that need them, or validate them against a "
        "strict allow-list (e.g. `^[0-9]+$`) before writing."
    ),
    references=(
        "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-an-environment-variable",
        "https://securitylab.github.com/research/github-actions-untrusted-input/",
    ),
    tags=("security", "injection", "CWE-77", "CWE-454"),
)


def _sinks(step: Step) -> Iterator[tuple[YStr, str, str]]:
    if step.run is not None:
        yield step.run, "a `run:` script", "shell commands"
    if step.uses_action("actions/github-script"):
        script = step.with_.get("script")
        if isinstance(script, YStr):
            yield script, "an actions/github-script `script:`", "JavaScript"


@register(AG001)
def check_script_injection(ctx: AnalysisContext) -> Iterator[Finding]:
    for job in ctx.wf.jobs:
        for step in job.steps:
            scope = ctx.taint.scope_for(step)
            for value, sink, lang in _sinks(step):
                for span, taints in scope.spans(value):
                    injectable = [t for t in taints if t.injectable]
                    if not injectable:
                        continue
                    severity = taint_severity(ctx, worst_level(injectable))
                    line, col, end = ctx.expression_location(value, span.start, span.text)
                    yield ctx.finding(
                        "AG001",
                        severity,
                        f"`{span.text}` expands untrusted {describe_taints(injectable)} directly "
                        f"into {sink}; an attacker can inject arbitrary {lang}",
                        line,
                        col,
                        end_column=end,
                        job=job,
                        step=step,
                    )


_JS_EXPORT_RE = re.compile(r"core\.(exportVariable|addPath)\((.*)")


@register(AG008)
def check_env_injection(ctx: AnalysisContext) -> Iterator[Finding]:
    for job in ctx.wf.jobs:
        for step in job.steps:
            scope = ctx.taint.scope_for(step)
            run = step.run
            if run is not None:
                locals_ = scope.script_locals(run)
                for target in ("GITHUB_ENV", "GITHUB_PATH"):
                    writes = iter_file_writes(run, target)
                    if target == "GITHUB_ENV":
                        writes += iter_set_output(run, legacy_env=True)
                    for w in writes:
                        taints = [
                            t
                            for t in scope.script_taints(w.data, locals_[w.line_index])
                            if t.injectable
                        ]
                        if not taints:
                            continue
                        line = run.line_of(w.line_index)
                        what = f" as `{w.name}`" if w.name else ""
                        impact = (
                            "an attacker can inject extra variables (e.g. BASH_ENV, LD_PRELOAD, "
                            "NODE_OPTIONS) that execute code in later steps"
                            if target == "GITHUB_ENV"
                            else "an attacker can prepend a directory to PATH and hijack later commands"
                        )
                        yield ctx.finding(
                            "AG008",
                            taint_severity(ctx, worst_level(taints)),
                            f"Untrusted {describe_taints(taints)} is written to ${target}{what}; {impact}",
                            line,
                            job=job,
                            step=step,
                        )
            if step.uses_action("actions/github-script"):
                script = step.with_.get("script")
                if not isinstance(script, YStr):
                    continue
                for idx, text in enumerate(script.split("\n")):
                    m = _JS_EXPORT_RE.search(text)
                    if not m:
                        continue
                    taints = [
                        t
                        for t in scope.script_taints(m.group(2))
                        + ctx.taint.js_payload_taints(m.group(2))
                        if t.injectable
                    ]
                    if taints:
                        yield ctx.finding(
                            "AG008",
                            taint_severity(ctx, worst_level(taints)),
                            f"Untrusted {describe_taints(taints)} is passed to core.{m.group(1)}(); "
                            "this writes it to GITHUB_ENV/GITHUB_PATH for every later step",
                            script.line_of(idx),
                            job=job,
                            step=step,
                        )
