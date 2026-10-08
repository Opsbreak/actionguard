"""AG007 artifact poisoning in workflow_run workflows."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from actionguard.analysis import AnalysisContext
from actionguard.knowledge import CROSS_RUN_ARTIFACT_ACTIONS
from actionguard.models import Finding, Rule, Severity
from actionguard.rules.base import register
from actionguard.shell import iter_file_writes
from actionguard.workflow import Job, Step

AG007 = Rule(
    id="AG007",
    name="artifact-poisoning",
    title="Artifact poisoning: untrusted artifacts extracted into the workspace",
    severity=Severity.HIGH,
    description=(
        "A `workflow_run` workflow runs with secrets and a writable token after an unprivileged "
        "workflow (often `pull_request` from a fork) completes. Artifacts produced by that "
        "triggering run are attacker-controlled. Downloading them into the workspace root lets a "
        "malicious artifact overwrite files the privileged job later executes or trusts "
        "(`package.json`, `Makefile`, scripts, `.git/hooks`), and reading artifact contents into "
        "$GITHUB_ENV/$GITHUB_OUTPUT or `eval` turns data into code."
    ),
    remediation=(
        "Download artifacts into an isolated directory such as `${{ runner.temp }}/artifacts`, "
        "treat every file as untrusted data, validate its contents strictly (e.g. a PR number "
        "must match `^[0-9]+$`) and never execute or `source` it."
    ),
    references=(
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        "https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust",
    ),
    tags=("security", "supply-chain", "CWE-829", "CWE-345"),
)


@dataclass(frozen=True)
class _Download:
    step: Step
    line: int
    path: str | None
    root: bool
    how: str


_ROOTS = {
    ".",
    "./",
    "$github_workspace",
    "${github_workspace}",
    "${{ github.workspace }}",
    "${{github.workspace}}",
}


def _is_root(path: object) -> bool:
    if path is None:
        return True
    p = str(path).strip().strip("\"'").lower()
    if not p:
        return True
    return p in _ROOTS or p.rstrip("/") in _ROOTS


_GH_RUN_DOWNLOAD_RE = re.compile(r"\bgh\s+run\s+download\b(.*)")
_DIR_FLAG_RE = re.compile(r"(?:^|\s)(?:-D|--dir)(?:\s+|=)(\"[^\"]+\"|'[^']+'|\S+)")


def _downloads(job: Job) -> Iterator[_Download]:
    for step in job.steps:
        uses_line = step.raw.key_line("uses", step.line)
        if step.uses_action("actions/download-artifact"):
            w = step.with_
            if "run-id" in w or "github-token" in w:
                path = w.get("path")
                yield _Download(
                    step, uses_line, path, _is_root(path), "actions/download-artifact (cross-run)"
                )
        elif any(step.uses_action(a) for a in CROSS_RUN_ARTIFACT_ACTIONS):
            path = step.with_.get("path")
            yield _Download(
                step, uses_line, path, _is_root(path), str(step.action.name if step.action else "")
            )
        elif step.uses_action("actions/github-script"):
            script = str(step.with_.get("script", ""))
            if "downloadArtifact" in script:
                isolated = "RUNNER_TEMP" in script or "runner.temp" in script
                yield _Download(
                    step, uses_line, None, not isolated, "actions/github-script downloadArtifact"
                )
        run = step.run
        if run is not None:
            for idx, text in enumerate(run.split("\n")):
                m = _GH_RUN_DOWNLOAD_RE.search(text)
                if m:
                    d = _DIR_FLAG_RE.search(m.group(1))
                    path = d.group(1) if d else None
                    yield _Download(step, run.line_of(idx), path, _is_root(path), "gh run download")


# Commands that run code from the current directory.
_WORKSPACE_EXEC_RE = re.compile(
    r"(?:^|[\s;&|(])(?:npm|npx|yarn|pnpm|bun|make|cmake|python3?|pip3?|poetry|tox|nox|node|deno|"
    r"go\s+(?:run|build|test|generate)|cargo|gradle|\./gradlew|mvn|\./mvnw|ant|bundle|rake|ruby|"
    r"php|composer|dotnet|msbuild|docker\s+(?:build|compose)|bash\s+[^-\s]|sh\s+[^-\s]|"
    r"\./[\w.\-/]+|source\s|\.\s+\S|pre-commit|terraform|helm|ansible-playbook)"
)
_READS_FILE_RE = re.compile(r"\$\(\s*(?:<|cat|head|tail|jq|tr|sed|awk|unzip\s+-p)\b|\$\(<|`cat\s")
_EVAL_RE = re.compile(r"(?:^|[\s;&|])(?:eval|source)\s|(?:^|[\s;&|])\.\s+\S")


def _executes_workspace(step: Step) -> bool:
    if step.run is not None:
        return any(_WORKSPACE_EXEC_RE.search(line) for line in step.run.split("\n"))
    return AnalysisContext.executes_code(step)


def _unsafe_read(step: Step) -> int | None:
    run = step.run
    if run is None:
        return None
    for target in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
        for w in iter_file_writes(run, target):
            if _READS_FILE_RE.search(w.data):
                return run.line_of(w.line_index)
    for idx, text in enumerate(run.split("\n")):
        if _EVAL_RE.search(text):
            return run.line_of(idx)
    return None


@register(AG007)
def check_artifact_poisoning(ctx: AnalysisContext) -> Iterator[Finding]:
    if not ctx.wf.has_trigger("workflow_run"):
        return
    for job in ctx.wf.jobs:
        for d in _downloads(job):
            later = job.steps[d.step.index + 1 :]
            where = "the workspace root" if d.root else f"`{d.path}`"
            exec_step = next((s for s in later if _executes_workspace(s)), None) if d.root else None
            if exec_step is not None:
                key = "run" if exec_step.run is not None else "uses"
                exec_line = exec_step.raw.key_line(key, exec_step.line)
                yield ctx.finding(
                    "AG007",
                    Severity.HIGH,
                    f"Artifacts from the triggering workflow run ({d.how}) are extracted into "
                    f"{where} and workspace code is executed afterwards (line {exec_line}); "
                    "a malicious artifact can overwrite files that this privileged job runs",
                    d.line,
                    job=job,
                    step=d.step,
                    related=[
                        (d.line, "artifact downloaded here"),
                        (exec_line, "workspace code executed here"),
                    ],
                )
                continue
            for step in later:
                read_line = _unsafe_read(step)
                if read_line is not None:
                    yield ctx.finding(
                        "AG007",
                        Severity.MEDIUM,
                        f"Artifact contents from the triggering workflow run ({d.how}, extracted into "
                        f"{where}) are read into the environment/outputs or evaluated without "
                        f"validation at line {read_line}",
                        read_line,
                        job=job,
                        step=step,
                        related=[(d.line, "artifact downloaded here")],
                    )
                    break
