"""Typed views over parsed workflow / composite-action documents."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from actionguard.yamlloader import SourceText, YList, YMap, YStr

__all__ = ["ActionRef", "Job", "Step", "Workflow", "parse_uses"]

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSIONISH_RE = re.compile(r"^v?\d+(\.\d+){0,3}([-+.][0-9A-Za-z.\-]+)?$")


@dataclass(frozen=True)
class ActionRef:
    """A parsed ``uses:`` value."""

    raw: str
    kind: str  # "local" | "docker" | "repo"
    owner: str = ""
    repo: str = ""
    path: str = ""  # sub-path inside the repo (actions or reusable workflow file)
    ref: str = ""

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}".lower() if self.kind == "repo" else self.raw

    @property
    def name(self) -> str:
        """``owner/repo[/path]`` without the ref, lower-cased."""
        if self.kind != "repo":
            return self.raw.lower()
        base = f"{self.owner}/{self.repo}"
        return (f"{base}/{self.path}" if self.path else base).lower()

    @property
    def is_sha_pinned(self) -> bool:
        return bool(SHA_RE.match(self.ref))

    @property
    def is_reusable_workflow(self) -> bool:
        return self.kind == "repo" and bool(
            re.search(r"\.github/workflows/[^/]+\.ya?ml$", self.path)
        )

    @property
    def looks_like_version_tag(self) -> bool:
        return bool(_VERSIONISH_RE.match(self.ref))

    @property
    def is_first_party(self) -> bool:
        return self.kind == "repo" and self.owner.lower() in ("actions", "github")

    def matches(self, name: str) -> bool:
        """True if this ref is ``name`` (``owner/repo`` or ``owner/repo/path``) or below it."""
        target = name.lower().rstrip("/")
        mine = self.name
        return mine == target or mine.startswith(target + "/")


def parse_uses(value: str) -> ActionRef:
    raw = value.strip()
    if raw.startswith(("./", "../")) or raw == ".":
        return ActionRef(raw, "local")
    if raw.lower().startswith("docker://"):
        return ActionRef(raw, "docker")
    target, _, ref = raw.partition("@")
    parts = [p for p in target.split("/") if p]
    owner = parts[0] if parts else ""
    repo = parts[1] if len(parts) > 1 else ""
    path = "/".join(parts[2:])
    return ActionRef(raw, "repo", owner, repo, path, ref.strip())


def _as_map(value: Any) -> YMap:
    return value if isinstance(value, YMap) else YMap()


@dataclass
class Step:
    index: int
    raw: YMap
    job: Job

    @property
    def id(self) -> str | None:
        v = self.raw.get("id")
        return str(v) if v is not None else None

    @property
    def name(self) -> str | None:
        v = self.raw.get("name")
        return str(v) if v is not None else None

    @property
    def uses(self) -> str | None:
        v = self.raw.get("uses")
        return v if isinstance(v, str) else None

    @property
    def action(self) -> ActionRef | None:
        return parse_uses(self.uses) if self.uses else None

    @property
    def run(self) -> YStr | None:
        v = self.raw.get("run")
        if isinstance(v, YStr):
            return v
        if isinstance(v, str):
            return YStr(v, self.line)
        return None

    @property
    def with_(self) -> YMap:
        return _as_map(self.raw.get("with"))

    @property
    def env(self) -> YMap:
        return _as_map(self.raw.get("env"))

    @property
    def if_(self) -> Any:
        return self.raw.get("if")

    @property
    def line(self) -> int:
        return self.raw.line

    @property
    def label(self) -> str:
        explicit = self.id or self.name or self.uses
        if explicit:
            return explicit
        run = self.run
        if run is not None and run.strip():
            first = run.strip().split("\n")[0].strip()
            return "run: " + (first[:40] + "..." if len(first) > 40 else first)
        return f"step {self.index + 1}"

    def uses_action(self, *names: str) -> bool:
        ref = self.action
        return ref is not None and ref.kind == "repo" and any(ref.matches(n) for n in names)


@dataclass
class Job:
    id: str
    raw: YMap
    workflow: Workflow
    steps: list[Step] = field(default_factory=list)

    @property
    def line(self) -> int:
        return self.workflow.raw_jobs.key_line(self.id, self.raw.line)

    @property
    def runs_on(self) -> Any:
        return self.raw.get("runs-on")

    @property
    def permissions(self) -> Any:
        return self.raw.get("permissions")

    @property
    def has_permissions(self) -> bool:
        return "permissions" in self.raw

    @property
    def env(self) -> YMap:
        return _as_map(self.raw.get("env"))

    @property
    def outputs(self) -> YMap:
        return _as_map(self.raw.get("outputs"))

    @property
    def uses(self) -> str | None:
        v = self.raw.get("uses")
        return v if isinstance(v, str) else None

    @property
    def secrets(self) -> Any:
        return self.raw.get("secrets")

    @property
    def if_(self) -> Any:
        return self.raw.get("if")

    @property
    def strategy(self) -> YMap:
        return _as_map(self.raw.get("strategy"))

    @property
    def needs(self) -> list[str]:
        v = self.raw.get("needs")
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
        return []


@dataclass
class Workflow:
    """A workflow file or a composite action (``kind == "action"``)."""

    path: str
    source: SourceText
    raw: YMap
    kind: str = "workflow"
    jobs: list[Job] = field(default_factory=list)

    @property
    def raw_jobs(self) -> YMap:
        return _as_map(self.raw.get("jobs"))

    @property
    def triggers(self) -> dict[str, Any]:
        """``on:`` normalised to ``{event_name: config}``."""
        on = self.raw.get("on")
        if on is None:
            on = self.raw.get(True)  # tolerate YAML 1.1 loaders
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {str(x): None for x in on}
        if isinstance(on, dict):
            return {str(k): v for k, v in on.items()}
        return {}

    @property
    def trigger_line(self) -> int:
        return self.raw.key_line("on", 1)

    def has_trigger(self, *names: str) -> bool:
        trig = self.triggers
        return any(n in trig for n in names)

    @property
    def permissions(self) -> Any:
        return self.raw.get("permissions")

    @property
    def has_permissions(self) -> bool:
        return "permissions" in self.raw

    @property
    def env(self) -> YMap:
        return _as_map(self.raw.get("env"))

    @property
    def is_reusable_only(self) -> bool:
        trig = self.triggers
        return bool(trig) and set(trig) <= {"workflow_call"}

    def input_specs(self) -> dict[str, list[tuple[str, str]]]:
        """``{input_name_lower: [(source, type), ...]}`` with source in dispatch/call/action."""
        specs: dict[str, list[tuple[str, str]]] = {}
        if self.kind == "action":
            for name in _as_map(self.raw.get("inputs")):
                specs.setdefault(str(name).lower(), []).append(("action", "string"))
            return specs
        for event, source in (("workflow_dispatch", "dispatch"), ("workflow_call", "call")):
            cfg = self.triggers.get(event)
            if not isinstance(cfg, dict):
                continue
            for name, spec in _as_map(cfg.get("inputs")).items():
                typ = "string"
                if isinstance(spec, dict) and isinstance(spec.get("type"), str):
                    typ = str(spec["type"]).lower()
                specs.setdefault(str(name).lower(), []).append((source, typ))
        return specs

    def job(self, job_id: str) -> Job | None:
        lowered = job_id.lower()
        for job in self.jobs:
            if job.id.lower() == lowered:
                return job
        return None

    def line_text(self, line: int) -> str:
        return self.source.line(line)


def build_workflow(path: str, source: SourceText, data: Any) -> Workflow | None:
    """Wrap parsed YAML. Returns ``None`` if the document is not a workflow or action."""
    if not isinstance(data, YMap):
        return None
    runs = data.get("runs")
    if isinstance(runs, YMap) and "jobs" not in data:
        wf = Workflow(path, source, data, kind="action")
        using = str(runs.get("using", "")).lower()
        if using == "composite":
            job = Job("(composite)", runs, wf)
            steps = runs.get("steps")
            if isinstance(steps, YList):
                job.steps = [Step(i, s, job) for i, s in enumerate(steps) if isinstance(s, YMap)]
            wf.jobs = [job]
        return wf
    if "jobs" not in data and "on" not in data:
        return None
    wf = Workflow(path, source, data, kind="workflow")
    for job_id, job_raw in wf.raw_jobs.items():
        if not isinstance(job_raw, YMap):
            continue
        job = Job(str(job_id), job_raw, wf)
        steps = job_raw.get("steps")
        if isinstance(steps, YList):
            job.steps = [Step(i, s, job) for i, s in enumerate(steps) if isinstance(s, YMap)]
        wf.jobs.append(job)
    return wf
