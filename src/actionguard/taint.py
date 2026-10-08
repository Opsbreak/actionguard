"""Taint tracking across a workflow.

Untrusted data enters through GitHub contexts (see :mod:`actionguard.contexts`) and is
propagated through:

* ``env:`` blocks at workflow, job and step level (``${{ env.X }}``),
* ``$GITHUB_ENV`` writes in earlier steps (dynamic environment),
* step outputs written to ``$GITHUB_OUTPUT`` / ``::set-output`` / ``core.setOutput``
  (``${{ steps.<id>.outputs.<name> }}``),
* job ``outputs:`` (``${{ needs.<job>.outputs.<name> }}``),
* ``strategy.matrix`` values (``${{ matrix.<key> }}``),
* outputs of actions known to emit attacker-controlled values.

A reference to a tainted env var *through the shell* (``"$TITLE"``) is data, not code,
and is not considered an injection sink by AG001 -- that is the recommended fix. It does
however still carry taint into ``$GITHUB_ENV``/``$GITHUB_OUTPUT`` writes.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field, replace

from actionguard.contexts import ContextCatalog
from actionguard.expressions import (
    ExpressionSpan,
    Ref,
    fallback_refs,
    find_expressions,
    safe_parse,
    value_refs,
)
from actionguard.knowledge import REF_OUTPUT_ACTIONS, TAINTED_OUTPUT_ACTIONS
from actionguard.shell import iter_file_writes, iter_set_output, shell_var_refs
from actionguard.workflow import Job, Step, Workflow
from actionguard.yamlloader import YList, YMap, YStr

__all__ = ["LEVELS", "Binding", "Scope", "Taint", "TaintEngine"]

LEVELS = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Taint:
    source: str  # the untrusted context as written, e.g. github.event.issue.title
    level: str  # high | medium | low
    injectable: bool
    via: tuple[str, ...] = ()

    def hop(self, label: str) -> Taint:
        if label in self.via:
            return self
        return replace(self, via=(*self.via, label))

    def describe(self) -> str:
        if not self.via:
            return f"`{self.source}`"
        return f"`{self.source}` (via {' -> '.join(self.via)})"


def _dedupe(taints: list[Taint]) -> list[Taint]:
    seen: set[tuple[str, tuple[str, ...], bool]] = set()
    out = []
    for t in taints:
        key = (t.source, t.via, t.injectable)
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


@dataclass
class Binding:
    """A named value (env var / output) together with the taint it carries."""

    name: str
    taints: list[Taint]
    line: int
    label: str  # how to describe a hop through this binding

    def resolved(self) -> list[Taint]:
        return [t.hop(self.label) for t in self.taints]


@dataclass
class Scope:
    engine: TaintEngine
    env: dict[str, Binding] = field(default_factory=dict)
    steps: dict[str, dict[str, Binding]] = field(default_factory=dict)
    needs: dict[str, dict[str, Binding]] = field(default_factory=dict)
    matrix: dict[str, list[Taint]] = field(default_factory=dict)

    def child(self, **changes: object) -> Scope:
        new = Scope(
            self.engine, dict(self.env), dict(self.steps), dict(self.needs), dict(self.matrix)
        )
        for k, v in changes.items():
            setattr(new, k, v)
        return new

    # -- expressions ------------------------------------------------------------------

    def expr_taints(self, inner: str) -> list[Taint]:
        node = safe_parse(inner)
        refs = value_refs(node) if node is not None else fallback_refs(inner)
        out: list[Taint] = []
        for ref in refs:
            out.extend(self.resolve(ref))
        return _dedupe(out)

    def spans(self, value: str) -> list[tuple[ExpressionSpan, list[Taint]]]:
        return [(span, self.expr_taints(span.inner)) for span in find_expressions(value)]

    def string_taints(self, value: str) -> list[Taint]:
        out: list[Taint] = []
        for _, taints in self.spans(value):
            out.extend(taints)
        return _dedupe(out)

    def shell_taints(self, text: str, locals_: dict[str, Binding] | None = None) -> list[Taint]:
        out: list[Taint] = []
        for name in shell_var_refs(text):
            local = (locals_ or {}).get(name)
            if local is not None:
                out.extend(local.resolved())
                continue
            binding = self.env.get(name.lower())
            if binding is not None:
                out.extend(binding.resolved())
        return out

    def script_taints(self, text: str, locals_: dict[str, Binding] | None = None) -> list[Taint]:
        """Taint reaching a piece of script text through expressions *or* shell variables."""
        return _dedupe(self.string_taints(text) + self.shell_taints(text, locals_))

    def script_locals(self, script: str) -> list[dict[str, Binding]]:
        """Taint of shell-local variables *before* each line of ``script``.

        Tracks simple assignments (``X=...``, ``export X=...``, ``local X=...``, PowerShell
        ``$X = ...``) so that ``T=$(echo "$TITLE")`` followed by ``echo "t=$T" >> $GITHUB_OUTPUT``
        is understood. Control flow is ignored (assignments are assumed to execute).
        """
        states: list[dict[str, Binding]] = []
        current: dict[str, Binding] = {}
        for idx, line in enumerate(script.split("\n")):
            states.append(dict(current))
            m = _ASSIGN_RE.match(line) or _PS_ASSIGN_RE.match(line)
            if not m:
                continue
            name, rhs = m.group(1), m.group(2)
            taints = self.script_taints(rhs, current)
            if taints:
                where = script.line_of(idx) if isinstance(script, YStr) else idx + 1
                current[name] = Binding(name, taints, where, f"${name} (line {where})")
            else:
                current.pop(name, None)
        return states

    # -- reference resolution ---------------------------------------------------------

    def resolve(self, ref: Ref) -> list[Taint]:
        path = ref.path
        if not path:
            return []
        head = path[0]
        if head == "env":
            if len(path) >= 2 and path[1] != "*":
                binding = self.env.get(path[1])
                return binding.resolved() if binding else []
            return [t for b in self.env.values() for t in b.resolved()] if ref.serialized else []
        if head in ("steps", "needs"):
            table = self.steps if head == "steps" else self.needs
            if len(path) < 2:
                return self._all(table) if ref.serialized else []
            outputs = (
                table.get(path[1], {})
                if path[1] != "*"
                else {k: v for d in table.values() for k, v in d.items()}
            )
            if len(path) >= 4 and path[2] == "outputs" and path[3] != "*":
                return [t for b in _lookup(outputs, path[3]) for t in b.resolved()]
            if len(path) >= 3 and path[2] != "outputs":
                return []  # .outcome / .conclusion / .result
            return (
                [t for b in outputs.values() for t in b.resolved()]
                if (ref.serialized or (len(path) >= 4 and path[3] == "*"))
                else []
            )
        if head == "matrix":
            key = path[1] if len(path) > 1 else "*"
            taints = list(self.matrix.get("*", []))
            if key == "*":
                if ref.serialized or len(path) > 1:
                    taints += [t for v in self.matrix.values() for t in v]
            else:
                taints += self.matrix.get(key, [])
            label = "matrix." + key
            return [t.hop(label) for t in taints]
        if head == "inputs":
            return self.engine.input_taints(path[1] if len(path) > 1 else None, ref.serialized)
        if path[:3] == ("github", "event", "inputs"):
            return self.engine.input_taints(
                path[3] if len(path) > 3 else None, ref.serialized, dispatch_only=True
            )
        hits = self.engine.catalog.match(path, ref.serialized)
        if not hits:
            return []
        injectable = any(h.injectable for h in hits)
        level = max((h.level for h in hits), key=lambda lv: LEVELS[lv])
        return [Taint(ref.display or ref.dotted, level, injectable)]

    @staticmethod
    def _all(table: dict[str, dict[str, Binding]]) -> list[Taint]:
        return [t for outs in table.values() for b in outs.values() for t in b.resolved()]


def _lookup(outputs: dict[str, Binding], name: str) -> list[Binding]:
    exact = outputs.get(name)
    if exact is not None:
        return [exact]
    return [
        b
        for pattern, b in outputs.items()
        if any(c in pattern for c in "*?[") and fnmatch.fnmatch(name, pattern)
    ]


_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$"
)
_PS_ASSIGN_RE = re.compile(r"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_JS_PAYLOAD_RE = re.compile(r"context\.payload((?:\.[A-Za-z_][\w]*|\[\s*['\"][^'\"]+['\"]\s*\])+)")
_SET_OUTPUT_JS_RE = re.compile(r"core\.setOutput\(\s*['\"]([A-Za-z_][\w\-]*)['\"]\s*,(.*)")
_EXPORT_VAR_JS_RE = re.compile(r"core\.exportVariable\(\s*['\"]([A-Za-z_][\w\-]*)['\"]\s*,(.*)")
_RETURN_JS_RE = re.compile(r"\breturn\b(.*)")


class TaintEngine:
    """Computes the taint scope visible to every step of every job."""

    MAX_PASSES = 8

    def __init__(self, workflow: Workflow, catalog: ContextCatalog | None = None) -> None:
        self.wf = workflow
        self.catalog = catalog or ContextCatalog()
        self._input_specs = workflow.input_specs()
        self.step_scopes: dict[tuple[str, int], Scope] = {}
        self.job_scopes: dict[str, Scope] = {}
        self.job_outputs: dict[str, dict[str, Binding]] = {}
        self.dynamic_env_writes: dict[tuple[str, int], list[Binding]] = {}
        self._run()

    # -- inputs ---------------------------------------------------------------------------

    def input_taints(
        self, name: str | None, serialized: bool, dispatch_only: bool = False
    ) -> list[Taint]:
        wf = self.wf
        specs = self._input_specs
        names = (
            [name] if name and name != "*" else (list(specs) if (serialized or name == "*") else [])
        )
        out: list[Taint] = []
        for n in names:
            entries = specs.get(n)
            prefix = "github.event.inputs." if dispatch_only else "inputs."
            if entries is None:
                if wf.kind == "action" or (not dispatch_only and wf.has_trigger("workflow_call")):
                    out.append(Taint(prefix + n, "medium", True))
                elif wf.has_trigger("workflow_dispatch"):
                    out.append(Taint(prefix + n, "low", True))
                continue
            for source, typ in entries:
                if dispatch_only and source != "dispatch":
                    continue
                if typ in ("boolean", "number", "choice", "environment"):
                    continue
                level = "low" if source == "dispatch" else "medium"
                out.append(Taint(prefix + n, level, True))
        return _dedupe(out)

    # -- driver ---------------------------------------------------------------------------

    def _bind_map(self, mapping: YMap, scope: Scope, kind: str) -> dict[str, Binding]:
        out: dict[str, Binding] = {}
        for key, value in mapping.items():
            name = str(key)
            taints = scope.string_taints(value) if isinstance(value, str) else []
            line = mapping.key_line(name)
            out[name.lower()] = Binding(name, taints, line, f"{kind}.{name} (line {line})")
        return out

    def _run(self) -> None:
        base = Scope(self)
        self.workflow_env = self._bind_map(self.wf.env, base, "env")
        for _ in range(self.MAX_PASSES):
            before = self._snapshot()
            for job in self.wf.jobs:
                self._run_job(job)
            if self._snapshot() == before:
                break

    def _snapshot(self) -> dict[str, dict[str, tuple[tuple[str, tuple[str, ...]], ...]]]:
        return {
            j: {n: tuple((t.source, t.via) for t in b.taints) for n, b in outs.items()}
            for j, outs in self.job_outputs.items()
        }

    def _matrix_taints(self, job: Job, scope: Scope) -> dict[str, list[Taint]]:
        matrix = job.strategy.get("matrix")
        out: dict[str, list[Taint]] = {}
        if isinstance(matrix, str):
            taints = scope.string_taints(matrix)
            if taints:
                out["*"] = taints
            return out
        if not isinstance(matrix, YMap):
            return out

        def leaves(value: object) -> list[str]:
            if isinstance(value, str):
                return [value]
            if isinstance(value, dict):
                return [s for v in value.values() for s in leaves(v)]
            if isinstance(value, list):
                return [s for v in value for s in leaves(v)]
            return []

        for key, value in matrix.items():
            k = str(key).lower()
            if k in ("include", "exclude") and isinstance(value, YList):
                for item in value:
                    if isinstance(item, YMap):
                        for k2, v2 in item.items():
                            t = [x for s in leaves(v2) for x in scope.string_taints(s)]
                            if t:
                                out.setdefault(str(k2).lower(), []).extend(t)
                    elif isinstance(item, str):
                        t = scope.string_taints(item)
                        if t:
                            out.setdefault("*", []).extend(t)
                continue
            if isinstance(value, str) and "${{" in value:
                t = scope.string_taints(value)
            else:
                t = [x for s in leaves(value) for x in scope.string_taints(s)]
            if t:
                out.setdefault(k, []).extend(t)
        return out

    def _run_job(self, job: Job) -> None:
        scope = Scope(self, env=dict(self.workflow_env), needs=dict(self.job_outputs))
        scope.matrix = self._matrix_taints(job, scope)
        scope.env.update(self._bind_map(job.env, scope, "env"))
        self.job_scopes[job.id] = scope
        dynamic_env: dict[str, Binding] = {}
        step_outputs: dict[str, dict[str, Binding]] = {}
        for step in job.steps:
            outer = scope.child(env={**scope.env, **dynamic_env}, steps=dict(step_outputs))
            step_scope = outer.child()
            step_scope.env.update(self._bind_map(step.env, outer, "env"))
            self.step_scopes[(job.id, step.index)] = step_scope
            if step.id:
                outs = self._step_outputs(step, step_scope)
                if outs:
                    step_outputs[step.id.lower()] = outs
            writes = self._env_writes(step, step_scope)
            self.dynamic_env_writes[(job.id, step.index)] = writes
            for binding in writes:
                if binding.taints:
                    dynamic_env[binding.name.lower()] = binding
                else:
                    dynamic_env.pop(binding.name.lower(), None)
        final = scope.child(env={**scope.env, **dynamic_env}, steps=dict(step_outputs))
        job_out: dict[str, Binding] = {}
        for key, value in job.outputs.items():
            name = str(key)
            line = job.outputs.key_line(name)
            taints = final.string_taints(value) if isinstance(value, str) else []
            job_out[name.lower()] = Binding(
                name, taints, line, f"needs.{job.id}.outputs.{name} (line {line})"
            )
        self.job_outputs[job.id.lower()] = job_out

    # -- per-step propagation ----------------------------------------------------------

    def js_payload_taints(self, text: str) -> list[Taint]:
        """``context.payload.issue.title`` in github-script maps to ``github.event...``."""
        out: list[Taint] = []
        for m in _JS_PAYLOAD_RE.finditer(text):
            raw = m.group(1)
            segs = [s for s in re.split(r"\.|\[\s*['\"]|['\"]\s*\]", raw) if s]
            path = ("github", "event", *(s.lower() for s in segs))
            for hit in self.catalog.match(path):
                out.append(Taint("context.payload" + raw, hit.level, hit.injectable))
                break
        return out

    def _step_outputs(self, step: Step, scope: Scope) -> dict[str, Binding]:
        outs: dict[str, Binding] = {}
        sid = step.id or ""
        run = step.run
        if run is not None:
            locals_ = scope.script_locals(run)
            for w in iter_file_writes(run, "GITHUB_OUTPUT") + iter_set_output(run):
                if not w.name:
                    continue
                taints = scope.script_taints(w.data, locals_[w.line_index])
                if taints:
                    line = run.line_of(w.line_index)
                    prev = outs.get(w.name.lower())
                    merged = _dedupe((prev.taints if prev else []) + taints)
                    outs[w.name.lower()] = Binding(
                        w.name, merged, line, f"steps.{sid}.outputs.{w.name} (line {line})"
                    )
        action = step.action
        if action is not None and action.kind == "repo":
            if step.uses_action("actions/github-script"):
                script = step.with_.get("script")
                if isinstance(script, YStr):
                    for idx, line_text in enumerate(script.split("\n")):
                        taints = scope.script_taints(line_text) + self.js_payload_taints(line_text)
                        if not taints:
                            continue
                        line = script.line_of(idx)
                        m = _SET_OUTPUT_JS_RE.search(line_text)
                        name = (
                            m.group(1)
                            if m
                            else ("result" if _RETURN_JS_RE.search(line_text) else None)
                        )
                        if name:
                            outs[name.lower()] = Binding(
                                name, taints, line, f"steps.{sid}.outputs.{name} (line {line})"
                            )
            for table, injectable in ((TAINTED_OUTPUT_ACTIONS, True), (REF_OUTPUT_ACTIONS, False)):
                for known, patterns in table.items():
                    if not action.matches(known):
                        continue
                    for pattern in patterns:
                        outs.setdefault(
                            pattern.lower(),
                            Binding(
                                pattern,
                                [Taint(f"{known} output", "high", injectable)],
                                step.line,
                                f"steps.{sid}.outputs.{pattern} (line {step.line})",
                            ),
                        )
        return outs

    def _env_writes(self, step: Step, scope: Scope) -> list[Binding]:
        """Variables a step exports to later steps via ``$GITHUB_ENV``."""
        out: list[Binding] = []
        run = step.run
        if run is not None:
            locals_ = scope.script_locals(run)
            for w in iter_file_writes(run, "GITHUB_ENV") + iter_set_output(run, legacy_env=True):
                if not w.name:
                    continue
                line = run.line_of(w.line_index)
                out.append(
                    Binding(
                        w.name,
                        scope.script_taints(w.data, locals_[w.line_index]),
                        line,
                        f"env.{w.name} ($GITHUB_ENV, line {line})",
                    )
                )
        if step.uses_action("actions/github-script"):
            script = step.with_.get("script")
            if isinstance(script, YStr):
                for idx, text in enumerate(script.split("\n")):
                    m = _EXPORT_VAR_JS_RE.search(text)
                    if m:
                        line = script.line_of(idx)
                        taints = scope.script_taints(m.group(2)) + self.js_payload_taints(
                            m.group(2)
                        )
                        out.append(
                            Binding(
                                m.group(1),
                                taints,
                                line,
                                f"env.{m.group(1)} (exportVariable, line {line})",
                            )
                        )
        return out

    # -- public helpers --------------------------------------------------------------------

    def scope_for(self, step: Step) -> Scope:
        return self.step_scopes.get((step.job.id, step.index)) or Scope(self)
