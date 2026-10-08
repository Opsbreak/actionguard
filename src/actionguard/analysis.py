"""Per-file analysis context shared by all rules."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from actionguard.contexts import ContextCatalog, is_checkout_ref_source
from actionguard.expressions import find_expressions
from actionguard.knowledge import BUILD_ACTIONS, PRIVILEGED_UNTRUSTED_TRIGGERS
from actionguard.models import Finding, Location, Related, Severity
from actionguard.shell import fetches_pr_code, git_ref_command
from actionguard.taint import Taint, TaintEngine
from actionguard.workflow import Job, Step, Workflow
from actionguard.yamlloader import YStr

if TYPE_CHECKING:
    from actionguard.config import Config

__all__ = ["AnalysisContext", "UntrustedCheckout"]


@dataclass(frozen=True)
class UntrustedCheckout:
    step: Step
    line: int
    reason: str


_SAME_REPO_GUARD_RE = re.compile(
    r"head(?:\.repo|_repository)\.full_name\s*==\s*github\.repository"
    r"|github\.repository\s*==\s*[\w.]*head(?:\.repo|_repository)\.full_name"
    r"|head\.repo\.fork\s*==\s*false|!\s*github\.event\.pull_request\.head\.repo\.fork"
    r"|head_repository\.fork\s*==\s*false",
    re.IGNORECASE,
)
_LABEL_GUARD_RE = re.compile(
    r"labels\.\*\.name|github\.event\.label\.name|\.labels\b", re.IGNORECASE
)


class AnalysisContext:
    def __init__(self, workflow: Workflow, config: Config | None = None) -> None:
        from actionguard.config import Config

        self.wf = workflow
        self.config = config or Config()

    # -- shared facts ---------------------------------------------------------------------

    @cached_property
    def catalog(self) -> ContextCatalog:
        return ContextCatalog(self.config.untrusted_contexts)

    @cached_property
    def taint(self) -> TaintEngine:
        return TaintEngine(self.wf, self.catalog)

    @cached_property
    def privileged(self) -> bool:
        """Triggered by an event that runs with secrets on attacker-supplied content."""
        return bool(set(self.wf.triggers) & PRIVILEGED_UNTRUSTED_TRIGGERS)

    def is_trusted_action(self, name: str) -> bool:
        return self.config.is_trusted_action(name)

    @cached_property
    def _checkouts(self) -> dict[str, list[UntrustedCheckout]]:
        return {job.id: list(self._find_untrusted_checkouts(job)) for job in self.wf.jobs}

    def untrusted_checkouts(self, job: Job) -> list[UntrustedCheckout]:
        return self._checkouts.get(job.id, [])

    def _ref_taints(self, step: Step, text: str) -> list[Taint]:
        scope = self.taint.scope_for(step)
        return [t for t in scope.script_taints(text) if is_checkout_ref_source(t.source)]

    def _find_untrusted_checkouts(self, job: Job) -> Iterable[UntrustedCheckout]:
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                with_ = step.with_
                for key in ("ref", "repository"):
                    value = with_.get(key)
                    if not isinstance(value, str):
                        continue
                    taints = self._ref_taints(step, value)
                    literal_pr = "refs/pull/" in value or value.startswith("pull/")
                    if taints or literal_pr:
                        line = with_.value_line(key)
                        why = taints[0].describe() if taints else f"`{value.strip()}`"
                        yield UntrustedCheckout(
                            step, line, f"actions/checkout `{key}:` resolves to {why}"
                        )
                        break
            run = step.run
            if run is not None:
                for idx, text in enumerate(run.split("\n")):
                    if fetches_pr_code(text) or (
                        git_ref_command(text) and self._ref_taints(step, text)
                    ):
                        yield UntrustedCheckout(
                            step, run.line_of(idx), f"`{text.strip()}` fetches pull request code"
                        )
                        break

    @staticmethod
    def executes_code(step: Step) -> bool:
        """Does this step (likely) execute code that lives in the workspace?"""
        if step.run is not None:
            return True
        ref = step.action
        if ref is None:
            return False
        if ref.kind == "local":
            return True
        if ref.kind != "repo":
            return False
        if step.uses_action("ruby/setup-ruby"):
            return str(step.with_.get("bundler-cache", "")).lower() == "true"
        if step.uses_action("pnpm/action-setup"):
            return bool(step.with_.get("run_install"))
        return any(step.uses_action(name) for name in BUILD_ACTIONS)

    @staticmethod
    def condition_text(*conds: object) -> str:
        return " ".join(str(c) for c in conds if c is not None)

    def same_repo_guarded(self, job: Job, step: Step | None = None) -> bool:
        text = self.condition_text(job.if_, step.if_ if step else None)
        return bool(_SAME_REPO_GUARD_RE.search(text))

    def label_guarded(self, job: Job, step: Step | None = None) -> bool:
        text = self.condition_text(job.if_, step.if_ if step else None)
        return bool(_LABEL_GUARD_RE.search(text))

    # -- finding construction -------------------------------------------------------------

    def finding(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        line: int,
        column: int = 1,
        *,
        end_column: int | None = None,
        job: Job | None = None,
        step: Step | None = None,
        related: Iterable[tuple[int, str]] = (),
    ) -> Finding:
        path = self.wf.path
        snippet = self.wf.line_text(line)
        if column <= 1 and snippet.strip():
            column = len(snippet) - len(snippet.lstrip()) + 1
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            location=Location(path, line, column, end_column),
            related=[Related(Location(path, ln, 1), msg) for ln, msg in related],
            job=job.id if job else None,
            step=step.label if step else None,
            snippet=snippet,
        )

    def expression_location(self, value: YStr, start: int, text: str) -> tuple[int, int, int]:
        """(line, column, end_column) of an expression found at ``start`` within ``value``."""
        line, col = value.locate(start, text)
        return line, col, col + len(text)

    @staticmethod
    def expressions_in(value: str) -> bool:
        return bool(find_expressions(value))
