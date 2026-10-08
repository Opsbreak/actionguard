"""Rule registry."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from actionguard.analysis import AnalysisContext
from actionguard.models import Finding, Rule, Severity
from actionguard.taint import LEVELS, Taint

__all__ = ["REGISTRY", "CheckFn", "RuleSpec", "all_rules", "get_rule", "register", "strings_in"]

CheckFn = Callable[[AnalysisContext], Iterable[Finding]]


@dataclass(frozen=True)
class RuleSpec:
    meta: Rule
    check: CheckFn | None

    @property
    def id(self) -> str:
        return self.meta.id


REGISTRY: dict[str, RuleSpec] = {}


def register(meta: Rule) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        if meta.id in REGISTRY:
            raise RuntimeError(f"duplicate rule id {meta.id}")
        REGISTRY[meta.id] = RuleSpec(meta, fn)
        return fn

    return deco


def register_meta(meta: Rule) -> None:
    REGISTRY[meta.id] = RuleSpec(meta, None)


def all_rules() -> list[RuleSpec]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def get_rule(rule_id: str) -> RuleSpec | None:
    return REGISTRY.get(rule_id.upper())


def worst_level(taints: Iterable[Taint]) -> str:
    return max((t.level for t in taints), key=lambda lv: LEVELS[lv], default="low")


def taint_severity(ctx: AnalysisContext, level: str) -> Severity:
    """Map a taint level to a finding severity, escalating under privileged triggers."""
    if level == "high":
        return Severity.CRITICAL if ctx.privileged else Severity.HIGH
    if level == "medium":
        return Severity.MEDIUM
    return Severity.LOW


def strings_in(value: object) -> Iterator[str]:
    """All string leaves of a YAML value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings_in(v)


def describe_taints(taints: list[Taint], limit: int = 2) -> str:
    shown = [t.describe() for t in taints[:limit]]
    more = len(taints) - limit
    text = ", ".join(shown)
    return f"{text} and {more} more" if more > 0 else text
