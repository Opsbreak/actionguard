"""Detection rules. Importing this package registers every rule."""

from __future__ import annotations

from actionguard.models import Rule, Severity
from actionguard.rules import (  # noqa: F401  (imported for registration side effects)
    artifacts,
    guards,
    injection,
    permissions,
    pinning,
    pwn,
    runners,
)
from actionguard.rules.base import REGISTRY, RuleSpec, all_rules, get_rule, register_meta

AG000 = Rule(
    id="AG000",
    name="parse-error",
    title="File could not be parsed",
    severity=Severity.HIGH,
    description=(
        "The file is not valid YAML (or not a valid workflow/action document), so it could not be "
        "analysed. GitHub will also refuse to run it. actionguard keeps scanning other files."
    ),
    remediation="Fix the syntax error at the reported position; `actionlint` gives detailed schema errors.",
    references=(
        "https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions",
    ),
    tags=("correctness",),
)
register_meta(AG000)

__all__ = ["AG000", "REGISTRY", "RuleSpec", "all_rules", "get_rule"]
