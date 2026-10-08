from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from actionguard.config import Config
from actionguard.engine import ScanOptions, analyze_text
from actionguard.models import Finding

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

Scanner = Callable[..., list[Finding]]


def run_scan(
    text: str,
    path: str = "workflow.yml",
    config: Config | None = None,
    select: tuple[str, ...] = (),
) -> list[Finding]:
    result = analyze_text(
        textwrap.dedent(text).lstrip("\n"),
        path,
        config=config,
        options=ScanOptions(select=list(select)),
    )
    return result.findings


@pytest.fixture
def scan() -> Scanner:
    return run_scan


def only(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]
