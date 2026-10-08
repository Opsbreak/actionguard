# Contributing to actionguard

Thanks for helping make CI/CD pipelines safer.

## Development setup

```console
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Before sending a pull request:

```console
ruff check .
ruff format --check .
pytest
actionguard scan .github/workflows --fail-on info
```

CI runs the same checks on Python 3.10-3.13.

## Adding or changing a rule

1. Rules live in `src/actionguard/rules/`. Each module defines a `Rule` (id, name, title,
   severity, description, remediation, references, tags) and a check function registered
   with `@register(...)`. Shared facts (taint, untrusted checkouts, trigger classes) come
   from `AnalysisContext` in `src/actionguard/analysis.py`.
2. Every rule needs **positive and negative tests**. False positives matter as much as
   false negatives: include the safe variant of the pattern you detect.
3. Point findings at the most precise line/column available (`YStr.locate`,
   `YStr.line_of`, `YMap.key_line`).
4. If the rule is triggered by the examples, update `examples/` and regenerate
   `docs/rules.md` with `actionguard rules -f markdown > docs/rules.md`.

New untrusted contexts belong in `src/actionguard/contexts.py`; knowledge about specific
third-party actions belongs in `src/actionguard/knowledge.py`. Please include a link to the
relevant GitHub documentation or a public write-up.

## Pull requests

- Keep changes focused; describe the vulnerability class or bug being addressed.
- Pin any new action references in `.github/workflows/` to full commit SHAs
  (`actionguard pin --write` does this).
- Never commit real secrets or tokens, including in test fixtures.

Security issues in actionguard itself: see [SECURITY.md](SECURITY.md).
