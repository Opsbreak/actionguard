# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-08

Initial release.

### Added

- `actionguard scan` for workflows, reusable workflows (`on: workflow_call`) and composite
  actions, with repository-root, directory and file discovery.
- Position-preserving YAML loader (exact line/column, including inside block scalars);
  `on:` is not coerced to a boolean.
- Parser for the `${{ }}` expression language with normalised context references
  (bracket access, wildcards, case-insensitivity) and value-flow analysis.
- Taint tracking through `env:` scopes, `$GITHUB_ENV`, step outputs, shell assignments, job
  outputs (`needs.*`) and matrix values.
- Rules AG000-AG010: parse errors, script injection, pwn requests, unpinned
  actions/images/reusable workflows, excessive permissions, self-hosted runners on PR
  triggers, secrets exposure, artifact poisoning, `GITHUB_ENV`/`GITHUB_PATH` injection,
  persisted checkout credentials, bypassable `if:` guards.
- Output formats: text (colour, grouped, source excerpts with carets), JSON, SARIF 2.1.0
  (rule metadata, related locations, stable fingerprints) and Markdown.
- `--fail-on`, `--min-severity`, `--select`, `--ignore`; `.actionguard.yml` configuration;
  inline `# actionguard: ignore[...]` suppressions.
- `actionguard pin` to rewrite `uses:` references to full commit SHAs with precise
  version comments, via `git ls-remote` or the GitHub REST API.
- `actionguard rules` with text, JSON and Markdown output.
- Vulnerable and hardened example repositories.

[0.1.0]: https://github.com/Opsbreak/actionguard/releases/tag/v0.1.0
