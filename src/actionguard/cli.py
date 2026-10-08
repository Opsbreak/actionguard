"""Command line interface: ``actionguard scan | pin | rules``."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from actionguard import __version__
from actionguard.config import Config, ConfigError
from actionguard.engine import ScanError, ScanOptions, discover, display_path, scan
from actionguard.models import Severity
from actionguard.output import FORMATS, render
from actionguard.pin import Resolver, apply_pins, make_resolver, plan_pins
from actionguard.rules import all_rules, get_rule

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITIES = [s.label for s in Severity]


def _split_ids(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        out.extend(x.strip().upper() for x in v.split(",") if x.strip())
    return out


def _use_color(mode: str, stream: TextIO) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _enable_windows_ansi() -> None:
    if os.name == "nt":  # pragma: no cover - platform specific
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def _load_config(args: argparse.Namespace) -> Config:
    if args.no_config:
        return Config(base_dir=Path.cwd().resolve())
    if args.config:
        return Config.load(Path(args.config))
    return Config.discover(Path.cwd())


# --------------------------------------------------------------------------- scan


def cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config(args)
    for rid in _split_ids(args.select) + _split_ids(args.ignore):
        if get_rule(rid) is None:
            raise ConfigError(f"unknown rule id: {rid}")
    min_sev = (
        Severity.parse(args.min_severity)
        if args.min_severity
        else (config.min_severity or Severity.INFO)
    )
    options = ScanOptions(
        select=_split_ids(args.select) or config.select,
        ignore=_split_ids(args.ignore),
        min_severity=min_sev,
    )
    result = scan(args.paths, config=config, options=options)
    if args.fail_on == "none":
        threshold: Severity | None = None
    elif args.fail_on:
        threshold = Severity.parse(args.fail_on)
    else:
        threshold = config.fail_on or Severity.LOW

    if args.output:
        text = render(result, args.format, color=False)
        Path(args.output).write_text(text, encoding="utf-8")
        counts = (
            ", ".join(f"{n} {s.label}" for s, n in result.counts().items() if n) or "no findings"
        )
        print(
            f"actionguard: wrote {args.format} report to {args.output} ({counts})", file=sys.stderr
        )
    else:
        color = args.format == "text" and _use_color(args.color, sys.stdout)
        if color:
            _enable_windows_ansi()
        sys.stdout.write(render(result, args.format, color=color))

    worst = result.max_severity()
    if threshold is not None and worst is not None and worst >= threshold:
        return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- pin


def cmd_pin(args: argparse.Namespace, resolver: Resolver | None = None) -> int:
    files = [(p, display_path(p)) for p, _ in discover(args.paths)]
    resolver = resolver or make_resolver(args.resolver)
    edits = plan_pins(files, resolver)
    if args.write:
        apply_pins(edits)
    ok = [e for e in edits if e.error is None]
    failed = [e for e in edits if e.error is not None]
    if args.format == "json":
        payload = {
            "write": bool(args.write),
            "edits": [
                {
                    "path": e.display,
                    "line": e.line,
                    "old": e.old,
                    "new": e.new or None,
                    "version": e.version or None,
                    "error": e.error,
                }
                for e in edits
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        for e in ok:
            print(f"{e.display}:{e.line}: {e.old} -> {e.new} # {e.version}")
        for e in failed:
            print(f"{e.display}:{e.line}: error: {e.error}", file=sys.stderr)
        if not edits:
            print("Nothing to pin: every action reference is already pinned to a commit SHA.")
        elif args.write:
            print(f"Pinned {len(ok)} reference(s) in {len({e.path for e in ok})} file(s).")
        elif ok:
            print(f"{len(ok)} reference(s) can be pinned. Re-run with --write to apply.")
    return EXIT_FINDINGS if failed else EXIT_OK


# --------------------------------------------------------------------------- rules


def cmd_rules(args: argparse.Namespace) -> int:
    specs = all_rules()
    if args.rule_id:
        wanted = {r.upper() for r in args.rule_id}
        unknown = wanted - {s.id for s in specs}
        if unknown:
            raise ConfigError(f"unknown rule id(s): {', '.join(sorted(unknown))}")
        specs = [s for s in specs if s.id in wanted]
    if args.format == "json":
        data = [
            {
                "id": s.meta.id,
                "name": s.meta.name,
                "title": s.meta.title,
                "default_severity": s.meta.severity.label,
                "description": s.meta.description,
                "remediation": s.meta.remediation,
                "references": list(s.meta.references),
                "tags": list(s.meta.tags),
            }
            for s in specs
        ]
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return EXIT_OK
    if args.format == "markdown":
        lines = ["# actionguard rules", ""]
        lines += ["| ID | Name | Default severity | Title |", "|---|---|---|---|"]
        lines += [
            f"| [{s.id}](#{s.id.lower()}) | `{s.meta.name}` | {s.meta.severity.label} | {s.meta.title} |"
            for s in specs
        ]
        for s in specs:
            m = s.meta
            lines += [
                "",
                f'<a id="{m.id.lower()}"></a>',
                "",
                f"## {m.id}: {m.title}",
                "",
                f"**Name:** `{m.name}` | **Default severity:** {m.severity.label}",
                "",
                m.description,
                "",
                "**Remediation.** " + m.remediation,
            ]
            if m.references:
                lines += ["", "**References**", ""] + [f"- <{r}>" for r in m.references]
        sys.stdout.write("\n".join(lines) + "\n")
        return EXIT_OK
    verbose = bool(args.rule_id)
    if not verbose:
        width = max(len(s.meta.name) for s in specs)
        print(f"{'ID':<6} {'SEVERITY':<9} {'NAME':<{width}}  TITLE")
        for s in specs:
            print(f"{s.id:<6} {s.meta.severity.label:<9} {s.meta.name:<{width}}  {s.meta.title}")
        print("\nRun `actionguard rules <ID>` for full documentation.")
        return EXIT_OK
    for s in specs:
        m = s.meta
        print(f"{m.id} {m.name} ({m.severity.label})")
        print(m.title)
        print()
        print(textwrap.fill(m.description, 88))
        print()
        print(textwrap.fill("Remediation: " + m.remediation, 88))
        if m.references:
            print("\nReferences:")
            for r in m.references:
                print(f"  - {r}")
        print()
    return EXIT_OK


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actionguard",
        description="Static security analyzer for GitHub Actions workflows.",
        epilog="Exit codes: 0 = clean (below --fail-on), 1 = findings at/above --fail-on "
        "(or pin failures), 2 = usage or configuration error.",
    )
    parser.add_argument("--version", action="version", version=f"actionguard {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser("scan", help="scan workflows and composite actions for vulnerabilities")
    p_scan.add_argument(
        "paths",
        nargs="*",
        help="workflow/action files, directories or repository roots (default: .github/workflows)",
    )
    p_scan.add_argument(
        "-f", "--format", choices=FORMATS, default="text", help="output format (default: text)"
    )
    p_scan.add_argument(
        "-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout"
    )
    p_scan.add_argument(
        "--fail-on",
        choices=[*_SEVERITIES, "none"],
        help="exit 1 if any finding is at or above this severity (default: low)",
    )
    p_scan.add_argument(
        "--min-severity", choices=_SEVERITIES, help="hide findings below this severity"
    )
    p_scan.add_argument(
        "--select", action="append", metavar="IDS", help="only run these rules (comma-separated)"
    )
    p_scan.add_argument(
        "--ignore", action="append", metavar="IDS", help="skip these rules (comma-separated)"
    )
    p_scan.add_argument(
        "--config", metavar="FILE", help="configuration file (default: ./.actionguard.yml)"
    )
    p_scan.add_argument("--no-config", action="store_true", help="ignore configuration files")
    p_scan.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colorize text output"
    )
    p_scan.set_defaults(func=cmd_scan)

    p_pin = sub.add_parser("pin", help="pin action references to full commit SHAs")
    p_pin.add_argument("paths", nargs="*", help="files or directories (default: .github/workflows)")
    p_pin.add_argument(
        "--write", action="store_true", help="rewrite files in place (default: dry run)"
    )
    p_pin.add_argument(
        "--resolver",
        choices=("auto", "git", "api"),
        default="auto",
        help="how to resolve refs: git ls-remote, GitHub REST API, or git with API fallback",
    )
    p_pin.add_argument("-f", "--format", choices=("text", "json"), default="text")
    p_pin.set_defaults(func=cmd_pin)

    p_rules = sub.add_parser("rules", help="list rules and show their documentation")
    p_rules.add_argument("rule_id", nargs="*", help="show full documentation for these rules")
    p_rules.add_argument("-f", "--format", choices=("text", "json", "markdown"), default="text")
    p_rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return EXIT_ERROR
    try:
        return int(args.func(args))
    except (ScanError, ConfigError, ValueError) as exc:
        print(f"actionguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
