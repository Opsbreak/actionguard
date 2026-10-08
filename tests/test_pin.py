"""`actionguard pin` with mocked network layers."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from actionguard.pin import (
    ChainResolver,
    GitHubApiResolver,
    GitLsRemoteResolver,
    Resolution,
    ResolveError,
    apply_pins,
    most_specific_tag,
    plan_pins,
    rewrite_line,
)

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_TAGOBJ = "c" * 40
SHA_MAIN = "d" * 40

LS_REMOTE = f"""\
{SHA_A}\trefs/heads/main
{SHA_B}\trefs/tags/v4
{SHA_B}\trefs/tags/v4.2
{SHA_B}\trefs/tags/v4.2.2
{SHA_A}\trefs/tags/v4.2.1
{SHA_TAGOBJ}\trefs/tags/v5.0.0
{SHA_MAIN}\trefs/tags/v5.0.0^{{}}
"""


class FakeResolver:
    def __init__(self, table: dict[tuple[str, str, str], Resolution | None]) -> None:
        self.table = table
        self.calls: list[tuple[str, str, str]] = []

    def resolve(self, owner: str, repo: str, ref: str) -> Resolution | None:
        self.calls.append((owner, repo, ref))
        return self.table.get((owner, repo, ref))


def test_ls_remote_resolver_parses_tags_heads_and_peels():
    calls: list[Sequence[str]] = []

    def runner(cmd: Sequence[str]) -> str:
        calls.append(cmd)
        return LS_REMOTE

    r = GitLsRemoteResolver(runner=runner)
    assert r.resolve("actions", "checkout", "v4") == Resolution(SHA_B, "v4.2.2")
    assert r.resolve("actions", "checkout", "main") == Resolution(SHA_A, "main")
    # annotated tag: the peeled commit wins over the tag object
    assert r.resolve("actions", "checkout", "v5.0.0") == Resolution(SHA_MAIN, "v5.0.0")
    assert r.resolve("actions", "checkout", "nope") is None
    assert len(calls) == 1  # cached per repository
    assert calls[0][-1] == "https://github.com/actions/checkout"


def test_most_specific_tag():
    tags = {"v4": SHA_B, "v4.2": SHA_B, "v4.2.2": SHA_B, "v4.10.0": SHA_A}
    assert most_specific_tag(SHA_B, "v4", tags) == "v4.2.2"
    assert most_specific_tag(SHA_A, "v4", tags) == "v4.10.0"
    assert most_specific_tag(SHA_B, "v40", tags) == "v40"


def test_api_resolver_statuses():
    seen = {}

    def opener(url: str, headers: dict[str, str]) -> tuple[int, str]:
        seen["url"], seen["headers"] = url, headers
        if url.endswith("/v1"):
            return 200, SHA_A + "\n"
        if url.endswith("/missing"):
            return 404, "{}"
        return 500, "boom"

    r = GitHubApiResolver(opener=opener, token="t0k")
    assert r.resolve("o", "r", "v1") == Resolution(SHA_A, "v1")
    assert seen["url"] == "https://api.github.com/repos/o/r/commits/v1"
    assert seen["headers"]["Authorization"] == "Bearer t0k"
    assert seen["headers"]["Accept"] == "application/vnd.github.sha"
    assert r.resolve("o", "r", "missing") is None
    with pytest.raises(ResolveError):
        r.resolve("o", "r", "explode")


def test_chain_resolver_falls_through_transport_errors():
    class Broken:
        def resolve(self, owner, repo, ref):
            raise ResolveError("offline")

    good = FakeResolver({("o", "r", "v1"): Resolution(SHA_A, "v1")})
    assert ChainResolver(Broken(), good).resolve("o", "r", "v1") == Resolution(SHA_A, "v1")
    with pytest.raises(ResolveError):
        ChainResolver(Broken()).resolve("o", "r", "v1")


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("      - uses: actions/checkout@v4", f"      - uses: actions/checkout@{SHA_B} # v4.2.2"),
        ("    uses: 'actions/checkout@v4'", f"    uses: 'actions/checkout@{SHA_B}' # v4.2.2"),
        ("  - uses: actions/checkout@v4 # v4", f"  - uses: actions/checkout@{SHA_B} # v4.2.2"),
        (
            "  - uses: actions/checkout@v4  # actionguard: ignore[AG003]",
            f"  - uses: actions/checkout@{SHA_B} # v4.2.2 # actionguard: ignore[AG003]",
        ),
    ],
)
def test_rewrite_line(line, expected):
    assert rewrite_line(line, "actions/checkout@v4", SHA_B, "v4.2.2") == expected


def test_rewrite_line_refuses_unrelated_line():
    assert rewrite_line("run: echo actions/checkout@v4", "actions/checkout@v4", SHA_B, "v4") is None


def test_plan_and_apply(tmp_path: Path):
    wf = tmp_path / "ci.yml"
    wf.write_text(
        "on: push\n"
        "jobs:\n"
        "  reuse:\n"
        "    uses: org/wf/.github/workflows/build.yml@v1\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: github/codeql-action/init@v3\n"
        f"      - uses: actions/setup-node@{SHA_A} # v4.0.0\n"
        "      - uses: ./local\n"
        "      - uses: docker://alpine:3\n"
        "      - uses: ghost/missing@v9\n",
        encoding="utf-8",
    )
    resolver = FakeResolver(
        {
            ("org", "wf", "v1"): Resolution(SHA_A, "v1.0.3"),
            ("actions", "checkout", "v4"): Resolution(SHA_B, "v4.2.2"),
            ("github", "codeql-action", "v3"): Resolution(SHA_MAIN, "v3.28.0"),
        }
    )
    edits = plan_pins([(wf, "ci.yml")], resolver)
    assert [(e.line, e.error is None) for e in edits] == [
        (4, True),
        (8, True),
        (9, True),
        (13, False),
    ]
    assert "not found" in (edits[-1].error or "")
    # dry run leaves the file alone
    assert "actions/checkout@v4\n" in wf.read_text(encoding="utf-8")
    changed = apply_pins(edits)
    assert changed == 3
    text = wf.read_text(encoding="utf-8")
    assert f"uses: org/wf/.github/workflows/build.yml@{SHA_A} # v1.0.3" in text
    assert f"- uses: actions/checkout@{SHA_B} # v4.2.2" in text
    assert f"- uses: github/codeql-action/init@{SHA_MAIN} # v3.28.0" in text
    assert "ghost/missing@v9" in text
    # second pass: nothing left except the unresolvable one
    again = plan_pins([(wf, "ci.yml")], resolver)
    assert [e.old for e in again] == ["ghost/missing@v9"]


def test_apply_preserves_crlf(tmp_path: Path):
    wf = tmp_path / "w.yml"
    wf.write_bytes(
        b"on: push\r\njobs:\r\n  a:\r\n    runs-on: x\r\n    steps:\r\n      - uses: a/b@v1\r\n"
    )
    resolver = FakeResolver({("a", "b", "v1"): Resolution(SHA_A, "v1")})
    apply_pins(plan_pins([(wf, "w.yml")], resolver))
    data = wf.read_bytes()
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")
    assert f"a/b@{SHA_A} # v1".encode() in data
