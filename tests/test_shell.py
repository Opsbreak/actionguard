from __future__ import annotations

from actionguard.shell import (
    fetches_pr_code,
    iter_file_writes,
    iter_set_output,
    shell_var_refs,
)


def test_shell_var_refs_across_shells():
    assert shell_var_refs('echo "$A ${B} ${C:-x} $env:D %E% ${{ env.F }}"') == [
        "B",
        "C",
        "A",
        "D",
        "E",
    ]
    assert shell_var_refs("console.log(process.env.G, process.env['H'])") == ["G", "H"]


def test_iter_file_writes_variants():
    script = "\n".join(
        [
            'echo "a=1" >> "$GITHUB_OUTPUT"',
            "echo b=2 >> ${GITHUB_OUTPUT}",
            "printf 'c=%s\\n' \"$X\" >> $GITHUB_OUTPUT",
            'echo "d<<EOF" >> $GITHUB_OUTPUT',
            'echo "$BODY" >> $GITHUB_OUTPUT',
            'echo "EOF" >> $GITHUB_OUTPUT',
            "cat $GITHUB_OUTPUT",
            '"e=5" | Out-File -FilePath $env:GITHUB_OUTPUT -Append',
        ]
    )
    writes = iter_file_writes(script, "GITHUB_OUTPUT")
    assert [(w.line_index, w.name) for w in writes] == [
        (0, "a"),
        (1, "b"),
        (2, "c"),
        (3, "d"),
        (4, "d"),
        (7, "e"),
    ]


def test_iter_file_writes_heredoc_block():
    script = "cat >> \"$GITHUB_ENV\" <<'EOF'\nA=1\nB=$X\nEOF\necho done"
    writes = iter_file_writes(script, "GITHUB_ENV")
    assert [(w.line_index, w.name) for w in writes] == [(1, "A"), (2, "B")]


def test_legacy_set_output():
    writes = iter_set_output('echo "::set-output name=title::${{ github.event.issue.title }}"')
    assert writes[0].name == "title"


def test_fetches_pr_code():
    assert fetches_pr_code("gh pr checkout 12")
    assert fetches_pr_code("git fetch origin pull/12/head:pr")
    assert fetches_pr_code("git fetch origin refs/pull/12/merge && git checkout FETCH_HEAD")
    assert not fetches_pr_code("git fetch --tags")
    assert not fetches_pr_code("echo pull request")
