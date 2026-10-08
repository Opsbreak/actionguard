from __future__ import annotations

import pytest

from actionguard.contexts import ContextCatalog
from actionguard.expressions import (
    Binary,
    Call,
    ContextRef,
    ExpressionError,
    Index,
    Literal,
    Not,
    Property,
    context_refs,
    find_expressions,
    parse_expression,
    tokenize,
    value_refs,
)


def dotted(refs):
    return [r.dotted for r in refs]


def test_tokenize_operators_and_literals():
    kinds = [(t.kind, t.value) for t in tokenize("a.b == 'it''s' && !c || 1.5 >= -2")]
    assert ("STRING", "it's") in kinds
    assert ("OP", "==") in kinds
    assert ("OP", "&&") in kinds
    assert ("OP", "!") in kinds
    assert ("NUMBER", "1.5") in kinds
    assert ("NUMBER", "-2") in kinds
    assert kinds[-1][0] == "EOF"


def test_tokenize_rejects_garbage():
    with pytest.raises(ExpressionError):
        tokenize("a ; b")


def test_unterminated_string_is_an_error():
    with pytest.raises(ExpressionError):
        parse_expression("'abc")


def test_parse_property_chain():
    node = parse_expression("github.event.issue.title")
    assert node == Property(Property(Property(ContextRef("github"), "event"), "issue"), "title")


def test_parse_precedence_and_over_or():
    node = parse_expression("a || b && c")
    assert isinstance(node, Binary)
    assert node.op == "||"
    assert isinstance(node.right, Binary)
    assert node.right.op == "&&"


def test_parse_function_call_and_not():
    node = parse_expression("!contains(github.event.issue.labels.*.name, 'bug')")
    assert isinstance(node, Not)
    assert isinstance(node.operand, Call)
    assert node.operand.name == "contains"
    assert len(node.operand.args) == 2


def test_parse_literals():
    assert parse_expression("true") == Literal(True)
    assert parse_expression("null") == Literal(None)
    assert parse_expression("0xff") == Literal(255)
    assert parse_expression("'x'") == Literal("x")


def test_identifiers_may_contain_hyphens():
    refs = context_refs(parse_expression("steps.my-step.outputs.some-value"))
    assert dotted(refs) == ["steps.my-step.outputs.some-value"]


def test_bracket_access_is_normalised():
    refs = context_refs(parse_expression("github.event['pull_request']['title']"))
    assert dotted(refs) == ["github.event.pull_request.title"]


def test_numeric_index_becomes_wildcard():
    refs = context_refs(parse_expression("github.event.commits[0].message"))
    assert dotted(refs) == ["github.event.commits.*.message"]


def test_dynamic_index_refs_are_collected():
    refs = context_refs(parse_expression("github.event[inputs.field]"))
    assert "github.event.*" in dotted(refs)
    assert "inputs.field" in dotted(refs)


def test_case_insensitive_normalisation():
    refs = context_refs(parse_expression("GitHub.Event.Issue.Title"))
    assert dotted(refs) == ["github.event.issue.title"]


def test_parse_errors_are_reported():
    with pytest.raises(ExpressionError):
        parse_expression("github.event.")
    with pytest.raises(ExpressionError):
        parse_expression("format('{0}'")


def test_index_node_for_string_keys():
    node = parse_expression("matrix['os']")
    assert isinstance(node, Index)


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("github.event.issue.title", ["github.event.issue.title"]),
        ("format('{0} x', github.event.issue.title)", ["github.event.issue.title"]),
        ("join(github.event.commits.*.message, ' ')", ["github.event.commits.*.message"]),
        ("github.event.issue.title || 'default'", ["github.event.issue.title"]),
        ("fromJSON(steps.x.outputs.json).title", ["steps.x.outputs.json"]),
        ("case(a == 'b', github.head_ref, 'x')", ["github.head_ref"]),
        # boolean results cannot carry attacker text
        ("contains(github.event.issue.title, 'bug')", []),
        ("startsWith(github.head_ref, 'feature/')", []),
        ("github.event.issue.title == 'x'", []),
        ("!github.event.issue.title", []),
        ("hashFiles('**/package-lock.json')", []),
    ],
)
def test_value_refs_follow_data_flow(expr, expected):
    assert dotted(value_refs(parse_expression(expr))) == expected


def test_tojson_marks_reference_serialized():
    refs = value_refs(parse_expression("toJSON(github.event.issue)"))
    assert refs[0].serialized is True
    plain = value_refs(parse_expression("github.event.issue"))
    assert plain[0].serialized is False


def test_find_expressions_handles_braces_inside_strings():
    text = "echo ${{ format('}}{0}', github.head_ref) }} and ${{ env.X }}"
    spans = find_expressions(text)
    assert [s.inner.strip() for s in spans] == ["format('}}{0}', github.head_ref)", "env.X"]
    assert text[spans[0].start : spans[0].end].startswith("${{")


def test_find_expressions_ignores_unterminated():
    assert find_expressions("echo ${{ github.head_ref") == []


def test_catalog_wildcards_and_descendants():
    cat = ContextCatalog()
    assert cat.match(("github", "event", "commits", "*", "message"))
    assert cat.match(("github", "event", "pages", "3", "page_name"))
    assert cat.match(("github", "event", "pull_request", "head", "ref"))
    assert not cat.match(("github", "event", "pull_request", "base", "ref"))
    assert not cat.match(("github", "repository"))


def test_catalog_ancestor_only_when_serialized():
    cat = ContextCatalog()
    assert not cat.match(("github", "event", "issue"))
    assert cat.match(("github", "event", "issue"), serialized=True)


def test_catalog_extra_contexts():
    cat = ContextCatalog(["github.event.client_payload.cmd", "github.event.custom.*"])
    assert cat.match(("github", "event", "custom", "anything"))
