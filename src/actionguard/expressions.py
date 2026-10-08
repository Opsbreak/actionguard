"""Parser for the GitHub Actions expression language (``${{ ... }}``).

The grammar implemented here follows the documented language:

    expr     := or
    or       := and ( '||' and )*
    and      := eq ( '&&' eq )*
    eq       := cmp ( ('==' | '!=') cmp )*
    cmp      := unary ( ('<' | '<=' | '>' | '>=') unary )*
    unary    := '!' unary | postfix
    postfix  := primary ( '.' IDENT | '.' '*' | '[' expr ']' )*
    primary  := literal | IDENT '(' args ')' | IDENT | '(' expr ')'

On top of the AST we implement two analyses used by the rules:

* :func:`context_refs` -- every context reference in an expression, normalised to a dotted
  path (``github.event['pull_request']['title']`` -> ``github.event.pull_request.title``,
  ``commits[0].message`` -> ``commits.*.message``).
* :func:`value_refs` -- only the references whose *data* can flow into the expression's
  result. ``contains(github.event.issue.title, 'x')`` evaluates to a boolean, so it cannot
  inject anything; ``format('{0}', github.event.issue.title)`` can.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

__all__ = [
    "Binary",
    "Call",
    "ContextRef",
    "ExpressionError",
    "ExpressionSpan",
    "Index",
    "Literal",
    "Not",
    "Property",
    "Ref",
    "Token",
    "context_refs",
    "find_expressions",
    "parse_expression",
    "tokenize",
    "value_refs",
]


class ExpressionError(ValueError):
    pass


# --------------------------------------------------------------------------- tokens


@dataclass(frozen=True)
class Token:
    kind: str  # NUMBER STRING IDENT OP EOF
    value: str
    pos: int


_OPERATORS = ("==", "!=", "<=", ">=", "&&", "||", "<", ">", "!", ".", "[", "]", "(", ")", ",", "*")
_NUMBER_RE = re.compile(r"-?(?:0x[0-9a-fA-F]+|0o[0-7]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "'":
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise ExpressionError(f"unterminated string literal at offset {i}")
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(text[j])
                j += 1
            tokens.append(Token("STRING", "".join(buf), i))
            i = j + 1
            continue
        if ch.isdigit() or (
            ch == "-" and i + 1 < n and (text[i + 1].isdigit() or text[i + 1] == ".")
        ):
            m = _NUMBER_RE.match(text, i)
            if m:
                tokens.append(Token("NUMBER", m.group(0), i))
                i = m.end()
                continue
        if ch.isalpha() or ch == "_":
            m = _IDENT_RE.match(text, i)
            assert m is not None
            tokens.append(Token("IDENT", m.group(0), i))
            i = m.end()
            continue
        for op in _OPERATORS:
            if text.startswith(op, i):
                tokens.append(Token("OP", op, i))
                i += len(op)
                break
        else:
            raise ExpressionError(f"unexpected character {ch!r} at offset {i}")
    tokens.append(Token("EOF", "", n))
    return tokens


# --------------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Literal:
    value: object


@dataclass(frozen=True)
class ContextRef:
    name: str


@dataclass(frozen=True)
class Property:
    obj: Node
    name: str | None  # None means the ``.*`` object filter


@dataclass(frozen=True)
class Index:
    obj: Node
    index: Node


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Not:
    operand: Node


@dataclass(frozen=True)
class Binary:
    op: str
    left: Node
    right: Node


Node = Literal | ContextRef | Property | Index | Call | Not | Binary


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = tokenize(text)
        self.i = 0

    @property
    def tok(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def accept(self, value: str) -> bool:
        if self.tok.kind == "OP" and self.tok.value == value:
            self.i += 1
            return True
        return False

    def expect(self, value: str) -> None:
        if not self.accept(value):
            raise ExpressionError(
                f"expected {value!r} at offset {self.tok.pos}, found {self.tok.value or 'end'!r}"
            )

    def parse(self) -> Node:
        node = self.parse_or()
        if self.tok.kind != "EOF":
            raise ExpressionError(f"unexpected {self.tok.value!r} at offset {self.tok.pos}")
        return node

    def _binary(self, ops: tuple[str, ...], sub: str) -> Node:
        parse_sub = getattr(self, sub)
        node: Node = parse_sub()
        while self.tok.kind == "OP" and self.tok.value in ops:
            op = self.advance().value
            node = Binary(op, node, parse_sub())
        return node

    def parse_or(self) -> Node:
        return self._binary(("||",), "parse_and")

    def parse_and(self) -> Node:
        return self._binary(("&&",), "parse_eq")

    def parse_eq(self) -> Node:
        return self._binary(("==", "!="), "parse_cmp")

    def parse_cmp(self) -> Node:
        return self._binary(("<", "<=", ">", ">="), "parse_unary")

    def parse_unary(self) -> Node:
        if self.accept("!"):
            return Not(self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self) -> Node:
        node = self.parse_primary()
        while True:
            if self.accept("."):
                if self.accept("*"):
                    node = Property(node, None)
                elif self.tok.kind == "IDENT":
                    node = Property(node, self.advance().value)
                else:
                    raise ExpressionError(f"expected property name at offset {self.tok.pos}")
            elif self.accept("["):
                node = Property(node, None) if self.accept("*") else Index(node, self.parse_or())
                self.expect("]")
            else:
                return node

    def parse_primary(self) -> Node:
        tok = self.tok
        if tok.kind == "NUMBER":
            self.advance()
            return Literal(_parse_number(tok.value))
        if tok.kind == "STRING":
            self.advance()
            return Literal(tok.value)
        if tok.kind == "IDENT":
            self.advance()
            lowered = tok.value.lower()
            if self.accept("("):
                args: list[Node] = []
                if not self.accept(")"):
                    args.append(self.parse_or())
                    while self.accept(","):
                        args.append(self.parse_or())
                    self.expect(")")
                return Call(tok.value, tuple(args))
            if lowered in ("true", "false"):
                return Literal(lowered == "true")
            if lowered == "null":
                return Literal(None)
            if lowered in ("nan", "infinity"):
                return Literal(float(lowered.replace("infinity", "inf")))
            return ContextRef(tok.value)
        if self.accept("("):
            node = self.parse_or()
            self.expect(")")
            return node
        raise ExpressionError(
            f"unexpected {tok.value or 'end of expression'!r} at offset {tok.pos}"
        )


def _parse_number(text: str) -> float | int:
    try:
        return int(text, 0)
    except ValueError:
        return float(text)


def parse_expression(text: str) -> Node:
    """Parse the *inside* of a ``${{ }}`` block into an AST."""
    return _Parser(text).parse()


# --------------------------------------------------------------------------- spans


@dataclass(frozen=True)
class ExpressionSpan:
    """A ``${{ ... }}`` occurrence inside a string."""

    start: int  # offset of '$'
    end: int  # offset just past the closing '}}'
    inner: str

    @property
    def text(self) -> str:
        return "${{" + self.inner + "}}"


def find_expressions(value: str) -> list[ExpressionSpan]:
    """Locate ``${{ }}`` blocks, honouring ``'...'`` literals that may contain ``}}``."""
    spans: list[ExpressionSpan] = []
    i = 0
    n = len(value)
    while True:
        start = value.find("${{", i)
        if start == -1:
            return spans
        j = start + 3
        in_string = False
        while j < n:
            ch = value[j]
            if in_string:
                if ch == "'":
                    if j + 1 < n and value[j + 1] == "'":
                        j += 2
                        continue
                    in_string = False
            elif ch == "'":
                in_string = True
            elif value.startswith("}}", j):
                spans.append(ExpressionSpan(start, j + 2, value[start + 3 : j]))
                break
            j += 1
        else:
            return spans  # unterminated: ignore the rest
        i = j + 2


# --------------------------------------------------------------------------- analyses


@dataclass(frozen=True)
class Ref:
    """A normalised context reference. ``path`` is lower-cased; ``*`` marks dynamic indices."""

    path: tuple[str, ...]
    serialized: bool = False  # reached through toJSON()/format of a whole object
    display: str = field(default="", compare=False)

    @property
    def dotted(self) -> str:
        return ".".join(self.path)

    def __str__(self) -> str:
        return self.display or self.dotted


def _ref_path(node: Node) -> list[str] | None:
    if isinstance(node, ContextRef):
        return [node.name.lower()]
    if isinstance(node, Property):
        base = _ref_path(node.obj)
        if base is None:
            return None
        return [*base, node.name.lower() if node.name is not None else "*"]
    if isinstance(node, Index):
        base = _ref_path(node.obj)
        if base is None:
            return None
        if isinstance(node.index, Literal) and isinstance(node.index.value, str):
            return [*base, node.index.value.lower()]
        return [*base, "*"]
    return None


def _children(node: Node) -> Iterator[Node]:
    if isinstance(node, (Property,)):
        yield node.obj
    elif isinstance(node, Index):
        yield node.obj
        yield node.index
    elif isinstance(node, Call):
        yield from node.args
    elif isinstance(node, Not):
        yield node.operand
    elif isinstance(node, Binary):
        yield node.left
        yield node.right


def context_refs(node: Node) -> list[Ref]:
    """Every context reference in the expression, outermost access chains only."""
    out: list[Ref] = []

    def walk(n: Node) -> None:
        path = _ref_path(n)
        if path is not None:
            out.append(Ref(tuple(path), display=".".join(path)))
            # Dynamic index expressions may themselves contain references.
            cur: Node = n
            while isinstance(cur, (Property, Index)):
                if isinstance(cur, Index):
                    walk(cur.index)
                cur = cur.obj
            return
        for child in _children(n):
            walk(child)

    walk(node)
    return out


# Functions whose result cannot carry attacker-controlled text.
_BOOLEAN_OR_SAFE_FUNCS = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "success",
        "failure",
        "always",
        "cancelled",
        "hashfiles",
    }
)
_SERIALIZING_FUNCS = frozenset({"tojson"})


def value_refs(node: Node) -> list[Ref]:
    """References whose *value* can end up in the result of evaluating ``node``."""
    out: list[Ref] = []

    def walk(n: Node, serialized: bool) -> None:
        if isinstance(n, Literal):
            return
        path = _ref_path(n)
        if path is not None:
            out.append(Ref(tuple(path), serialized, ".".join(path)))
            return
        if isinstance(n, (Property, Index)):
            # Property access on a computed value, e.g. fromJSON(x).title
            walk(n.obj, serialized)
            return
        if isinstance(n, Not):
            return
        if isinstance(n, Binary):
            if n.op in ("&&", "||"):
                walk(n.left, serialized)
                walk(n.right, serialized)
            return
        if isinstance(n, Call):
            name = n.name.lower()
            if name in _BOOLEAN_OR_SAFE_FUNCS:
                return
            if name == "case":
                # case(pred1, val1, pred2, val2, ..., default)
                for idx, arg in enumerate(n.args):
                    if idx % 2 == 1 or idx == len(n.args) - 1:
                        walk(arg, serialized)
                return
            child_serialized = serialized or name in _SERIALIZING_FUNCS
            for arg in n.args:
                walk(arg, child_serialized)

    walk(node, False)
    return out


def safe_parse(inner: str) -> Node | None:
    try:
        return parse_expression(inner)
    except ExpressionError:
        return None


def fallback_refs(inner: str) -> list[Ref]:
    """Best-effort reference extraction for expressions that fail to parse."""
    refs = []
    for m in re.finditer(r"[A-Za-z_][\w\-]*(?:\.(?:[A-Za-z_*][\w\-]*))+", inner):
        refs.append(Ref(tuple(m.group(0).lower().split(".")), display=m.group(0)))
    return refs
