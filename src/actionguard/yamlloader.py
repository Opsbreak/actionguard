"""A position-preserving YAML loader built on PyYAML's composer.

PyYAML's node graph carries start/end marks for every node. We convert that graph into
plain ``dict``/``list``/``str`` subclasses (``YMap``/``YList``/``YStr``) that remember
where they came from, so every finding can point at an exact line and column -- including
lines *inside* multi-line ``run: |`` block scalars.

Two GitHub-Actions-specific deviations from YAML 1.1 are applied:

* ``on``/``off``/``yes``/``no`` are **not** booleans (otherwise the ``on:`` trigger key
  would load as ``True``). Only ``true``/``false`` are, matching YAML 1.2 and GitHub.
* Merge keys (``<<: *anchor``) are flattened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

__all__ = [
    "SourceText",
    "YAMLParseError",
    "YList",
    "YMap",
    "YStr",
    "load_yaml",
]


class SourceText:
    """The raw text of a file, addressable by 1-based line numbers."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.splitlines()

    def line(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    def find(
        self, needle: str, start_line: int, start_col: int, end_line: int, occurrence: int = 0
    ) -> tuple[int, int] | None:
        """Find the ``occurrence``-th ``needle`` between two positions (1-based, inclusive)."""
        seen = 0
        for lineno in range(start_line, min(end_line, len(self.lines)) + 1):
            text = self.line(lineno)
            idx = text.find(needle, start_col - 1 if lineno == start_line else 0)
            while idx != -1:
                if seen == occurrence:
                    return lineno, idx + 1
                seen += 1
                idx = text.find(needle, idx + 1)
        return None


class YStr(str):
    """A string that remembers its source span and scalar style."""

    line: int
    col: int
    end_line: int
    style: str | None
    source: SourceText | None

    def __new__(
        cls,
        value: str,
        line: int = 1,
        col: int = 1,
        end_line: int | None = None,
        style: str | None = None,
        source: SourceText | None = None,
    ) -> YStr:
        obj = super().__new__(cls, value)
        obj.line = line
        obj.col = col
        obj.end_line = end_line if end_line is not None else line
        obj.style = style
        obj.source = source
        return obj

    @property
    def is_block(self) -> bool:
        return self.style in ("|", ">")

    def locate(self, offset: int, needle: str | None = None) -> tuple[int, int]:
        """Map a character offset inside the value back to a (line, column) in the file."""
        value = str(self)
        offset = max(0, min(offset, len(value)))
        src = self.source
        if self.style == "|":
            line = self.line + 1 + value.count("\n", 0, offset)
            line_start = value.rfind("\n", 0, offset) + 1
            in_line = offset - line_start
            col = in_line + 1
            if src is not None:
                text = src.line(line)
                line_end = value.find("\n", line_start)
                value_line = value[line_start : line_end if line_end != -1 else len(value)]
                if value_line and text.endswith(value_line):
                    col = len(text) - len(value_line) + in_line + 1
                elif needle and needle in text:
                    col = text.index(needle) + 1
            return line, col
        if src is not None and needle:
            occurrence = value.count(needle, 0, offset)
            found = src.find(needle, self.line, self.col, self.end_line, occurrence)
            if found:
                return found
        if src is not None and self.style is None and "\n" not in value:
            return self.line, self.col + offset
        return self.line, self.col

    def line_of(self, script_line_index: int) -> int:
        """Source line of the N-th (0-based) line of this scalar's value."""
        value = str(self)
        lines = value.split("\n")
        if script_line_index >= len(lines):
            return self.line
        if self.style == "|":
            return self.line + 1 + script_line_index
        offset = sum(len(x) + 1 for x in lines[:script_line_index])
        needle = lines[script_line_index].strip() or None
        return self.locate(
            offset + (len(lines[script_line_index]) - len(lines[script_line_index].lstrip())),
            needle,
        )[0]


class YMap(dict):  # type: ignore[type-arg]
    """A mapping that remembers its own position and the position of each key."""

    line: int = 1
    col: int = 1
    key_pos: dict[str, tuple[int, int]]

    def __init__(self, line: int = 1, col: int = 1) -> None:
        super().__init__()
        self.line = line
        self.col = col
        self.key_pos = {}

    def key_line(self, key: str, default: int | None = None) -> int:
        pos = self.key_pos.get(key)
        if pos:
            return pos[0]
        return default if default is not None else self.line

    def value_line(self, key: str) -> int:
        value = self.get(key)
        if isinstance(value, (YStr, YMap, YList)) and not (
            isinstance(value, YStr) and value.is_block
        ):
            return value.line
        return self.key_line(key)

    def ci_get(self, key: str, default: Any = None) -> Any:
        """Case-insensitive lookup (GitHub treats most workflow keys case-insensitively)."""
        if key in self:
            return self[key]
        lowered = key.lower()
        for k, v in self.items():
            if isinstance(k, str) and k.lower() == lowered:
                return v
        return default


class YList(list):  # type: ignore[type-arg]
    line: int = 1
    col: int = 1

    def __init__(self, line: int = 1, col: int = 1) -> None:
        super().__init__()
        self.line = line
        self.col = col


@dataclass
class YAMLParseError(Exception):
    message: str
    line: int = 1
    column: int = 1

    def __str__(self) -> str:
        return f"{self.message} (line {self.line}, column {self.column})"


class _Loader(yaml.SafeLoader):
    pass


_BOOL_TAG = "tag:yaml.org,2002:bool"
_Loader.yaml_implicit_resolvers = {
    key: [(tag, rx) for tag, rx in resolvers if tag != _BOOL_TAG]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


class _Converter:
    def __init__(self, loader: _Loader, source: SourceText) -> None:
        self.loader = loader
        self.source = source
        self.memo: dict[int, Any] = {}

    def convert(self, node: Node) -> Any:
        key = id(node)
        if key in self.memo:
            return self.memo[key]
        line, col = node.start_mark.line + 1, node.start_mark.column + 1
        if isinstance(node, MappingNode):
            self.loader.flatten_mapping(node)
            mapping = YMap(line, col)
            self.memo[key] = mapping
            for key_node, value_node in node.value:
                k = self.convert(key_node)
                try:
                    hash(k)
                except TypeError:
                    k = str(k)
                mapping[k] = self.convert(value_node)
                mapping.key_pos[str(k)] = (
                    key_node.start_mark.line + 1,
                    key_node.start_mark.column + 1,
                )
            return mapping
        if isinstance(node, SequenceNode):
            seq = YList(line, col)
            self.memo[key] = seq
            seq.extend(self.convert(item) for item in node.value)
            return seq
        if isinstance(node, ScalarNode):
            if node.tag == "tag:yaml.org,2002:str":
                end_line = node.end_mark.line + 1
                # Block scalars end on the line after their last content line.
                if node.style in ("|", ">") and node.end_mark.column == 0:
                    end_line -= 1
                result: Any = YStr(node.value, line, col, end_line, node.style, self.source)
            else:
                result = self.loader.construct_object(node, deep=True)
            self.memo[key] = result
            return result
        raise YAMLParseError(f"unsupported YAML node {type(node).__name__}", line, col)


def load_yaml(text: str) -> tuple[Any, SourceText]:
    """Parse ``text`` into position-aware containers. Raises :class:`YAMLParseError`."""
    if text.startswith("﻿"):
        text = text[1:]
    source = SourceText(text)
    loader = _Loader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            return None, source
        return _Converter(loader, source).convert(node), source
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        msg = " ".join(p for p in (exc.context, exc.problem) if p) or "invalid YAML"
        if mark is not None:
            raise YAMLParseError(msg, mark.line + 1, mark.column + 1) from None
        raise YAMLParseError(msg) from None
    except yaml.YAMLError as exc:
        raise YAMLParseError(str(exc).splitlines()[0] if str(exc) else "invalid YAML") from None
    except RecursionError:
        raise YAMLParseError("YAML document is too deeply nested") from None
    finally:
        loader.dispose()
