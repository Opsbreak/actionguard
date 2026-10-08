from __future__ import annotations

import textwrap

import pytest

from actionguard.yamlloader import YAMLParseError, YList, YMap, YStr, load_yaml


def load(text: str):
    data, _ = load_yaml(textwrap.dedent(text).lstrip("\n"))
    return data


def test_on_key_is_not_a_boolean():
    data = load(
        """
        on: push
        yes_key: yes
        flag: true
        """
    )
    assert "on" in data
    assert data["yes_key"] == "yes"
    assert data["flag"] is True


def test_positions_of_keys_and_values():
    data = load(
        """
        name: test
        jobs:
          build:
            runs-on: ubuntu-latest
        """
    )
    assert isinstance(data, YMap)
    assert data.key_line("jobs") == 2
    build = data["jobs"]["build"]
    assert isinstance(build, YMap)
    assert isinstance(build["runs-on"], YStr)
    assert build["runs-on"].line == 4
    assert build["runs-on"].col == 14


def test_literal_block_offsets_map_to_lines():
    data = load(
        """
        run: |
          echo one
          echo "${{ github.head_ref }}"
        """
    )
    run = data["run"]
    offset = run.index("${{")
    assert run.locate(offset, "${{ github.head_ref }}") == (3, 9)
    assert run.line_of(0) == 2
    assert run.line_of(1) == 3


def test_folded_and_plain_scalars_locate_by_search():
    data = load(
        """
        a: >
          first ${{ x }}
          second ${{ y }}
        b: echo ${{ z }}
        """
    )
    a = data["a"]
    assert a.locate(a.index("${{ y }}"), "${{ y }}") == (3, 10)
    b = data["b"]
    assert b.locate(b.index("${{ z }}"), "${{ z }}") == (4, 9)


def test_sequences_and_anchors():
    data = load(
        """
        base: &base
          x: 1
        derived:
          <<: *base
          y: 2
        items:
          - a
          - b
        """
    )
    assert data["derived"] == {"x": 1, "y": 2}
    assert isinstance(data["items"], YList)
    assert data["items"].line == 7


def test_parse_errors_carry_positions():
    with pytest.raises(YAMLParseError) as exc:
        load_yaml("jobs:\n  build:\n    run: echo: bad\n")
    assert exc.value.line == 3
    assert exc.value.column > 1


def test_bom_is_tolerated():
    data, source = load_yaml("﻿on: push\n")
    assert data["on"] == "push"
    assert source.line(1) == "on: push"
