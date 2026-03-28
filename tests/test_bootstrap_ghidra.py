"""Unit tests for bootstrap Ghidra function selection."""

from __future__ import annotations

from agent.core import _bootstrap_ghidra_function_names


def test_priority_order_main_vuln_win():
    fa = {"z_extra": 1, "main": 2, "vuln": 3, "aaa": 4, "win": 5}
    n = _bootstrap_ghidra_function_names(fa, 12)
    assert n[:3] == ["main", "vuln", "win"]


def test_caps_at_max_funcs():
    fa = {f"f{i}": i for i in range(100)}
    fa["main"] = 0
    n = _bootstrap_ghidra_function_names(fa, 3)
    assert len(n) == 3
    assert n[0] == "main"


def test_empty_funcs_falls_back_to_main():
    assert _bootstrap_ghidra_function_names({}, 12) == ["main"]
