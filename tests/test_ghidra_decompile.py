"""Tests for Ghidra headless decompilation helper."""

from __future__ import annotations

import importlib.util
import os

import pytest


def _load_run_ghidra_decompile():
    path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "exploit-tools", "ghidra_decompile.py")
    )
    spec = importlib.util.spec_from_file_location("ghidra_decompile_test", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.run_ghidra_decompile


run_ghidra_decompile = _load_run_ghidra_decompile()


def test_run_ghidra_decompile_empty_functions():
    r = run_ghidra_decompile(__file__, [])
    assert r.get("ok") is False
    assert "empty" in (r.get("error") or "").lower()


def test_run_ghidra_decompile_missing_binary():
    r = run_ghidra_decompile("/nonexistent/no_such_binary", ["main"])
    assert r.get("ok") is False


def test_run_ghidra_decompile_no_ghidra_home(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("PWN_GHIDRA_HOME", raising=False)
    r = run_ghidra_decompile(__file__, ["main"])
    assert r.get("ok") is False
    assert "Ghidra" in (r.get("error") or "")


def test_run_ghidra_decompile_bad_explicit_home():
    r = run_ghidra_decompile(__file__, ["main"], ghidra_home="/definitely/not/ghidra")
    assert r.get("ok") is False
    assert "ghidra_home" in (r.get("error") or "").lower()


def _ghidra_headless_available() -> bool:
    for key in ("GHIDRA_HOME", "PWN_GHIDRA_HOME"):
        gh = os.environ.get(key)
        if gh and os.path.isfile(os.path.join(gh, "support", "analyzeHeadless")):
            return True
    return False


@pytest.mark.skipif(not _ghidra_headless_available(), reason="Ghidra headless / GHIDRA_HOME not available")
def test_run_ghidra_decompile_smoke_ret2win():
    """End-to-end headless run (requires Java + Ghidra on the runner)."""
    here = os.path.dirname(__file__)
    chal = os.path.join(here, "challenges", "ret2win_x64")
    if not os.path.isfile(chal):
        pytest.skip("ret2win_x64 not built")

    r = run_ghidra_decompile(chal, ["main", "win"], timeout=900)
    assert r.get("ok") is True, r
    funcs = r.get("functions") or {}
    assert "main" in funcs
    assert "c" in funcs.get("main", {}) or "error" in funcs.get("main", {})
