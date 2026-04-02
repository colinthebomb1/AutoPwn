"""Regression tests for packaged MCP server imports."""

from __future__ import annotations

from importlib import resources


def test_core_imports_packaged_mcp_servers() -> None:
    from agent.core import _get_dynamic_module, _get_exploit_module

    assert _get_exploit_module().__name__ == "agent.mcp_servers.exploit_tools.server"
    assert _get_dynamic_module().__name__ == "agent.mcp_servers.dynamic_analysis.server"


def test_packaged_ghidra_script_is_bundled() -> None:
    script = (
        resources.files("agent.mcp_servers.exploit_tools.ghidra_scripts")
        / "DecompileFunctions.py"
    )
    assert script.is_file()
