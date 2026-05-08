"""Regression tests for packaged MCP server imports."""

from __future__ import annotations

from importlib import resources


def test_mcp_server_modules_are_importable() -> None:
    import importlib

    exploit = importlib.import_module("agent.mcp_servers.exploit_tools.server")
    dynamic = importlib.import_module("agent.mcp_servers.dynamic_analysis.server")
    assert exploit.__name__ == "agent.mcp_servers.exploit_tools.server"
    assert dynamic.__name__ == "agent.mcp_servers.dynamic_analysis.server"


def test_packaged_ghidra_script_is_bundled() -> None:
    script = (
        resources.files("agent.mcp_servers.exploit_tools.ghidra_scripts") / "DecompileFunctions.py"
    )
    assert script.is_file()
