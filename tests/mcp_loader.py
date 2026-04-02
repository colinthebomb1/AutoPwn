"""Load packaged MCP server modules used by the agent."""

from __future__ import annotations

import importlib


def _load(module_name: str):
    return importlib.import_module(module_name)


def load_exploit_tools():
    return _load("agent.mcp_servers.exploit_tools.server")


def load_dynamic_analysis():
    return _load("agent.mcp_servers.dynamic_analysis.server")
