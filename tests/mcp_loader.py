"""Load MCP server modules by file path — avoids `import server` cache collisions."""

from __future__ import annotations

import importlib.util
import os


def _load(name: str, *path_parts: str):
    root = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", *path_parts)
    server_path = os.path.abspath(os.path.join(root, "server.py"))
    spec = importlib.util.spec_from_file_location(name, server_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load MCP server from {server_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_exploit_tools():
    return _load("pwn_solver_tests.exploit_tools", "exploit-tools")


def load_dynamic_analysis():
    return _load("pwn_solver_tests.dynamic_analysis", "dynamic-analysis")
