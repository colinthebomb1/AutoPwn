"""Tests for the dynamic-analysis (GDB/pwndbg) MCP server."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "dynamic-analysis"))

import server as gdb_server


class TestGDBFindOffset:
    def test_finds_ret2win_offset(self, ret2win_binary):
        result = gdb_server.gdb_find_offset(ret2win_binary, pattern_length=300)
        assert isinstance(result, dict)
        assert result["signal"] == "SIGSEGV"
        assert result["offset"] is not None
        assert isinstance(result["offset"], int)
        assert result["offset"] > 0
        # ret2win has buf[64], so offset should be 64 + 8 (saved rbp) = 72
        assert result["offset"] == 72

    def test_returns_registers(self, ret2win_binary):
        result = gdb_server.gdb_find_offset(ret2win_binary)
        assert "registers" in result
        assert isinstance(result["registers"], dict)


class TestGDBRun:
    def test_normal_exit(self, ret2win_binary):
        result = gdb_server.gdb_run(ret2win_binary, stdin_data="hello")
        # Should exit normally (no crash with small input)
        assert isinstance(result, dict)
        assert result["signal"] is None or result.get("exit_code") is not None

    def test_crash_with_overflow(self, ret2win_binary):
        result = gdb_server.gdb_run(ret2win_binary, stdin_data="A" * 200)
        assert result["signal"] == "SIGSEGV"
        assert len(result["registers"]) > 0


class TestGDBBreakpoint:
    def test_break_at_symbol(self, ret2win_binary):
        result = gdb_server.gdb_breakpoint(ret2win_binary, address="vuln", stdin_data="test")
        assert isinstance(result, dict)
        assert "registers" in result
        assert "stack_dump" in result
        assert len(result["registers"]) > 0


class TestGDBStack:
    def test_dump_stack(self, ret2win_binary):
        result = gdb_server.gdb_stack(ret2win_binary, count=8, break_at="vuln", stdin_data="test")
        assert "rsp" in result
        assert "stack" in result
        assert result["rsp"] != "unknown"
