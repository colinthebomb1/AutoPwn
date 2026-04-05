"""Tests for the dynamic-analysis (GDB/pwndbg) MCP server."""

from __future__ import annotations

from tests.mcp_loader import load_dynamic_analysis

gdb_server = load_dynamic_analysis()


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
        assert "disassembly" in result
        assert isinstance(result["disassembly"], str)
        assert len(result["registers"]) > 0

    def test_returns_early_after_run_timeout(self, monkeypatch):
        from agent.mcp_servers.dynamic_analysis import server as gdb_server_mod

        class FakeSession:
            def __init__(self):
                self.commands: list[str] = []
                self.closed = False

            def start(self, path):
                self.commands.append(f"start:{path}")

            def command(self, cmd, timeout=None):
                self.commands.append(cmd)
                return "unexpected follow-up command"

            def run_with_stdin(self, stdin_data, timeout=None):
                self.commands.append(f"run_with_stdin:{timeout}")
                return "[TIMEOUT after 30s waiting for GDB prompt]"

            def close(self):
                self.closed = True

        fake_session = FakeSession()

        monkeypatch.setattr(gdb_server_mod, "_resolve_binary", lambda p: p)
        monkeypatch.setattr(gdb_server_mod, "_get_session", lambda: fake_session)

        result = gdb_server_mod.gdb_breakpoint(
            "/tmp/fake",
            address="main",
            stdin_data="AAAA",
        )

        assert result["output"] == "[TIMEOUT after 30s waiting for GDB prompt]"
        assert result["disassembly"] == "[TIMEOUT after 30s waiting for GDB prompt]"
        assert result["stack_dump"] == "[TIMEOUT after 30s waiting for GDB prompt]"
        assert result["registers"] == {}
        assert result["command_results"] == {}
        assert fake_session.closed is True
        assert fake_session.commands == [
            "start:/tmp/fake",
            "break main",
            "run_with_stdin:30",
        ]


class TestGDBStack:
    def test_dump_stack(self, ret2win_binary):
        result = gdb_server.gdb_stack(ret2win_binary, count=8, break_at="vuln", stdin_data="test")
        assert "rsp" in result
        assert "stack" in result
        assert result["rsp"] != "unknown"
