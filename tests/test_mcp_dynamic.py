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

    def test_finds_offset_on_i386_via_eip(self, monkeypatch):
        from pwn import context, cyclic

        from agent.mcp_servers.dynamic_analysis import server as gdb_server_mod

        context.arch = "i386"
        pat = cyclic(40)
        eip_int = int.from_bytes(pat[8:12], "little")
        eip_val = hex(eip_int)

        class FakeSession:
            def start(self, path): pass
            def run_with_stdin(self, data, timeout=None):
                return "Program received signal SIGSEGV"
            def command(self, cmd, timeout=None):
                if "info registers" in cmd:
                    return f"eip {eip_val}\nebp 0x00000000"
                return ""
            def close(self): pass

        monkeypatch.setattr(gdb_server_mod, "_resolve_binary", lambda p: p)
        monkeypatch.setattr(gdb_server_mod, "_get_session", lambda: FakeSession())
        monkeypatch.setattr(
            gdb_server_mod, "_gdb_arch_context", lambda path: ("i386", "eip", "esp", "ebp")
        )

        result = gdb_server_mod.gdb_find_offset("/tmp/fake", pattern_length=40)
        assert result["offset"] == 8
        assert result["signal"] == "SIGSEGV"

    def test_finds_offset_on_i386_via_ebp_uses_ptr_size_4(self, monkeypatch):
        from pwn import context, cyclic

        from agent.mcp_servers.dynamic_analysis import server as gdb_server_mod

        context.arch = "i386"
        pat = cyclic(40)
        ebp_int = int.from_bytes(pat[8:12], "little")
        ebp_val = hex(ebp_int)

        class FakeSession:
            def start(self, path): pass
            def run_with_stdin(self, data, timeout=None):
                return "Program received signal SIGSEGV"
            def command(self, cmd, timeout=None):
                if "info registers" in cmd:
                    return f"eip 0xdeadbeef\nebp {ebp_val}"
                if cmd == "backtrace":
                    return ""
                return ""
            def close(self): pass

        monkeypatch.setattr(gdb_server_mod, "_resolve_binary", lambda p: p)
        monkeypatch.setattr(gdb_server_mod, "_get_session", lambda: FakeSession())
        monkeypatch.setattr(
            gdb_server_mod, "_gdb_arch_context", lambda path: ("i386", "eip", "esp", "ebp")
        )

        result = gdb_server_mod.gdb_find_offset("/tmp/fake", pattern_length=40)
        # EBP matches at offset 8; return addr = 8 + ptr_size(4) = 12
        assert result["offset"] == 12


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

    def test_uses_32bit_registers_and_stack_for_i386(self, monkeypatch):
        from agent.mcp_servers.dynamic_analysis import server as gdb_server_mod

        class FakeSession:
            def __init__(self):
                self.commands: list[str] = []

            @property
            def alive(self):
                return True

            def start(self, path):
                self.commands.append(f"start:{path}")

            def command(self, cmd, timeout=None):
                self.commands.append(cmd)
                if cmd == "info registers":
                    return "eip 0x8049000\nesp 0xfffef000\nebp 0xfffef100"
                if cmd == "x/12i $eip":
                    return "=> 0x8049000 <vuln>: ret"
                if cmd == "x/16wx $esp":
                    return "0xfffef000:\t0x41414141"
                return "Breakpoint 1, vuln ()"

            def run_with_stdin(self, stdin_data, timeout=None):
                self.commands.append(f"run_with_stdin:{timeout}")
                return "Breakpoint 1, vuln ()"

            def close(self):
                self.commands.append("close")

        monkeypatch.setattr(gdb_server_mod, "_resolve_binary", lambda p: p)
        monkeypatch.setattr(gdb_server_mod, "_get_session", lambda: FakeSession())
        monkeypatch.setattr(
            gdb_server_mod,
            "_gdb_arch_context",
            lambda path: ("i386", "eip", "esp", "ebp"),
        )

        result = gdb_server_mod.gdb_breakpoint("/tmp/fake", address="vuln", stdin_data="A")
        assert result["disassembly"] == "=> 0x8049000 <vuln>: ret"
        assert "0x41414141" in result["stack_dump"]
        assert result["registers"]["eip"] == "0x8049000"


class TestGDBStack:
    def test_dump_stack(self, ret2win_binary):
        result = gdb_server.gdb_stack(ret2win_binary, count=8, break_at="vuln", stdin_data="test")
        assert "rsp" in result
        assert "stack" in result
        assert result["rsp"] != "unknown"
