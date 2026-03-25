"""
pwn-mcp-dynamic: MCP server exposing GDB/pwndbg-based dynamic analysis tools.

Tools: gdb_find_offset, gdb_run, gdb_breakpoint, gdb_examine, gdb_vmmap, gdb_stack
"""

from __future__ import annotations

import os
import re
import sys

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(__file__))
from gdb_session import GDBSession

mcp = FastMCP(
    name="pwn-dynamic-analysis",
    instructions=(
        "Dynamic analysis toolkit using GDB/pwndbg. Provides crash analysis, "
        "offset finding, memory examination, and breakpoint-based inspection."
    ),
)

# Shared session — stateful across tool calls within a server lifecycle
_session: GDBSession | None = None


def _get_session() -> GDBSession:
    global _session
    if _session is None or not _session.alive:
        _session = GDBSession(timeout=15)
    return _session


def _resolve_binary(path: str) -> str:
    resolved = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"Binary not found: {resolved}")
    return resolved


def _parse_registers(output: str) -> dict[str, str]:
    """Extract register values from GDB / pwndbg `info registers` output."""
    if not output or output.startswith("[TIMEOUT") or output.startswith("[GDB process"):
        return {}
    regs = {}
    for line in output.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("LEGEND") or line_stripped.startswith("─"):
            continue
        # "rax            0x401234" / "RAX  0x401234" / "rax: 0x401234"
        match = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s*:\s*(0x[0-9a-fA-F]+)", line_stripped)
        if not match:
            match = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s+(0x[0-9a-fA-F]+)", line_stripped)
        if match:
            regs[match.group(1).lower()] = match.group(2)
    return regs


def _registers_fallback(session) -> dict[str, str]:
    """When `info registers` layout differs (pwndbg/GDB versions), use print expressions."""
    regs: dict[str, str] = {}
    for name in ("rip", "rsp", "rbp", "rax"):
        out = session.command(f"p/x ${name}")
        m = re.search(r"(0x[0-9a-fA-F]+)", out)
        if m:
            regs[name] = m.group(1)
    return regs


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def gdb_find_offset(binary_path: str, pattern_length: int = 300) -> dict:
    """Find the exact buffer overflow offset by sending a cyclic pattern and analyzing the crash.

    Sends a De Bruijn cyclic pattern as stdin, runs the binary in GDB, reads
    the crash address from RSP (or RIP if it faulted on a ret), and computes
    the exact offset.

    Args:
        binary_path: Path to the ELF binary.
        pattern_length: Length of the cyclic pattern. Defaults to 300.

    Returns dict with: offset, crash_address, register_state, signal.
    """
    from pwn import cyclic, cyclic_find, context

    context.arch = "amd64"
    path = _resolve_binary(binary_path)
    pattern = cyclic(pattern_length)

    session = _get_session()
    session.start(path)
    output = session.run_with_stdin(pattern, timeout=10)

    # Get the signal info
    signal_info = "unknown"
    sig_match = re.search(r"Program received signal (\w+)", output)
    if sig_match:
        signal_info = sig_match.group(1)

    # Read registers after crash
    reg_output = session.command("info registers rip rsp rbp")
    regs = _parse_registers(reg_output)

    rip_val = regs.get("rip", "")
    rsp_val = regs.get("rsp", "")
    rbp_val = regs.get("rbp", "")

    offset = None
    crash_addr = None

    # Strategy 1: Check if RIP itself contains cyclic pattern data.
    # This happens when the `ret` instruction successfully executed
    # and jumped to a pattern address.
    if rip_val:
        try:
            rip_int = int(rip_val, 16)
            found = cyclic_find(rip_int & 0xFFFFFFFF)
            if found >= 0:
                offset = found
                crash_addr = rip_val
        except (ValueError, TypeError):
            pass

    # Strategy 2: Check RBP for cyclic data.
    # Often the crash occurs INSIDE the function (before ret) because
    # the corrupted RBP breaks RBP-relative memory accesses.
    # The return address is always at RBP_offset + 8 (saved RBP is
    # right below the return address on the stack).
    if offset is None and rbp_val:
        try:
            rbp_int = int(rbp_val, 16)
            found = cyclic_find(rbp_int & 0xFFFFFFFF)
            if found >= 0:
                offset = found + 8
                crash_addr = rbp_val
        except (ValueError, TypeError):
            pass

    # Strategy 3: Parse the backtrace for pattern addresses in return frames.
    if offset is None:
        bt_output = session.command("backtrace")
        for line in bt_output.splitlines():
            addr_match = re.search(r"(0x[0-9a-fA-F]{8,16})\s+None", line)
            if addr_match:
                try:
                    val = int(addr_match.group(1), 16)
                    found = cyclic_find(val & 0xFFFFFFFF)
                    if found >= 0:
                        offset = found
                        crash_addr = addr_match.group(1)
                        break
                except (ValueError, TypeError):
                    pass

    session.close()

    return {
        "offset": offset,
        "crash_address": crash_addr,
        "signal": signal_info,
        "registers": regs,
        "pattern_length": pattern_length,
    }


@mcp.tool()
def gdb_run(
    binary_path: str,
    stdin_data: str | None = None,
    args: str | None = None,
) -> dict:
    """Run a binary in GDB and return the result (registers, signal, output).

    Args:
        binary_path: Path to the ELF binary.
        stdin_data: String data to pipe as stdin. Use hex-escaped bytes for binary data.
        args: Command line arguments for the binary.

    Returns dict with: output, signal, registers, exit_code.
    """
    path = _resolve_binary(binary_path)
    session = _get_session()
    session.start(path)

    if args:
        session.command(f"set args {args}")

    if stdin_data:
        output = session.run_with_stdin(stdin_data.encode("latin-1"), timeout=10)
    else:
        output = session.command("run", timeout=10)

    # Check for signal/crash
    signal_info = None
    sig_match = re.search(r"Program received signal (\w+)", output)
    if sig_match:
        signal_info = sig_match.group(1)

    # Get registers if crashed
    regs = {}
    if signal_info:
        reg_output = session.command("info registers")
        regs = _parse_registers(reg_output)
        if not regs:
            regs = _registers_fallback(session)

    # Check exit status
    exit_code = None
    exit_match = re.search(r"exited (?:with code |normally)(\d*)", output)
    if exit_match:
        code_str = exit_match.group(1)
        exit_code = int(code_str) if code_str else 0

    session.close()

    return {
        "output": output[-4000:] if len(output) > 4000 else output,
        "signal": signal_info,
        "registers": regs,
        "exit_code": exit_code,
    }


@mcp.tool()
def gdb_breakpoint(
    binary_path: str,
    address: str,
    stdin_data: str | None = None,
    commands: list[str] | None = None,
) -> dict:
    """Set a breakpoint, run the binary, and return state at the breakpoint.

    Args:
        binary_path: Path to the ELF binary.
        address: Breakpoint address (hex like "0x401234" or symbol like "vuln").
        stdin_data: Optional stdin data for the binary.
        commands: Optional list of GDB commands to run at the breakpoint.

    Returns dict with: registers, stack_dump, output, command_results.
    """
    path = _resolve_binary(binary_path)
    session = _get_session()
    session.start(path)

    bp_output = session.command(f"break *{address}" if address.startswith("0x") else f"break {address}")

    if stdin_data:
        output = session.run_with_stdin(stdin_data.encode("latin-1"), timeout=10)
    else:
        output = session.command("run", timeout=10)

    # Get registers at breakpoint
    reg_output = session.command("info registers")
    regs = _parse_registers(reg_output)
    if not regs:
        regs = _registers_fallback(session)

    # Dump stack
    stack_output = session.command("x/16gx $rsp")

    # Run any extra commands
    cmd_results = {}
    if commands:
        for cmd in commands:
            cmd_results[cmd] = session.command(cmd)

    session.close()

    return {
        "output": output[-2000:] if len(output) > 2000 else output,
        "registers": regs,
        "stack_dump": stack_output,
        "command_results": cmd_results,
    }


@mcp.tool()
def gdb_examine(
    binary_path: str,
    address: str,
    count: int = 16,
    format: str = "gx",
    stdin_data: str | None = None,
    break_at: str | None = None,
) -> dict:
    """Examine memory at an address in GDB.

    Args:
        binary_path: Path to the ELF binary.
        address: Memory address to examine (hex or $register expression).
        count: Number of units to display. Defaults to 16.
        format: GDB format string (e.g. "gx" for giant hex, "wx" for word hex, "s" for string). Defaults to "gx".
        stdin_data: Optional stdin to provide before examining.
        break_at: Optional breakpoint to set before running (address or symbol).

    Returns dict with: memory_dump, address.
    """
    path = _resolve_binary(binary_path)
    session = _get_session()
    session.start(path)

    if break_at:
        bp_addr = f"*{break_at}" if break_at.startswith("0x") else break_at
        session.command(f"break {bp_addr}")

    if stdin_data:
        session.run_with_stdin(stdin_data.encode("latin-1"), timeout=10)
    elif break_at:
        session.command("run", timeout=10)

    result = session.command(f"x/{count}{format} {address}")
    session.close()

    return {
        "address": address,
        "format": f"{count}{format}",
        "memory_dump": result,
    }


@mcp.tool()
def gdb_vmmap(binary_path: str, stdin_data: str | None = None) -> dict:
    """Show the memory map of a running process in GDB.

    Args:
        binary_path: Path to the ELF binary.
        stdin_data: Optional stdin data (to get the process running first).

    Returns dict with: vmmap output showing memory regions.
    """
    path = _resolve_binary(binary_path)
    session = _get_session()
    session.start(path)

    session.command("break main")
    if stdin_data:
        session.run_with_stdin(stdin_data.encode("latin-1"), timeout=10)
    else:
        session.command("run", timeout=10)

    result = session.command("vmmap")
    session.close()

    return {"vmmap": result}


@mcp.tool()
def gdb_stack(
    binary_path: str,
    count: int = 32,
    stdin_data: str | None = None,
    break_at: str | None = None,
) -> dict:
    """Dump stack words around RSP.

    Args:
        binary_path: Path to the ELF binary.
        count: Number of 8-byte words to dump. Defaults to 32.
        stdin_data: Optional stdin data for the binary.
        break_at: Optional breakpoint to set before running.

    Returns dict with: stack contents, RSP value.
    """
    path = _resolve_binary(binary_path)
    session = _get_session()
    session.start(path)

    if break_at:
        bp_addr = f"*{break_at}" if break_at.startswith("0x") else break_at
        session.command(f"break {bp_addr}")

    if stdin_data:
        session.run_with_stdin(stdin_data.encode("latin-1"), timeout=10)
    elif break_at:
        session.command("run", timeout=10)

    rsp_output = session.command("p/x $rsp")
    stack_output = session.command(f"x/{count}gx $rsp")
    session.close()

    rsp_match = re.search(r"(0x[0-9a-fA-F]+)", rsp_output)
    rsp_val = rsp_match.group(1) if rsp_match else "unknown"

    return {
        "rsp": rsp_val,
        "count": count,
        "stack": stack_output,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
