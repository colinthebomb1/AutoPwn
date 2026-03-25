"""ReAct agent loop — drives the exploit development process via Anthropic tool_use."""

from __future__ import annotations

import json
import os
import sys
import time
import random
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from agent.planner import plan_from_checksec
from agent.prompts import get_system_prompt

console = Console()

# ---------------------------------------------------------------------------
# Tool modules — loaded lazily from MCP server directories
# ---------------------------------------------------------------------------

_exploit_mod = None
_dynamic_mod = None


def _load_server_module(name: str, server_dir: str):
    """Load a server.py module from a specific directory without import cache collisions."""
    import importlib.util

    server_dir = os.path.abspath(server_dir)
    server_path = os.path.join(server_dir, "server.py")
    sys.path.insert(0, server_dir)
    spec = importlib.util.spec_from_file_location(name, server_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _get_exploit_module():
    global _exploit_mod
    if _exploit_mod is None:
        server_dir = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "exploit-tools")
        _exploit_mod = _load_server_module("exploit_server", server_dir)
    return _exploit_mod


def _get_dynamic_module():
    global _dynamic_mod
    if _dynamic_mod is None:
        server_dir = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "dynamic-analysis")
        _dynamic_mod = _load_server_module("dynamic_server", server_dir)
    return _dynamic_mod


# Maps tool name → which module provides it
TOOL_MODULE_MAP: dict[str, str] = {
    "checksec": "exploit",
    "elf_symbols": "exploit",
    "elf_search": "exploit",
    "rop_gadgets": "exploit",
    "cyclic_pattern": "exploit",
    "strings_search": "exploit",
    "shellcraft_generate": "exploit",
    "libc_symbols": "exploit",
    "libc_base_from_leak": "exploit",
    "pie_base_from_leak": "exploit",
    "ret2libc_stage1_payload": "exploit",
    "ret2libc_stage2_payload": "exploit",
    "format_string_payload": "exploit",
    "run_exploit": "exploit",
    "gdb_find_offset": "dynamic",
    "gdb_run": "dynamic",
    "gdb_breakpoint": "dynamic",
    "gdb_examine": "dynamic",
    "gdb_vmmap": "dynamic",
    "gdb_stack": "dynamic",
}


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    # --- Exploit tools ---
    "checksec": {
        "description": "Run checksec on a binary to identify security mitigations (RELRO, Canary, NX, PIE). Call this FIRST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
            },
            "required": ["binary_path"],
        },
    },
    "elf_symbols": {
        "description": "List symbols from an ELF binary: functions, PLT, GOT, and sections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "symbol_type": {
                    "type": "string",
                    "enum": ["all", "functions", "plt", "got"],
                    "description": "Type of symbols to list. Defaults to 'all'.",
                },
            },
            "required": ["binary_path"],
        },
    },
    "elf_search": {
        "description": "Search for a byte pattern in an ELF binary and return virtual addresses. Essential for finding '/bin/sh' addresses for ROP chains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search_string": {
                    "type": "string",
                    "description": "The string or hex bytes to search for. e.g. '/bin/sh' or '5fc3'",
                },
                "search_type": {
                    "type": "string",
                    "enum": ["string", "hex"],
                    "description": "'string' for ASCII, 'hex' for raw bytes. Default 'string'.",
                },
            },
            "required": ["binary_path", "search_string"],
        },
    },
    "rop_gadgets": {
        "description": "Search for ROP gadgets in a binary. Uses pwntools ROP engine plus raw byte-pattern search for common gadgets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search": {
                    "type": "string",
                    "description": "Filter string (e.g. 'pop rdi', 'ret'). If omitted, returns all gadgets.",
                },
                "max_results": {"type": "integer", "description": "Max gadgets to return. Default 50."},
            },
            "required": ["binary_path"],
        },
    },
    "cyclic_pattern": {
        "description": "Generate or query a De Bruijn cyclic pattern for finding buffer overflow offsets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["generate", "find"],
                    "description": "'generate' to create a pattern, 'find' to locate offset of a crash value.",
                },
                "length": {"type": "integer", "description": "Pattern length in bytes (for generate). Default 200."},
                "value": {"type": "string", "description": "Hex value to find (for find action), e.g. '0x61616168'."},
            },
            "required": ["action"],
        },
    },
    "strings_search": {
        "description": "Extract printable strings from a binary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "min_length": {"type": "integer", "description": "Minimum string length. Default 4."},
            },
            "required": ["binary_path"],
        },
    },
    "shellcraft_generate": {
        "description": "Generate shellcode using pwntools shellcraft. Returns hex-encoded shellcode, assembly listing, and length.",
        "input_schema": {
            "type": "object",
            "properties": {
                "payload_type": {
                    "type": "string",
                    "enum": ["sh", "cat_flag", "execve", "nop_sled"],
                    "description": "Type of shellcode: 'sh' for /bin/sh shell, 'cat_flag' to read flag.txt, 'execve' same as sh, 'nop_sled' for NOP padding.",
                },
                "arch": {
                    "type": "string",
                    "enum": ["amd64", "i386"],
                    "description": "Target architecture. Default 'amd64'.",
                },
            },
            "required": ["payload_type"],
        },
    },
    "libc_symbols": {
        "description": "Resolve useful libc symbol offsets and /bin/sh offset from a libc .so file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "libc_path": {"type": "string", "description": "Path to libc shared object."},
                "symbols": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional symbol names. Defaults to puts/system/__libc_start_main.",
                },
            },
            "required": ["libc_path"],
        },
    },
    "libc_base_from_leak": {
        "description": "Compute libc base from one leaked symbol address and return resolved runtime addresses (system, /bin/sh).",
        "input_schema": {
            "type": "object",
            "properties": {
                "libc_path": {"type": "string", "description": "Path to libc shared object."},
                "leaked_symbol": {"type": "string", "description": "Leaked symbol name, e.g. puts."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
            },
            "required": ["libc_path", "leaked_symbol", "leaked_address"],
        },
    },
    "pie_base_from_leak": {
        "description": "Compute PIE base from one leaked symbol address (pie_base = leak - elf.symbols[symbol]).",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target PIE ELF path."},
                "leaked_symbol": {"type": "string", "description": "Symbol name you leaked (e.g. 'main')."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
            },
            "required": ["binary_path", "leaked_symbol", "leaked_address"],
        },
    },
    "ret2libc_stage1_payload": {
        "description": "Build stage-1 payload: leak GOT via puts@plt and return to main/vuln for a second stage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target ELF path."},
                "offset": {"type": "integer", "description": "Overflow offset to saved RIP."},
                "leak_symbol": {"type": "string", "description": "Imported symbol to leak. Default puts."},
                "reentry_symbol": {"type": "string", "description": "Symbol to return to after leak. Default main."},
                "pie_base": {"type": "string", "description": "Optional PIE base as hex/int string. If omitted, treated as 0."},
            },
            "required": ["binary_path", "offset"],
        },
    },
    "ret2libc_stage2_payload": {
        "description": "Build stage-2 payload: compute libc base from leak and call system('/bin/sh').",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target ELF path."},
                "libc_path": {"type": "string", "description": "Libc path used by target."},
                "offset": {"type": "integer", "description": "Overflow offset to saved RIP."},
                "leaked_symbol": {"type": "string", "description": "Symbol name used for base calc (e.g. puts)."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
                "pie_base": {"type": "string", "description": "Optional PIE base as hex/int string. If omitted, treated as 0."},
            },
            "required": ["binary_path", "libc_path", "offset", "leaked_symbol", "leaked_address"],
        },
    },
    "format_string_payload": {
        "description": (
            "Generate a format string write payload (pwntools fmtstr_payload). "
            "In run_exploit scripts, copy exploit_lines verbatim OR use bytes.fromhex(payload_hex) — "
            "never type binary as b'\\\\xdc3@' or change %7$ to %8$."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "offset": {
                    "type": "integer",
                    "description": "Stack index where your input starts (from AAAA%p.%p... tests).",
                },
                "writes": {
                    "type": "object",
                    "description": "Dict of {hex_address: value}. Example: {'0x4033dc': 1} for a flag byte.",
                },
                "arch": {"type": "string", "description": "Default 'amd64'."},
                "written": {
                    "type": "integer",
                    "description": "Chars already printed in THIS printf only. Usually 0 if prefix was a separate printf(3) call.",
                },
                "write_size": {
                    "type": "string",
                    "enum": ["byte", "short", "int"],
                    "description": "Prefer 'byte' for small writes (default). Use 'int' for full 32-bit values.",
                },
                "no_dollars": {
                    "type": "boolean",
                    "description": "Set true if the binary rejects positional %N$ (pwntools no_dollars). Default false.",
                },
            },
            "required": ["offset", "writes"],
        },
    },
    "run_exploit": {
        "description": "Execute a pwntools exploit script. Write a complete Python script using pwntools, and this tool will run it and return stdout/stderr/exit_code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "The pwntools exploit script as a Python string."},
                "binary_path": {"type": "string", "description": "Path to target binary (optional, set as BINARY env var)."},
                "timeout": {"type": "integer", "description": "Execution timeout in seconds. Default 15."},
            },
            "required": ["script"],
        },
    },
    # --- Dynamic analysis (GDB) tools ---
    "gdb_find_offset": {
        "description": "Find the exact buffer overflow offset by crashing the binary with a cyclic pattern in GDB and analyzing the crash state. Much more reliable than guessing offsets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "pattern_length": {"type": "integer", "description": "Length of cyclic pattern. Default 300."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_run": {
        "description": "Run a binary in GDB and return the crash/exit state including registers and signal info.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "stdin_data": {"type": "string", "description": "Data to pipe as stdin."},
                "args": {"type": "string", "description": "Command line arguments."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_breakpoint": {
        "description": "Set a breakpoint in GDB, run the binary, and return the register/stack state at the breakpoint.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "address": {"type": "string", "description": "Breakpoint address (hex like '0x401234' or symbol like 'vuln')."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional GDB commands to run at the breakpoint.",
                },
            },
            "required": ["binary_path", "address"],
        },
    },
    "gdb_examine": {
        "description": "Examine memory at an address in GDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "address": {"type": "string", "description": "Memory address to examine (hex or $register)."},
                "count": {"type": "integer", "description": "Number of units to display. Default 16."},
                "format": {"type": "string", "description": "GDB format (e.g. 'gx' for giant hex, 'wx' for word hex, 's' for string). Default 'gx'."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "break_at": {"type": "string", "description": "Optional breakpoint to set before running."},
            },
            "required": ["binary_path", "address"],
        },
    },
    "gdb_vmmap": {
        "description": "Show the memory map of a running process in GDB. Useful for finding stack/heap addresses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_stack": {
        "description": "Dump stack words around RSP. Useful for understanding stack layout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "count": {"type": "integer", "description": "Number of 8-byte words to dump. Default 32."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "break_at": {"type": "string", "description": "Optional breakpoint (address or symbol)."},
            },
            "required": ["binary_path"],
        },
    },
}


def _call_tool(name: str, arguments: dict) -> Any:
    """Dispatch a tool call to the appropriate MCP server module."""
    module_key = TOOL_MODULE_MAP.get(name)
    if module_key is None:
        return {"error": f"Unknown tool: {name}"}

    if module_key == "exploit":
        mod = _get_exploit_module()
    elif module_key == "dynamic":
        mod = _get_dynamic_module()
    else:
        return {"error": f"Unknown module: {module_key}"}

    func = getattr(mod, name, None)
    if func is None:
        return {"error": f"Tool {name} not found in {module_key} module"}
    try:
        return func(**arguments)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

@dataclass
class AgentResult:
    success: bool
    summary: str
    iterations: int
    exploit_script: str | None = None
    tool_calls: list[dict] = field(default_factory=list)


class PwnAgent:
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int = 30,
        api_key: str | None = None,
    ):
        self.model = model
        self.max_iterations = max_iterations
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def solve(self, binary_path: str, remote: str | None = None) -> AgentResult:
        """Run the full ReAct loop to analyze and exploit a binary."""
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            return AgentResult(success=False, summary=f"Binary not found: {binary_path}", iterations=0)

        console.print(Panel(f"[bold]Target:[/bold] {binary_path}", title="pwn-solver", border_style="blue"))

        tools = [
            {"name": name, "description": spec["description"], "input_schema": spec["input_schema"]}
            for name, spec in TOOL_REGISTRY.items()
        ]

        system = get_system_prompt()
        if remote:
            host, port = remote.split(":")
            system += f"\n\nRemote target: {host}:{port}"

        # ------------------------------------------------------------------
        # Bootstrap analysis (cheap local tools)
        # ------------------------------------------------------------------
        # The goal is to avoid the agent spending early iterations re-running
        # `checksec`, `elf_symbols`, and `strings_search`.
        def _bootstrap() -> str:
            def _safe_call(name: str, args: dict) -> Any:
                try:
                    return _call_tool(name, args)
                except Exception as e:
                    return {"error": f"{type(e).__name__}: {e}"}

            checksec_res = _safe_call("checksec", {"binary_path": binary_path})
            funcs_res = _safe_call("elf_symbols", {"binary_path": binary_path, "symbol_type": "functions"})
            plt_res = _safe_call("elf_symbols", {"binary_path": binary_path, "symbol_type": "plt"})
            got_res = _safe_call("elf_symbols", {"binary_path": binary_path, "symbol_type": "got"})
            strings_res = _safe_call("strings_search", {"binary_path": binary_path, "min_length": 4})

            plt = plt_res.get("plt", {}) if isinstance(plt_res, dict) else {}
            got = got_res.get("got", {}) if isinstance(got_res, dict) else {}
            func_addrs = funcs_res.get("functions", {}) if isinstance(funcs_res, dict) else {}

            main_addr = func_addrs.get("main")
            vuln_addr = func_addrs.get("vuln")

            def _pick(d: dict, keys: tuple[str, ...]) -> dict:
                out: dict[str, Any] = {}
                for k in keys:
                    if k in d:
                        out[k] = d[k]
                return out

            bootstrap = {
                "checksec": checksec_res,
                "main": main_addr,
                "vuln": vuln_addr,
                "plt": _pick(plt, ("puts", "printf", "read", "system")),
                "got": _pick(got, ("puts", "printf", "read", "system")),
                # Unfiltered; may be truncated by the overall bootstrap size cap.
                "strings": strings_res if isinstance(strings_res, list) else strings_res,
                "strings_note": "If strings look truncated, rerun strings_search when needed.",
            }
            # Keep the injected message short enough to avoid token blowups.
            import json

            dumped = json.dumps(bootstrap, indent=2, default=str)
            if len(dumped) > 2500:
                dumped = dumped[:2500] + "\n... [bootstrap truncated]"
            return dumped

        bootstrap_msg = _bootstrap()

        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"Analyze and exploit the binary at `{binary_path}`. "
                    f"Start with `checksec` + `elf_symbols` for recon, but if bootstrap provides those values, reuse them. "
                    f"Use gdb_find_offset to determine buffer overflow offsets precisely."
                ),
            }
        ]

        messages.append(
            {
                "role": "user",
                "content": (
                    "Bootstrap analysis computed locally to help you start faster. "
                    "You can use it as context, but feel free to rerun any tools if needed.\n\n"
                    f"{bootstrap_msg}"
                ),
            }
        )

        all_tool_calls: list[dict] = []
        planner_injected = False

        for iteration in range(1, self.max_iterations + 1):
            console.print(f"\n[dim]─── Iteration {iteration}/{self.max_iterations} ───[/dim]")

            # Anthropic sometimes returns 429/529 transient errors. Retry so the
            # agent doesn't crash mid-run and lose context.
            last_exc: Exception | None = None
            for attempt in range(1, 6):
                try:
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=4096,
                        system=system,
                        tools=tools,
                        messages=messages,
                    )
                    last_exc = None
                    break
                except (anthropic._exceptions.OverloadedError, anthropic._exceptions.RateLimitError) as e:
                    last_exc = e
                    if attempt >= 5:
                        break
                    # Exponential backoff with small jitter.
                    sleep_s = min(2 ** attempt, 20) + random.uniform(0, 0.75)
                    console.print(
                        f"[dim]Anthropic busy (attempt {attempt}/4). Sleeping {sleep_s:.1f}s...[/dim]"
                    )
                    time.sleep(sleep_s)
            if last_exc is not None:
                raise last_exc

            assistant_content = response.content
            tool_use_blocks = []

            for block in assistant_content:
                if block.type == "text":
                    console.print(Panel(block.text, title="Agent", border_style="green"))
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                summary = ""
                for block in assistant_content:
                    if block.type == "text":
                        summary += block.text

                last_script = None
                for tc in reversed(all_tool_calls):
                    if tc["tool"] == "run_exploit":
                        last_script = tc["input"].get("script")
                        break

                return AgentResult(
                    success=True,
                    summary=summary,
                    iterations=iteration,
                    exploit_script=last_script,
                    tool_calls=all_tool_calls,
                )

            if tool_use_blocks:
                messages.append({"role": "assistant", "content": assistant_content})
                tool_results = []

                for tool_block in tool_use_blocks:
                    tool_name = tool_block.name
                    tool_input = tool_block.input

                    self._display_tool_call(tool_name, tool_input)

                    start = time.time()
                    result = _call_tool(tool_name, tool_input)
                    elapsed = time.time() - start

                    call_record = {
                        "iteration": iteration,
                        "tool": tool_name,
                        "input": tool_input,
                        "output": result,
                        "elapsed_seconds": round(elapsed, 2),
                    }
                    all_tool_calls.append(call_record)

                    self._display_tool_result(tool_name, result, elapsed)

                    # Inject planner strategy after first checksec call
                    result_str = json.dumps(result, indent=2, default=str)
                    if tool_name == "checksec" and not planner_injected and isinstance(result, dict):
                        strategy = plan_from_checksec(result)
                        planner_note = (
                            f"\n\n[Strategy Hint] Based on checksec: **{strategy.name}** — "
                            f"{strategy.description}\n"
                            f"Suggested techniques: {', '.join(strategy.technique_hints)}\n"
                            f"Suggested tools: {', '.join(strategy.suggested_tools)}"
                        )
                        result_str += planner_note
                        planner_injected = True
                        console.print(
                            Panel(
                                f"Strategy: [bold]{strategy.name}[/bold] — {strategy.description}",
                                title="Planner",
                                border_style="magenta",
                            )
                        )

                    if len(result_str) > 8000:
                        result_str = result_str[:8000] + "\n... [truncated]"

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": result_str,
                    })

                messages.append({"role": "user", "content": tool_results})

            if response.stop_reason == "end_turn" and tool_use_blocks:
                continue

        return AgentResult(
            success=False,
            summary="Max iterations reached without solving the challenge.",
            iterations=self.max_iterations,
            tool_calls=all_tool_calls,
        )

    def _display_tool_call(self, name: str, inputs: dict) -> None:
        table = Table(title=f"Tool Call: {name}", border_style="cyan", show_header=False)
        table.add_column("Param", style="bold")
        table.add_column("Value")
        for k, v in inputs.items():
            val_str = str(v)
            if len(val_str) > 200:
                val_str = val_str[:200] + "..."
            table.add_row(k, val_str)
        console.print(table)

    def _display_tool_result(self, name: str, result: Any, elapsed: float) -> None:
        result_str = json.dumps(result, indent=2, default=str) if not isinstance(result, str) else result
        if len(result_str) > 2000:
            result_str = result_str[:2000] + "\n... [truncated]"
        console.print(
            Panel(result_str, title=f"Result: {name} ({elapsed:.1f}s)", border_style="yellow")
        )
