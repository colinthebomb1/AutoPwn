"""ReAct agent loop — drives the exploit development process via Anthropic tool_use."""

from __future__ import annotations

import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from agent.planner import plan_from_checksec
from agent.prompts import get_system_prompt
from agent.tools import TOOL_MODULE_MAP, TOOL_REGISTRY

console = Console()

# Strip Markdown inline-code spans with no real content (model often emits `` or ` `).
_EMPTY_INLINE_CODE = re.compile(r"`[\t \u00a0\n]*`")


def _sanitize_agent_text(text: str) -> str:
    """Remove empty `...` pairs from assistant markdown so the UI isn't littered with ``."""
    if not text:
        return text
    return _EMPTY_INLINE_CODE.sub("", text)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _default_max_iterations() -> int:
    """CLI default when `-n` omitted: env `PWN_AGENT_MAX_ITERATIONS`, else 30."""
    raw = os.environ.get("PWN_AGENT_MAX_ITERATIONS")
    if raw and str(raw).strip():
        try:
            return int(raw)
        except ValueError:
            pass
    return 30


# First N messages are fixed (task + bootstrap). Older turns are dropped to cap input tokens.
_CONTEXT_HEAD_MESSAGES = 2


def _trim_conversation(messages: list[dict]) -> None:
    """Keep opening messages plus the last few assistant↔user rounds (in-place)."""
    turns = max(1, _env_int("PWN_AGENT_CONTEXT_TURNS", 8))
    max_tail = turns * 2  # each turn: assistant, then user(tool results)
    if len(messages) <= _CONTEXT_HEAD_MESSAGES + max_tail:
        return
    messages[:] = messages[:_CONTEXT_HEAD_MESSAGES] + messages[-max_tail:]


def _shallow_copy_trunc_run_exploit_script(result: Any) -> Any:
    """Shrink run_exploit tool_result JSON: full script is mirrored on disk already."""
    if not isinstance(result, dict):
        return result
    out = dict(result)
    sc = out.get("script")
    lim = _env_int("PWN_AGENT_RUN_EXPLOIT_SCRIPT_SNIP", 1600)
    if isinstance(sc, str) and len(sc) > lim:
        out["script"] = (
            sc[:lim]
            + "\n# ... truncated for API context; full file: exploits/last_attempt_<binary>.py"
        )
    return out


def _tool_result_str_for_api(tool_name: str, result: Any, suffix: str = "") -> str:
    payload = _shallow_copy_trunc_run_exploit_script(result) if tool_name == "run_exploit" else result
    body = json.dumps(payload, separators=(",", ":"), default=str) + suffix
    cap = _env_int("PWN_AGENT_TOOL_RESULT_MAX", 4500)
    if len(body) > cap:
        body = body[:cap] + "\n... [truncated]"
    return body


def _exploits_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exploits"))


def _binary_stem(binary_path: str) -> str:
    return os.path.splitext(os.path.basename(binary_path))[0]


def _save_last_attempt_exploit(binary_path: str, script: str) -> str:
    """Mirror the latest run_exploit script (success or failure) for the user to inspect."""
    os.makedirs(_exploits_dir(), exist_ok=True)
    path = os.path.join(_exploits_dir(), f"last_attempt_{_binary_stem(binary_path)}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(script)
    return path


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
        max_iterations: int | None = None,
        api_key: str | None = None,
    ):
        self.model = model
        self.max_iterations = max_iterations if max_iterations is not None else _default_max_iterations()
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

            str_list = strings_res if isinstance(strings_res, list) else []
            fname_l = os.path.basename(binary_path).lower()
            looks_canary_ret2 = (
                "ret2libc_pie_canary" in fname_l
                or any(
                    isinstance(s, str) and "ret2libc-pie-canary" in s for s in str_list
                )
            )
            if looks_canary_ret2:
                bootstrap["layout_hint"] = (
                    "Typical vuln stack for this family: buffer low at rbp-0x50, canary at rbp-0x8 "
                    "→ 72 bytes fill to canary, 88 bytes to saved RIP (not 80 from sub rsp,0x50). "
                    "sub rsp,IMM is total frame size, not distance to canary. "
                    "Use recvuntil(b'name?\\n'). Printed canary matches vuln fs:0x28 in one process; "
                    "do not compare unrelated GDB runs."
                )
            # Keep the injected message short enough to avoid token blowups.
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
                        max_tokens=_env_int("PWN_AGENT_MAX_OUTPUT_TOKENS", 3072),
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
                    clean = _sanitize_agent_text(block.text)
                    console.print(Panel(clean, title="Agent", border_style="green"))
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                summary = ""
                for block in assistant_content:
                    if block.type == "text":
                        summary += _sanitize_agent_text(block.text)

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

                    if tool_name == "run_exploit":
                        script = tool_input.get("script")
                        if isinstance(script, str) and script.strip():
                            lp = _save_last_attempt_exploit(binary_path, script)
                            console.print(
                                f"[dim]Latest exploit mirrored to {lp}[/dim]"
                            )

                    suffix = ""
                    if tool_name == "checksec" and not planner_injected and isinstance(result, dict):
                        strategy = plan_from_checksec(result)
                        suffix = (
                            "\n\n[Strategy Hint] Based on checksec: **"
                            + strategy.name
                            + "** — "
                            + strategy.description
                            + "\nSuggested techniques: "
                            + ", ".join(strategy.technique_hints)
                            + "\nSuggested tools: "
                            + ", ".join(strategy.suggested_tools)
                        )
                        planner_injected = True
                        console.print(
                            Panel(
                                f"Strategy: [bold]{strategy.name}[/bold] — {strategy.description}",
                                title="Planner",
                                border_style="magenta",
                            )
                        )

                    result_str = _tool_result_str_for_api(tool_name, result, suffix)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": result_str,
                    })

                messages.append({"role": "user", "content": tool_results})
                _trim_conversation(messages)

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
