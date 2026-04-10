"""ReAct agent loop — drives the exploit development process via Anthropic tool_use."""

from __future__ import annotations

import importlib
import json
import os
import random
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _bootstrap_ghidra_function_names(func_addrs: dict[str, Any], max_funcs: int) -> list[str]:
    """Pick bounded symbol names for startup decompilation (prioritize main/vuln/win)."""
    if not isinstance(func_addrs, dict) or not func_addrs:
        return ["main"]
    keys = [k for k in func_addrs if isinstance(k, str)]
    priority: list[str] = []
    for name in ("main", "vuln", "win", "pwn"):
        if name in keys and name not in priority:
            priority.append(name)
    fixed_skip = frozenset({"_init", "_fini", "_start", "start"})
    rest: list[str] = []
    for k in sorted(keys):
        if k in priority or k in fixed_skip:
            continue
        if k.startswith("__"):
            continue
        if k.startswith("register_tm") or k.startswith("deregister"):
            continue
        rest.append(k)
    out = priority + rest
    if not out:
        return ["main"]
    return out[: max(1, max_funcs)]


def _default_max_iterations() -> int:
    """CLI default when `-n` omitted: env `PWN_AGENT_MAX_ITERATIONS`, else 30."""
    raw = os.environ.get("PWN_AGENT_MAX_ITERATIONS")
    if raw and str(raw).strip():
        try:
            return int(raw)
        except ValueError:
            pass
    return 30


def _message_content_text(content: Any) -> str:
    """Flatten a message content payload into plain text for rough size estimation."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for key in ("text", "content"):
                    value = item.get(key)
                    if isinstance(value, str):
                        parts.append(value)
        return "\n".join(parts)
    return str(content)


def _estimated_message_chars(message: dict[str, Any]) -> int:
    return len(_message_content_text(message.get("content", "")))


# First N messages are fixed (task + bootstrap). Older turns are dropped to cap input tokens.
def _trim_conversation(messages: list[dict], *, head_messages: int = 2) -> None:
    """Keep opening messages plus the last few assistant↔user rounds (in-place).

    ``head_messages`` is 2 by default (task + bootstrap), or 3 when optional user
    context (CTF notes) was inserted between them.
    """
    turns = max(1, _env_int("PWN_AGENT_CONTEXT_TURNS", 8))
    max_chars = max(1, _env_int("PWN_AGENT_CONTEXT_MAX_CHARS", 18000))
    max_tail = turns * 2  # each turn: assistant, then user(tool results)
    head = messages[:head_messages]
    tail = messages[head_messages:]
    if len(messages) <= head_messages + max_tail and (
        sum(_estimated_message_chars(m) for m in messages) <= max_chars
    ):
        return
    kept_tail = tail[-max_tail:]
    while kept_tail and (
        sum(_estimated_message_chars(m) for m in head)
        + sum(_estimated_message_chars(m) for m in kept_tail)
        > max_chars
    ):
        del kept_tail[:2]
    messages[:] = head + kept_tail


def _shallow_copy_strip_run_exploit_script(result: Any) -> Any:
    """Drop echoed exploit source from API context; the full script is mirrored on disk."""
    if not isinstance(result, dict):
        return result
    out = dict(result)
    out.pop("script", None)
    return out


def _tool_result_str_for_api(tool_name: str, result: Any, suffix: str = "") -> str:
    payload = (
        _shallow_copy_strip_run_exploit_script(result)
        if tool_name == "run_exploit"
        else result
    )
    body = json.dumps(payload, separators=(",", ":"), default=str) + suffix
    cap = _env_int("PWN_AGENT_TOOL_RESULT_MAX", 4500)
    if len(body) > cap:
        body = body[:cap] + "\n... [truncated]"
    return body


def _operator_notes_message(user_context: str) -> str:
    """Render operator notes as binding constraints for the current run."""
    return (
        "The operator provided notes below. Treat explicit instructions and constraints "
        "in them as binding for this run unless a tool result proves they are impossible "
        "or incorrect. If you need to violate a note, say why and cite the conflicting "
        "evidence first. Use the remaining note content as additional challenge context.\n\n"
        "---\n\n"
        f"{user_context}"
    )


def _run_exploit_failure_hint(result: Any) -> str:
    """Return concise recovery hints for common run_exploit failure modes."""
    if not isinstance(result, dict):
        return ""
    stderr = str(result.get("stderr", "") or "")
    stdout = str(result.get("stdout", "") or "")
    timed_out = bool(result.get("timed_out", False))
    out = (stdout + "\n" + stderr).lower()

    hints: list[str] = []
    if timed_out:
        hints.append(
            "timeout likely from I/O desync; prefer sendlineafter/sendafter per "
            "prompt and avoid giant static stdin transcripts"
        )
    if "eoferror" in out or "brokenpipe" in out:
        hints.append(
            "target exited before next send; parse transcript to find last "
            "successful prompt and re-sync interaction"
        )
    if "unaligned tcache chunk detected" in out:
        hints.append(
            "tcache fd likely not correctly safe-linked; verify encoded fd "
            "uses (chunk_addr>>12)^target_addr"
        )

    if not hints:
        return ""
    return "\n[run_exploit recovery hint] " + " | ".join(hints)


def _usage_to_dict(usage: Any) -> dict[str, int]:
    """Normalize Anthropic usage object/dict to a dict of ints."""
    if usage is None:
        return {}
    if isinstance(usage, dict):
        out: dict[str, int] = {}
        for k, v in usage.items():
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                out[str(k)] = int(v)
            elif isinstance(v, str) and v.isdigit():
                out[str(k)] = int(v)
        return out

    out = {}
    for k in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        v = getattr(usage, k, None)
        if isinstance(v, (int, float)):
            out[k] = int(v)
    return out


def _bootstrap_function_symbol_scope(checksec_res: Any) -> str:
    """Prefer a smaller, user-focused function list for static binaries."""
    if isinstance(checksec_res, dict) and checksec_res.get("pie") is False:
        runpath = checksec_res.get("runpath")
        rpath = checksec_res.get("rpath")
        if not runpath and not rpath:
            return "user"
    return "all"


def _merge_known_facts(existing: list[str], new: list[str], *, max_facts: int = 8) -> list[str]:
    """Deduplicate while preserving recency and keeping the fact list short."""
    merged: list[str] = []
    for fact in [*existing, *new]:
        if not fact or fact in merged:
            continue
        merged.append(fact)
    if len(merged) > max_facts:
        merged = merged[-max_facts:]
    return merged


def _known_facts_message(facts: list[str]) -> str:
    """Render a compact, persistent summary of settled findings."""
    lines = ["Known facts summary. Reuse these before broad recon:"]
    for fact in facts:
        lines.append(f"- {fact}")
    return "\n".join(lines)


def _sync_known_facts_message(
    messages: list[dict[str, Any]],
    facts: list[str],
    *,
    insert_at: int,
    known_facts_index: int | None,
) -> int | None:
    """Insert, update, or remove the known-facts summary message."""
    if not facts:
        if known_facts_index is not None:
            del messages[known_facts_index]
        return None

    content = _known_facts_message(facts)
    if known_facts_index is None:
        messages.insert(insert_at, {"role": "user", "content": content})
        return insert_at

    messages[known_facts_index]["content"] = content
    return known_facts_index


_KNOWN_FACTS_BLOCK_RE = re.compile(
    r"<known_facts>\s*(?P<body>.*?)\s*</known_facts>",
    re.IGNORECASE | re.DOTALL,
)


def _normalize_known_fact(raw: str) -> str:
    fact = re.sub(r"\s+", " ", str(raw or "")).strip()
    fact = re.sub(r"^[-*]\s*", "", fact)
    if len(fact) > 240:
        fact = fact[:237].rstrip() + "..."
    return fact


def _extract_known_facts_block(text: str) -> tuple[str, list[str] | None]:
    """Strip an optional known-facts block from assistant text and parse its facts."""
    match = _KNOWN_FACTS_BLOCK_RE.search(text)
    if not match:
        return text, None

    body = match.group("body")
    facts: list[str] = []
    for line in body.splitlines():
        fact = _normalize_known_fact(line)
        if fact and fact not in facts:
            facts.append(fact)

    cleaned = (text[: match.start()] + text[match.end() :]).strip()
    return cleaned, facts


def _usage_add(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + int(v)
    return out


def _format_usage_summary(u: dict[str, int]) -> str:
    if not u:
        return "usage: (unavailable)"
    inp = u.get("input_tokens", 0)
    out = u.get("output_tokens", 0)
    cwrite = u.get("cache_creation_input_tokens", 0)
    cread = u.get("cache_read_input_tokens", 0)
    parts = [f"in={inp}", f"out={out}"]
    if cwrite or cread:
        parts.append(f"cache_write_in={cwrite}")
        parts.append(f"cache_read_in={cread}")
    return "usage: " + ", ".join(parts)


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
# Tool modules — loaded lazily from packaged MCP server modules
# ---------------------------------------------------------------------------

_exploit_mod = None
_dynamic_mod = None


def _get_exploit_module():
    global _exploit_mod
    if _exploit_mod is None:
        _exploit_mod = importlib.import_module("agent.mcp_servers.exploit_tools.server")
    return _exploit_mod


def _get_dynamic_module():
    global _dynamic_mod
    if _dynamic_mod is None:
        _dynamic_mod = importlib.import_module("agent.mcp_servers.dynamic_analysis.server")
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


class AutoPwnAgent:
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int | None = None,
        api_key: str | None = None,
        verbose: bool = False,
    ):
        self.model = model
        self.max_iterations = (
            max_iterations if max_iterations is not None else _default_max_iterations()
        )
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.verbose = verbose

    def solve(
        self,
        binary_path: str,
        remote: str | None = None,
        *,
        user_context: str | None = None,
    ) -> AgentResult:
        """Run the full ReAct loop to analyze and exploit a binary.

        ``user_context``: optional free-form text from the operator (CTF story,
        constraints, suspected bug class or solve sketch). Shown to the model before
        bootstrap. Length capped by ``PWN_AGENT_USER_CONTEXT_MAX`` (default 12000).
        """
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            return AgentResult(
                success=False, summary=f"Binary not found: {binary_path}", iterations=0
            )

        panel_lines = f"[bold]Target:[/bold] {binary_path}"
        uc = (user_context or "").strip()
        if uc:
            cap = _env_int("PWN_AGENT_USER_CONTEXT_MAX", 12000)
            if len(uc) > cap:
                uc = uc[:cap] + "\n... [user context truncated; raise PWN_AGENT_USER_CONTEXT_MAX]"
                console.print(
                    "[dim]User context truncated to "
                    f"PWN_AGENT_USER_CONTEXT_MAX ({cap}) chars.[/dim]"
                )
            user_context = uc
            panel_lines += f"\n[bold]Operator notes:[/bold] {len(user_context)} chars"
        else:
            user_context = None

        console.print(
            Panel(
                panel_lines,
                title="AutoPwn",
                border_style="blue",
            )
        )

        tools = [
            {"name": name, "description": spec["description"], "input_schema": spec["input_schema"]}
            for name, spec in TOOL_REGISTRY.items()
        ]

        system = get_system_prompt()
        if remote:
            host, port = remote.split(":")
            system += f"\n\nRemote target: {host}:{port}"

        system_blocks: list[dict[str, Any]] = [
            {
                "type": "text",
                "text": system,
                # Anthropic prompt caching (ephemeral ~5 min TTL). Biggest win: the system prompt
                # is reused across iterations in the ReAct loop.
                "cache_control": {"type": "ephemeral"},
            }
        ]

        # ------------------------------------------------------------------
        # Bootstrap analysis (cheap local tools + optional Ghidra)
        # ------------------------------------------------------------------
        # The goal is to avoid the agent spending early iterations re-running
        # `checksec`, `elf_symbols`, `strings_search`, and (when configured) `ghidra_decompile`.
        def _bootstrap() -> str:
            def _safe_call(name: str, args: dict) -> Any:
                try:
                    return _call_tool(name, args)
                except Exception as e:
                    return {"error": f"{type(e).__name__}: {e}"}

            def _safe_cmd(cmd: list[str], timeout_s: int = 3) -> str | None:
                try:
                    out = subprocess.check_output(
                        cmd,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=timeout_s,
                    )
                    return out.strip()
                except Exception:
                    return None

            checksec_res = _safe_call("checksec", {"binary_path": binary_path})
            function_symbol_scope = _bootstrap_function_symbol_scope(checksec_res)
            funcs_res = _safe_call(
                "elf_symbols",
                {
                    "binary_path": binary_path,
                    "symbol_type": "functions",
                    "symbol_scope": function_symbol_scope,
                },
            )
            plt_res = _safe_call("elf_symbols", {"binary_path": binary_path, "symbol_type": "plt"})
            got_res = _safe_call("elf_symbols", {"binary_path": binary_path, "symbol_type": "got"})
            strings_res = _safe_call(
                "strings_search", {"binary_path": binary_path, "min_length": 4}
            )
            ldd_out = _safe_cmd(["ldd", binary_path])
            interp_out = _safe_cmd(["readelf", "-l", binary_path])

            runtime_libc_lines: list[str] = []
            runtime_loader: str | None = None
            if isinstance(ldd_out, str):
                for line in ldd_out.splitlines():
                    s = line.strip()
                    if not s:
                        continue
                    if "libc.so" in s:
                        runtime_libc_lines.append(s)
                    if "ld-linux" in s or "ld-musl" in s:
                        runtime_loader = s

            requested_interp: str | None = None
            if isinstance(interp_out, str):
                m = re.search(r"Requesting program interpreter:\s*(.+?)\]", interp_out)
                if m:
                    requested_interp = m.group(1).strip()

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

            ghidra_res: Any = None
            ghidra_names: list[str] = []
            if _env_bool("PWN_AGENT_BOOTSTRAP_GHIDRA", True):
                max_fn = _env_int("PWN_AGENT_BOOTSTRAP_GHIDRA_MAX_FUNCS", 12)
                ghidra_names = _bootstrap_ghidra_function_names(func_addrs, max_fn)
                timeout_s = _env_int("PWN_AGENT_BOOTSTRAP_GHIDRA_TIMEOUT", 300)
                per_fn = _env_int("PWN_AGENT_BOOTSTRAP_GHIDRA_MAX_CHARS", 6000)
                console.print(
                    "[dim]Bootstrap: Ghidra decompile ("
                    f"{len(ghidra_names)} functions, timeout {timeout_s}s)…[/dim]"
                )
                ghidra_res = _safe_call(
                    "ghidra_decompile",
                    {
                        "binary_path": binary_path,
                        "functions": ghidra_names,
                        "timeout": timeout_s,
                        "max_chars_per_function": per_fn,
                    },
                )

            bootstrap = {
                "checksec": checksec_res,
                "main": main_addr,
                "vuln": vuln_addr,
                "plt": _pick(plt, ("puts", "printf", "read", "system")),
                "got": _pick(got, ("puts", "printf", "read", "system")),
                "runtime": {
                    "ldd_libc_lines": runtime_libc_lines,
                    "ldd_loader_line": runtime_loader,
                    "requested_program_interpreter": requested_interp,
                },
                # Unfiltered; may be truncated by the overall bootstrap size cap.
                "strings": strings_res if isinstance(strings_res, list) else strings_res,
                "strings_note": "If strings look truncated, rerun strings_search when needed.",
                "ghidra_decompile": ghidra_res,
                "ghidra_functions_requested": ghidra_names,
                "ghidra_note": (
                    "Pseudocode from headless Ghidra when ok=true; reuse before re-calling "
                    "ghidra_decompile. Set PWN_AGENT_BOOTSTRAP_GHIDRA=0 to skip."
                ),
            }
            # Keep the injected message short enough to avoid token blowups; allow more when
            # Ghidra succeeded (decompilation is the main reason for a larger bootstrap).
            ghidra_ok = isinstance(ghidra_res, dict) and ghidra_res.get("ok") is True
            if ghidra_ok:
                cap = _env_int("PWN_AGENT_BOOTSTRAP_MAX_CHARS_WITH_GHIDRA", 12000)
            else:
                cap = _env_int("PWN_AGENT_BOOTSTRAP_MAX_CHARS", 2500)
            dumped = json.dumps(bootstrap, separators=(",", ":"), default=str)
            if len(dumped) > cap:
                dumped = dumped[:cap] + "\n... [bootstrap truncated]"
            return dumped

        bootstrap_msg = _bootstrap()

        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"Analyze and exploit the binary at `{binary_path}`. "
                    "Start with `checksec` + `elf_symbols` for recon, "
                    "but if bootstrap provides those values, reuse them. "
                    "If bootstrap includes `ghidra_decompile` with ok=true, treat that pseudocode "
                    "as primary source for control flow before writing exploits. "
                    "If you want to refresh the known-facts summary, include a "
                    "<known_facts>...</known_facts> block in your normal reply with one "
                    "bullet-style fact per line. Only include settled, reusable facts; omit the "
                    "block when nothing needs updating. "
                    "On static binaries, avoid broad "
                    "`elf_symbols(symbol_type='all', symbol_scope='all')` unless you need "
                    "runtime/libc/compiler symbols for a specific reason; prefer the default "
                    "narrower symbol scope and curated `strings_search` output first. "
                    "Use gdb_find_offset to determine buffer overflow offsets precisely."
                ),
            }
        ]

        if user_context:
            messages.append(
                {
                    "role": "user",
                    "content": _operator_notes_message(user_context),
                }
            )

        messages.append(
            {
                "role": "user",
                "content": (
                    "Bootstrap analysis computed locally to help you start faster "
                    "(checksec, symbols, strings, and Ghidra pseudocode when the host has it). "
                    "You can use it as context, but feel free to rerun any tools if needed.\n\n"
                    f"{bootstrap_msg}"
                ),
            }
        )

        known_facts: list[str] = []
        known_facts_insert_at = len(messages)
        known_facts_index: int | None = None
        base_head_messages = 3 if user_context else 2

        all_tool_calls: list[dict] = []
        planner_injected = False
        total_usage: dict[str, int] = {}

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
                        system=system_blocks,
                        tools=tools,
                        messages=messages,
                    )
                    last_exc = None
                    break
                except (
                    anthropic._exceptions.OverloadedError,
                    anthropic._exceptions.RateLimitError,
                ) as e:
                    last_exc = e
                    if attempt >= 5:
                        break
                    # Exponential backoff with small jitter.
                    sleep_s = min(2 ** attempt, 20) + random.uniform(0, 0.75)
                    console.print(
                        "[dim]Anthropic busy (attempt "
                        f"{attempt}/4). Sleeping {sleep_s:.1f}s...[/dim]"
                    )
                    time.sleep(sleep_s)
            if last_exc is not None:
                raise last_exc

            assistant_content = response.content
            tool_use_blocks = []
            total_usage = _usage_add(
                total_usage, _usage_to_dict(getattr(response, "usage", None))
            )

            for block in assistant_content:
                if block.type == "text":
                    clean, proposed_known_facts = _extract_known_facts_block(block.text)
                    clean = _sanitize_agent_text(clean)
                    if proposed_known_facts is not None:
                        prev_known_facts = list(known_facts)
                        known_facts = proposed_known_facts[:]
                        known_facts_index = _sync_known_facts_message(
                            messages,
                            known_facts,
                            insert_at=known_facts_insert_at,
                            known_facts_index=known_facts_index,
                        )
                        if self.verbose:
                            added_facts = [
                                fact for fact in known_facts if fact not in prev_known_facts
                            ]
                            removed_facts = [
                                fact for fact in prev_known_facts if fact not in known_facts
                            ]
                            if added_facts:
                                self._display_known_facts(added_facts)
                            if removed_facts:
                                self._display_known_facts(
                                    [f"Removed: {fact}" for fact in removed_facts]
                                )
                    if clean.strip():
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

                if self.verbose:
                    console.print(
                        Panel(
                            _format_usage_summary(total_usage),
                            title="Tokens/Cache",
                            border_style="blue",
                        )
                    )
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
                    if (
                        tool_name == "checksec"
                        and not planner_injected
                        and isinstance(result, dict)
                    ):
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

                    if tool_name == "run_exploit":
                        suffix += _run_exploit_failure_hint(result)

                    result_str = _tool_result_str_for_api(tool_name, result, suffix)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": result_str,
                    })

                messages.append({"role": "user", "content": tool_results})
                current_head_messages = base_head_messages + (
                    1 if known_facts_index is not None else 0
                )
                _trim_conversation(messages, head_messages=current_head_messages)

            if response.stop_reason == "end_turn" and tool_use_blocks:
                continue

        if self.verbose:
            console.print(
                Panel(
                    _format_usage_summary(total_usage),
                    title="Tokens/Cache",
                    border_style="blue",
                )
            )
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

    def _display_known_facts(self, facts: list[str]) -> None:
        body = "\n".join(f"- {fact}" for fact in facts)
        console.print(Panel(body, title="Known Facts", border_style="magenta"))

    def _display_tool_result(self, name: str, result: Any, elapsed: float) -> None:
        result_str = (
            json.dumps(result, indent=2, default=str)
            if not isinstance(result, str)
            else result
        )
        if len(result_str) > 2000:
            result_str = result_str[:2000] + "\n... [truncated]"
        console.print(
            Panel(result_str, title=f"Result: {name} ({elapsed:.1f}s)", border_style="yellow")
        )
