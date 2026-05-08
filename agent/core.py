"""ReAct agent loop — drives the exploit development process via Anthropic tool_use."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent.mcp_client import MCPDispatcher
from agent.planner import plan_from_checksec
from agent.prompts import get_system_prompt
from agent.tools import TOOL_REGISTRY

log = logging.getLogger(__name__)
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
    for name in keys:
        lowered = name.lower()
        if lowered == "vulnerable" and name not in priority:
            priority.append(name)
    fixed_skip = frozenset({"_init", "_fini", "_start", "start"})
    static_hint_parts = ("vuln", "vulner", "win", "pwn", "flag", "shell", "secret", "admin")
    library_heavy = any(
        k.startswith(("_", "dl", "pthread_"))
        or any(
            part in k.lower() for part in ("printf", "scanf", "malloc", "free", "locale", "unwind")
        )
        for k in keys
    )
    rest: list[str] = []
    for k in sorted(keys):
        if k in priority or k in fixed_skip:
            continue
        if k.startswith("__"):
            continue
        if k.startswith("register_tm") or k.startswith("deregister"):
            continue
        if library_heavy and not any(part in k.lower() for part in static_hint_parts):
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
    # Snap forward to the first assistant message so we never start
    # with an orphaned tool_result that has no preceding tool_use.
    while kept_tail and kept_tail[0]["role"] != "assistant":
        kept_tail = kept_tail[1:]
    while kept_tail and (
        sum(_estimated_message_chars(m) for m in head)
        + sum(_estimated_message_chars(m) for m in kept_tail)
        > max_chars
    ):
        # Remove one complete turn: the leading assistant message plus all
        # immediately following user messages (tool_results + reconcile).
        del kept_tail[0]
        while kept_tail and kept_tail[0]["role"] == "user":
            del kept_tail[0]
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
        _shallow_copy_strip_run_exploit_script(result) if tool_name == "run_exploit" else result
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


def _print_exploit_success_banner(result: dict, script_path: str | None) -> None:
    stdout = str(result.get("stdout", "") or "").strip()
    flags = result.get("flags_found") or []
    uid_line = result.get("uid_line")

    lines: list[str] = []
    if flags:
        lines.append("[bold]Flags:[/bold] " + "  ".join(flags))
    if uid_line:
        lines.append("[bold]Shell:[/bold] " + uid_line)
    if stdout:
        preview = stdout[-1500:] if len(stdout) > 1500 else stdout
        lines.append("[bold]Output:[/bold]\n" + preview)
    if script_path:
        lines.append(f"[bold]Exploit saved:[/bold] {script_path}")

    console.print(
        Panel(
            "\n".join(lines) if lines else "Exploit succeeded.",
            title="[bold green] Exploit Succeeded [/bold green]",
            border_style="green",
        )
    )


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


def _known_facts_reconcile_message() -> str:
    """Generic reminder to consolidate reusable facts before more recon."""
    return (
        "Before making more tool calls, reconcile what you already know from bootstrap and the "
        "latest tool results. If any settled, reusable facts were learned, update the "
        "<known_facts>...</known_facts> block in your next normal reply before asking for more "
        "recon. Do not re-query a tool for a fact you already have unless you first state the "
        "specific ambiguity or missing detail."
    )


def _usage_add(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + int(v)
    return out


# (input $/MTok, output $/MTok, cache_write $/MTok, cache_read $/MTok)
_MODEL_PRICING: list[tuple[str, tuple[float, float, float, float]]] = [
    ("claude-opus-4", (15.0, 75.0, 18.75, 1.50)),
    ("claude-sonnet-4", (3.0, 15.0, 3.75, 0.30)),
    ("claude-haiku-4-5", (0.80, 4.0, 1.00, 0.08)),
    ("claude-haiku-4", (0.80, 4.0, 1.00, 0.08)),
]


def _estimate_cost(u: dict[str, int], model: str) -> float | None:
    rates = None
    for prefix, r in _MODEL_PRICING:
        if prefix in model:
            rates = r
            break
    if rates is None:
        return None
    inp_r, out_r, cw_r, cr_r = rates
    inp = u.get("input_tokens", 0)
    out = u.get("output_tokens", 0)
    cwrite = u.get("cache_creation_input_tokens", 0)
    cread = u.get("cache_read_input_tokens", 0)
    return (inp * inp_r + out * out_r + cwrite * cw_r + cread * cr_r) / 1_000_000


def _format_usage_summary(u: dict[str, int], model: str = "") -> str:
    if not u:
        return "usage: (unavailable)"
    inp = u.get("input_tokens", 0)
    out = u.get("output_tokens", 0)
    cwrite = u.get("cache_creation_input_tokens", 0)
    cread = u.get("cache_read_input_tokens", 0)
    parts = [f"in={inp}", f"out={out}"]
    if cwrite or cread:
        parts.append(f"cache_write={cwrite}")
        parts.append(f"cache_read={cread}")
    cost = _estimate_cost(u, model)
    if cost is not None:
        parts.append(f"est. cost=${cost:.4f}")
    return "usage: " + ", ".join(parts)


def _exploits_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exploits"))


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------


def _checkpoint_path(binary_path: str) -> str:
    stem = _binary_stem(binary_path)
    return os.path.join(os.path.dirname(binary_path), f".autopwn_checkpoint_{stem}.json")


def _serialize_messages(messages: list[dict]) -> list[dict]:
    """Convert Anthropic SDK content block objects to plain dicts for JSON serialization."""
    out: list[dict] = []
    for msg in messages:
        content = msg["content"]
        if isinstance(content, list):
            blocks: list[dict] = []
            for block in content:
                if isinstance(block, dict):
                    blocks.append(block)
                elif hasattr(block, "type"):
                    t = block.type
                    if t == "text":
                        blocks.append({"type": "text", "text": getattr(block, "text", "")})
                    elif t == "tool_use":
                        blocks.append(
                            {
                                "type": "tool_use",
                                "id": getattr(block, "id", ""),
                                "name": getattr(block, "name", ""),
                                "input": dict(getattr(block, "input", {})),
                            }
                        )
                    else:
                        blocks.append({"type": t})
                else:
                    blocks.append({"type": "text", "text": str(block)})
            out.append({"role": msg["role"], "content": blocks})
        else:
            out.append({"role": msg["role"], "content": content})
    return out


def _save_checkpoint(
    path: str,
    *,
    iteration: int,
    messages: list[dict],
    known_facts: list[str],
    known_facts_index: int | None,
    known_facts_insert_at: int,
    base_head_messages: int,
    planner_injected: bool,
    total_usage: dict[str, int],
    all_tool_calls: list[dict],
) -> None:
    data = {
        "iteration": iteration,
        "messages": _serialize_messages(messages),
        "known_facts": known_facts,
        "known_facts_index": known_facts_index,
        "known_facts_insert_at": known_facts_insert_at,
        "base_head_messages": base_head_messages,
        "planner_injected": planner_injected,
        "total_usage": total_usage,
        "all_tool_calls": all_tool_calls,
    }
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"), default=str)
        os.replace(tmp, path)
    except OSError:
        pass


def _load_checkpoint(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _delete_checkpoint(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


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
        _dispatcher: MCPDispatcher | None = None,
    ):
        self.model = model
        self.max_iterations = (
            max_iterations if max_iterations is not None else _default_max_iterations()
        )
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.verbose = verbose
        self._dispatcher = (
            _dispatcher if _dispatcher is not None else MCPDispatcher(verbose=verbose)
        )

    def _run_bootstrap(self, binary_path: str) -> str:
        """Run cheap local analysis tools and optional Ghidra before the ReAct loop.

        Returns a JSON string injected as the bootstrap message so the agent can
        reuse checksec/symbol/string/decompilation results without re-querying.
        """

        def _safe_call(name: str, args: dict) -> Any:
            try:
                return self._dispatcher.call_tool(name, args)
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

        # Run checksec and all independent tool calls in parallel.
        with console.status(
            "[dim]Bootstrap: analyzing binary (checksec, symbols, strings, ldd)...[/dim]",
            spinner="dots",
        ):
            with ThreadPoolExecutor(max_workers=7) as pool:
                f_checksec = pool.submit(_safe_call, "checksec", {"binary_path": binary_path})
                f_plt = pool.submit(
                    self._dispatcher.call_tool,
                    "elf_symbols",
                    {"binary_path": binary_path, "symbol_type": "plt"},
                )
                f_got = pool.submit(
                    self._dispatcher.call_tool,
                    "elf_symbols",
                    {"binary_path": binary_path, "symbol_type": "got"},
                )
                f_strings = pool.submit(
                    self._dispatcher.call_tool,
                    "strings_search",
                    {"binary_path": binary_path, "min_length": 4},
                )
                f_ldd = pool.submit(_safe_cmd, ["ldd", binary_path])
                f_interp = pool.submit(_safe_cmd, ["readelf", "-l", binary_path])

                # elf_symbols(functions) depends on checksec → scope; wrap so it
                # waits internally while the other five tasks run in parallel.
                def _submit_functions() -> Any:
                    scope = _bootstrap_function_symbol_scope(f_checksec.result())
                    return self._dispatcher.call_tool(
                        "elf_symbols",
                        {
                            "binary_path": binary_path,
                            "symbol_type": "functions",
                            "symbol_scope": scope,
                        },
                    )

                f_funcs = pool.submit(_submit_functions)

            checksec_res = f_checksec.result()
            funcs_res = f_funcs.result()
            plt_res = f_plt.result()
            got_res = f_got.result()
            strings_res = f_strings.result()
            ldd_out = f_ldd.result()
            interp_out = f_interp.result()

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
            names_preview = ", ".join(ghidra_names[:8])
            if len(ghidra_names) > 8:
                names_preview += f", … (+{len(ghidra_names) - 8} more)"
            console.print(
                f"[dim]Bootstrap: Ghidra decompile — "
                f"{len(ghidra_names)} functions ({names_preview}), "
                f"timeout {timeout_s}s…[/dim]"
            )
            with console.status("[dim]Bootstrap: running Ghidra...[/dim]", spinner="dots"):
                ghidra_res = _safe_call(
                    "ghidra_decompile",
                    {
                        "binary_path": binary_path,
                        "functions": ghidra_names,
                        "timeout": timeout_s,
                        "max_chars_per_function": per_fn,
                    },
                )
            if isinstance(ghidra_res, dict) and ghidra_res.get("ok"):
                decompiled = list(ghidra_res.get("functions", {}).keys())
                cache_info = ghidra_res.get("cache", {})
                hits = cache_info.get("function_hits", [])
                misses = cache_info.get("function_misses", [])
                missing = [n for n in ghidra_names if n not in decompiled]
                parts = [f"[green]ok[/green] {len(decompiled)}/{len(ghidra_names)} decompiled"]
                if hits:
                    parts.append(f"[dim]{len(hits)} from cache[/dim]")
                if misses:
                    parts.append(f"[dim]{len(misses)} analyzed[/dim]")
                if missing:
                    parts.append(f"[yellow]not found: {', '.join(missing)}[/yellow]")
                console.print("[dim]Ghidra: " + " · ".join(parts) + "[/dim]")
            elif isinstance(ghidra_res, dict):
                console.print(
                    f"[dim][yellow]Ghidra: failed — "
                    f"{ghidra_res.get('error', 'unknown error')}[/yellow][/dim]"
                )

        strategy = None
        if isinstance(checksec_res, dict) and "error" not in checksec_res:
            strategy = plan_from_checksec(checksec_res)
            console.print(
                Panel(
                    f"Strategy: [bold]{strategy.name}[/bold] — {strategy.description}",
                    title="Planner",
                    border_style="magenta",
                )
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
            "strategy": {
                "name": strategy.name,
                "description": strategy.description,
                "technique_hints": strategy.technique_hints,
                "suggested_tools": strategy.suggested_tools,
            }
            if strategy
            else None,
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
        return dumped, strategy is not None

    def solve(
        self,
        binary_path: str,
        remote: str | None = None,
        *,
        user_context: str | None = None,
        fresh: bool = False,
    ) -> AgentResult:
        """Run the full ReAct loop to analyze and exploit a binary.

        ``user_context``: optional free-form text from the operator (CTF story,
        constraints, suspected bug class or solve sketch). Shown to the model before
        bootstrap. Length capped by ``PWN_AGENT_USER_CONTEXT_MAX`` (default 12000).

        ``fresh``: if True, ignore any existing checkpoint and start from scratch.
        """
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            return AgentResult(
                success=False, summary=f"Binary not found: {binary_path}", iterations=0
            )

        try:
            return self._solve(binary_path, remote, user_context=user_context, fresh=fresh)
        finally:
            self._dispatcher.shutdown()

    def _solve(
        self,
        binary_path: str,
        remote: str | None = None,
        *,
        user_context: str | None = None,
        fresh: bool = False,
    ) -> AgentResult:
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
            parts = remote.rsplit(":", 1)
            if len(parts) != 2 or not parts[1].isdigit():
                return AgentResult(
                    success=False,
                    summary=f"Invalid remote target {remote!r}: expected host:port or [ipv6]:port",
                    iterations=0,
                )
            host, port = parts
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

        checkpoint_path = _checkpoint_path(binary_path)
        checkpoint = None if fresh else _load_checkpoint(checkpoint_path)

        if checkpoint:
            resume_iter = checkpoint["iteration"] + 1
            console.print(
                Panel(
                    f"[bold]Resuming from checkpoint[/bold] — "
                    f"iteration {checkpoint['iteration']} of {self.max_iterations} completed\n"
                    f"[dim]Pass --fresh to start over.[/dim]",
                    title="AutoPwn",
                    border_style="yellow",
                )
            )
            messages: list[dict] = checkpoint["messages"]
            known_facts: list[str] = checkpoint["known_facts"]
            known_facts_index: int | None = checkpoint["known_facts_index"]
            known_facts_insert_at: int = checkpoint["known_facts_insert_at"]
            base_head_messages: int = checkpoint["base_head_messages"]
            planner_injected: bool = checkpoint["planner_injected"]
            total_usage: dict[str, int] = checkpoint["total_usage"]
            all_tool_calls: list[dict] = checkpoint["all_tool_calls"]
        else:
            resume_iter = 1
            bootstrap_msg, strategy_injected = self._run_bootstrap(binary_path)

            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Analyze and exploit the binary at `{binary_path}`. "
                        "Start with `checksec` + `elf_symbols` for recon, "
                        "but if bootstrap provides those values, reuse them. "
                        "If bootstrap includes `ghidra_decompile` with ok=true, treat that "
                        "pseudocode as primary source for control flow before writing exploits. "
                        "Whenever bootstrap or a tool result settles reusable facts, update the "
                        "<known_facts>...</known_facts> block in your next normal reply with one "
                        "bullet-style fact per line before asking for more recon. Only include "
                        "settled, reusable facts; omit the block when nothing needs updating. "
                        "Do not re-query tools for facts already present in bootstrap, recent tool "
                        "results, or the known-facts summary unless you first state the unresolved "
                        "ambiguity. "
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

            known_facts = []
            known_facts_insert_at = len(messages)
            known_facts_index = None
            base_head_messages = 3 if user_context else 2
            all_tool_calls = []
            planner_injected = strategy_injected
            total_usage = {}

        for iteration in range(resume_iter, self.max_iterations + 1):
            console.print(f"\n[dim]─── Iteration {iteration}/{self.max_iterations} ───[/dim]")

            # Anthropic sometimes returns 429/529 transient errors. Retry so the
            # agent doesn't crash mid-run and lose context.
            last_exc: Exception | None = None
            with console.status("[bold green]Claude is thinking...[/bold green]", spinner="dots"):
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
                        sleep_s = min(2**attempt, 20) + random.uniform(0, 0.75)
                        console.print(
                            "[dim]Anthropic busy (attempt "
                            f"{attempt}/4). Sleeping {sleep_s:.1f}s...[/dim]"
                        )
                        time.sleep(sleep_s)
            if last_exc is not None:
                raise last_exc

            assistant_content = response.content
            tool_use_blocks = []
            total_usage = _usage_add(total_usage, _usage_to_dict(getattr(response, "usage", None)))

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
                            _format_usage_summary(total_usage, self.model),
                            title="Tokens/Cache",
                            border_style="blue",
                        )
                    )
                _delete_checkpoint(checkpoint_path)
                return AgentResult(
                    success=True,
                    summary=summary,
                    iterations=iteration,
                    exploit_script=last_script,
                    tool_calls=all_tool_calls,
                )

            if tool_use_blocks:
                updated_known_facts_this_turn = any(
                    block.type == "text" and _extract_known_facts_block(block.text)[1] is not None
                    for block in assistant_content
                )
                messages.append({"role": "assistant", "content": assistant_content})
                tool_results = []

                for tool_block in tool_use_blocks:
                    tool_name = tool_block.name
                    tool_input = tool_block.input

                    self._display_tool_call(tool_name, tool_input)

                    with console.status(
                        f"[bold cyan]Running [bold]{tool_name}[/bold]...[/bold cyan]",
                        spinner="dots",
                    ):
                        start = time.time()
                        result = self._dispatcher.call_tool(tool_name, tool_input)
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
                        lp = None
                        if isinstance(script, str) and script.strip():
                            lp = _save_last_attempt_exploit(binary_path, script)
                            console.print(f"[dim]Latest exploit mirrored to {lp}[/dim]")
                        if isinstance(result, dict) and (
                            result.get("flag_detected") or result.get("shell_detected")
                        ):
                            _print_exploit_success_banner(result, lp)

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

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_block.id,
                            "content": result_str,
                        }
                    )

                messages.append({"role": "user", "content": tool_results})
                if not updated_known_facts_this_turn:
                    messages.append(
                        {
                            "role": "user",
                            "content": _known_facts_reconcile_message(),
                        }
                    )
                current_head_messages = base_head_messages + (
                    1 if known_facts_index is not None else 0
                )
                _trim_conversation(messages, head_messages=current_head_messages)

            _save_checkpoint(
                checkpoint_path,
                iteration=iteration,
                messages=messages,
                known_facts=known_facts,
                known_facts_index=known_facts_index,
                known_facts_insert_at=known_facts_insert_at,
                base_head_messages=base_head_messages,
                planner_injected=planner_injected,
                total_usage=total_usage,
                all_tool_calls=all_tool_calls,
            )

            if response.stop_reason == "end_turn" and tool_use_blocks:
                continue

        if self.verbose:
            console.print(
                Panel(
                    _format_usage_summary(total_usage, self.model),
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
            if k == "script":
                lines = val_str.splitlines()
                if len(lines) > 40:
                    val_str = "\n".join(lines[:40]) + f"\n... [{len(lines) - 40} more lines]"
                elif len(val_str) > 2000:
                    val_str = val_str[:2000] + "..."
            elif len(val_str) > 200:
                val_str = val_str[:200] + "..."
            table.add_row(k, val_str)
        console.print(table)

    def _display_known_facts(self, facts: list[str]) -> None:
        body = "\n".join(f"- {fact}" for fact in facts)
        console.print(Panel(body, title="Known Facts", border_style="magenta"))

    def _display_tool_result(self, name: str, result: Any, elapsed: float) -> None:
        result_str = (
            json.dumps(result, indent=2, default=str) if not isinstance(result, str) else result
        )
        if len(result_str) > 2000:
            result_str = result_str[:2000] + "\n... [truncated]"
        console.print(
            Panel(result_str, title=f"Result: {name} ({elapsed:.1f}s)", border_style="yellow")
        )
