"""Synchronous MCP dispatcher — connects to server subprocesses via stdio transport."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import sys
import threading
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from agent.tools import TOOL_MODULE_MAP

log = logging.getLogger(__name__)

_EXPLOIT_MODULE = "agent.mcp_servers.exploit_tools.server"

# Vars the tool servers need beyond the MCP SDK's minimal safe defaults.
_PASSTHROUGH_VARS = ("GHIDRA_HOME", "PWN_GHIDRA_HOME", "PYTHONPATH", "LD_LIBRARY_PATH")
_PASSTHROUGH_PREFIXES = ("PWN_",)


def _server_env() -> dict[str, str]:
    """Build a subprocess environment: SDK safe defaults + tool-relevant vars, no secrets."""
    from mcp.client.stdio import get_default_environment

    env = get_default_environment()
    for key, value in os.environ.items():
        if key in _PASSTHROUGH_VARS:
            env[key] = value
            continue
        if any(key.startswith(p) for p in _PASSTHROUGH_PREFIXES):
            env[key] = value
    return env


_DYNAMIC_MODULE = "agent.mcp_servers.dynamic_analysis.server"

# Per-call timeout (seconds). Ghidra can take several minutes; run_exploit has its own
# internal timeout. 600 s matches the ghidra_decompile default.
_CALL_TIMEOUT = 600


def _parse_result(result: Any) -> Any:
    """Extract a Python value from a CallToolResult."""
    if result.isError:
        texts = [b.text for b in result.content if getattr(b, "type", None) == "text"]
        return {"error": " ".join(texts) if texts else "MCP tool error"}
    if result.structuredContent is not None:
        return result.structuredContent
    texts = [b.text for b in result.content if getattr(b, "type", None) == "text"]
    if not texts:
        return {}
    combined = "\n".join(texts)
    try:
        return json.loads(combined)
    except json.JSONDecodeError:
        return combined


class MCPDispatcher:
    """Manages two persistent MCP subprocess connections and dispatches tool calls."""

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()

        # Each entry: (stdio_ctx, ClientSession) once connected, None before.
        self._exploit: tuple[Any, ClientSession] | None = None
        self._dynamic: tuple[Any, ClientSession] | None = None
        self._exploit_lock = threading.Lock()
        self._dynamic_lock = threading.Lock()

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._start_lock:
            if self._loop is None:
                self._loop = asyncio.new_event_loop()
                self._thread = threading.Thread(
                    target=self._loop.run_forever, daemon=True
                )
                self._thread.start()
        return self._loop

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    async def _connect(self, module: str) -> tuple[Any, ClientSession]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", module],
            env=_server_env(),
        )
        errlog = sys.stderr if self._verbose else io.StringIO()
        ctx = stdio_client(params, errlog=errlog)
        read, write = await ctx.__aenter__()
        session = ClientSession(read, write)
        await session.__aenter__()
        await session.initialize()
        return ctx, session

    def _ensure_exploit(self) -> ClientSession:
        loop = self._ensure_loop()
        with self._exploit_lock:
            if self._exploit is None:
                future = asyncio.run_coroutine_threadsafe(
                    self._connect(_EXPLOIT_MODULE), loop
                )
                self._exploit = future.result(timeout=30)
        return self._exploit[1]

    def _ensure_dynamic(self) -> ClientSession:
        loop = self._ensure_loop()
        with self._dynamic_lock:
            if self._dynamic is None:
                future = asyncio.run_coroutine_threadsafe(
                    self._connect(_DYNAMIC_MODULE), loop
                )
                self._dynamic = future.result(timeout=30)
        return self._dynamic[1]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def _reset_session(self, module_key: str) -> None:
        if module_key == "exploit":
            with self._exploit_lock:
                self._exploit = None
        else:
            with self._dynamic_lock:
                self._dynamic = None

    def call_tool(self, name: str, arguments: dict) -> Any:
        module_key = TOOL_MODULE_MAP.get(name)
        if module_key is None:
            return {"error": f"Unknown tool: {name}"}

        for attempt in range(2):
            try:
                session = (
                    self._ensure_exploit() if module_key == "exploit" else self._ensure_dynamic()
                )
            except Exception as e:
                log.debug("MCP connect failed for %s: %s", name, e, exc_info=True)
                return {"error": f"MCP connect error: {e}"}

            try:
                future = asyncio.run_coroutine_threadsafe(
                    session.call_tool(name, arguments), self._ensure_loop()
                )
                result = future.result(timeout=_CALL_TIMEOUT)
                return _parse_result(result)
            except Exception as e:
                if attempt == 0:
                    log.debug(
                        "Tool %s failed (%s), reconnecting and retrying",
                        name,
                        type(e).__name__,
                    )
                    self._reset_session(module_key)
                    continue
                log.debug("Tool %s raised %s", name, type(e).__name__, exc_info=True)
                return {"error": f"{type(e).__name__}: {e}"}

        return {"error": "unreachable"}

    def shutdown(self) -> None:
        async def _close() -> None:
            for ctx_session in (self._exploit, self._dynamic):
                if ctx_session is None:
                    continue
                ctx, session = ctx_session
                try:
                    await session.__aexit__(None, None, None)
                except Exception:
                    pass
                try:
                    await ctx.__aexit__(None, None, None)
                except Exception:
                    pass

        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(_close(), self._loop).result(timeout=10)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._loop = None
        self._thread = None
        self._exploit = None
        self._dynamic = None
