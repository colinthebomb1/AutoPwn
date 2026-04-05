"""Unit tests for conversation trimming and tool-result shaping (API cost controls)."""

from __future__ import annotations

import json

import pytest


def test_solve_bootstrap_calls_elf_symbols_with_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from agent.core import AutoPwnAgent

    binary_path = tmp_path / "fake.bin"
    binary_path.write_bytes(b"\x7fELF")

    tool_calls: list[tuple[str, dict]] = []

    def fake_call_tool(name: str, arguments: dict):
        tool_calls.append((name, arguments))
        if name == "checksec":
            return {"pie": False, "runpath": None, "rpath": None}
        if name == "elf_symbols":
            return {"functions": {"main": "0x401000"}}
        if name == "strings_search":
            return []
        return {"ok": True}

    monkeypatch.setattr("agent.core._call_tool", fake_call_tool)
    monkeypatch.setenv("PWN_AGENT_BOOTSTRAP_GHIDRA", "0")

    agent = AutoPwnAgent(max_iterations=0, api_key="test")
    result = agent.solve(str(binary_path))

    assert result.success is False
    assert ("checksec", {"binary_path": str(binary_path)}) in tool_calls
    assert (
        "elf_symbols",
        {
            "binary_path": str(binary_path),
            "symbol_type": "functions",
            "symbol_scope": "user",
        },
    ) in tool_calls


def test_trim_conversation_keeps_bootstrap_and_recent_turns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent.core import _trim_conversation

    monkeypatch.setenv("PWN_AGENT_CONTEXT_TURNS", "3")
    messages: list[dict] = [
        {"role": "user", "content": "task"},
        {"role": "user", "content": "bootstrap"},
    ]
    for i in range(8):
        messages.append({"role": "assistant", "content": f"a{i}"})
        messages.append({"role": "user", "content": f"u{i}"})
    assert len(messages) == 18
    _trim_conversation(messages)
    assert len(messages) == 8
    assert messages[0]["content"] == "task"
    assert messages[1]["content"] == "bootstrap"
    assert messages[-2]["content"] == "a7"
    assert messages[-1]["content"] == "u7"


def test_trim_conversation_three_head_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    """When operator notes are present, task + notes + bootstrap stay fixed (head_messages=3)."""
    from agent.core import _trim_conversation

    monkeypatch.setenv("PWN_AGENT_CONTEXT_TURNS", "3")
    messages: list[dict] = [
        {"role": "user", "content": "task"},
        {"role": "user", "content": "operator notes"},
        {"role": "user", "content": "bootstrap"},
    ]
    for i in range(8):
        messages.append({"role": "assistant", "content": f"a{i}"})
        messages.append({"role": "user", "content": f"u{i}"})
    _trim_conversation(messages, head_messages=3)
    assert len(messages) == 9
    assert messages[0]["content"] == "task"
    assert messages[1]["content"] == "operator notes"
    assert messages[2]["content"] == "bootstrap"
    assert messages[-2]["content"] == "a7"
    assert messages[-1]["content"] == "u7"


def test_run_exploit_result_truncates_script_in_api_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent.core import _tool_result_str_for_api

    monkeypatch.setenv("PWN_AGENT_RUN_EXPLOIT_SCRIPT_SNIP", "20")
    long_script = "x" * 100
    result = {"exit_code": 1, "script": long_script, "stdout": "ok"}
    s = _tool_result_str_for_api("run_exploit", result)
    data = json.loads(s)
    assert len(data["script"]) < len(long_script)
    assert "truncated" in data["script"]


def test_operator_notes_message_treats_constraints_as_binding() -> None:
    from agent.core import _operator_notes_message

    msg = _operator_notes_message("Do not use gdb_run. Focus on user-created functions.")
    assert "binding for this run" in msg
    assert "If you need to violate a note" in msg
    assert "Do not use gdb_run" in msg


def test_bootstrap_function_symbol_scope_prefers_user_for_static_binaries() -> None:
    from agent.core import _bootstrap_function_symbol_scope

    assert (
        _bootstrap_function_symbol_scope({"pie": False, "runpath": None, "rpath": None})
        == "user"
    )
    assert (
        _bootstrap_function_symbol_scope({"pie": True, "runpath": None, "rpath": None})
        == "all"
    )
    assert (
        _bootstrap_function_symbol_scope({"pie": False, "runpath": "/tmp/lib", "rpath": None})
        == "all"
    )
