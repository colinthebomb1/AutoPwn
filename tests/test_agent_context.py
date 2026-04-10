"""Unit tests for conversation trimming and tool-result shaping (API cost controls)."""

from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner


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


def test_trim_conversation_respects_char_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent.core import _trim_conversation

    monkeypatch.setenv("PWN_AGENT_CONTEXT_TURNS", "8")
    monkeypatch.setenv("PWN_AGENT_CONTEXT_MAX_CHARS", "120")
    messages: list[dict] = [
        {"role": "user", "content": "task"},
        {"role": "user", "content": "bootstrap"},
    ]
    for i in range(4):
        messages.append({"role": "assistant", "content": f"a{i}-" + ("x" * 40)})
        messages.append({"role": "user", "content": f"u{i}-" + ("y" * 40)})

    _trim_conversation(messages)

    assert messages[0]["content"] == "task"
    assert messages[1]["content"] == "bootstrap"
    assert len(messages) < 10
    assert messages[-2]["content"].startswith("a3-")
    assert messages[-1]["content"].startswith("u3-")


def test_run_exploit_result_strips_script_from_api_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent.core import _tool_result_str_for_api

    long_script = "x" * 100
    result = {"exit_code": 1, "script": long_script, "stdout": "ok"}
    s = _tool_result_str_for_api("run_exploit", result)
    data = json.loads(s)
    assert "script" not in data
    assert data["stdout"] == "ok"


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


def test_extract_known_facts_block_parses_and_strips_markup() -> None:
    from agent.core import _extract_known_facts_block

    text, facts = _extract_known_facts_block(
        "We have enough to continue.\n"
        "<known_facts>\n"
        "- Canary abort observed\n"
        "- PIE is off\n"
        "</known_facts>\n"
        "Next step: inspect win."
    )

    assert "known_facts" not in text
    assert "Next step" in text
    assert facts == ["Canary abort observed", "PIE is off"]


def test_extract_known_facts_block_returns_none_when_absent() -> None:
    from agent.core import _extract_known_facts_block

    text, facts = _extract_known_facts_block("No memory update in this reply.")

    assert text == "No memory update in this reply."
    assert facts is None


def test_merge_known_facts_deduplicates_and_caps() -> None:
    from agent.core import _merge_known_facts

    merged = _merge_known_facts(
        ["fact a", "fact b"],
        ["fact b", "fact c", "fact d"],
        max_facts=3,
    )
    assert merged == ["fact b", "fact c", "fact d"]


def test_known_facts_message_renders_summary() -> None:
    from agent.core import _known_facts_message

    msg = _known_facts_message(["fact a", "fact b"])
    assert "Known facts summary" in msg
    assert "- fact a" in msg
    assert "- fact b" in msg


def test_sync_known_facts_message_inserts_updates_and_removes() -> None:
    from agent.core import _sync_known_facts_message

    messages = [
        {"role": "user", "content": "task"},
        {"role": "user", "content": "bootstrap"},
        {"role": "assistant", "content": "reply"},
    ]

    idx = _sync_known_facts_message(messages, ["fact a"], insert_at=2, known_facts_index=None)
    assert idx == 2
    assert messages[2]["content"].startswith("Known facts summary")

    idx = _sync_known_facts_message(messages, ["fact b"], insert_at=2, known_facts_index=idx)
    assert idx == 2
    assert "- fact b" in messages[2]["content"]

    idx = _sync_known_facts_message(messages, [], insert_at=2, known_facts_index=idx)
    assert idx is None
    assert all("Known facts summary" not in m["content"] for m in messages)


def test_display_known_facts_prints_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent.core import AutoPwnAgent

    printed = []
    monkeypatch.setattr("agent.core.console.print", lambda *args, **kwargs: printed.append(args))

    agent = AutoPwnAgent(max_iterations=0, api_key="test", verbose=True)
    agent._display_known_facts(["fact a", "fact b"])

    assert printed


def test_get_system_prompt_uses_consolidated_files() -> None:
    from agent.prompts import get_system_prompt

    prompt = get_system_prompt()

    assert "You are AutoPwn, an expert binary exploitation agent." in prompt
    assert "## Technique Playbooks" in prompt
    assert "Pwn knowledge base (operator notes)" not in prompt


def test_cli_verbose_flag_wires_into_agent(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from agent import cli

    binary_path = tmp_path / "fake.bin"
    binary_path.write_bytes(b"\x7fELF")

    captured = {}

    class FakeAgent:
        def __init__(self, model, max_iterations, api_key, verbose):
            captured["model"] = model
            captured["max_iterations"] = max_iterations
            captured["api_key"] = api_key
            captured["verbose"] = verbose

        def solve(self, binary_path, remote=None, user_context=None):
            from agent.core import AgentResult

            captured["binary_path"] = binary_path
            captured["remote"] = remote
            captured["user_context"] = user_context
            return AgentResult(success=False, summary="x", iterations=0, tool_calls=[])

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("agent.core.AutoPwnAgent", FakeAgent)

    runner = CliRunner()
    result = runner.invoke(cli.main, [str(binary_path), "-v", "--notes", "hello"])

    assert result.exit_code == 0
    assert captured["verbose"] is True
    assert captured["binary_path"] == os.path.abspath(str(binary_path))
    assert captured["user_context"] == "hello"
