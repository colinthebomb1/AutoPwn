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


def test_extract_known_facts_from_ghidra_decompile() -> None:
    from agent.core import _extract_known_facts

    result = {
        "ok": True,
        "functions": {
            "main": {"c": "undefined8 main(void) { game(); syscall(); return 0; }"},
            "game": {
                "c": (
                    "void game(void) { mallic(); freee(); monkey_see(); monkey_do(); "
                    "monkey_swaperoo(); }"
                )
            },
            "monkey_do": {
                "c": (
                    "void monkey_do(void) { char local_28 [24]; "
                    "fgets(local_28,0x28,(FILE *)stdin); }"
                )
            },
            "monkey_see": {
                "c": (
                    "void monkey_see(void) { __isoc99_scanf(x,&local_34); "
                    'printf("\\nThat monkey holds this: 0x%016lx\\n\\n",alStack_28); }'
                )
            },
        },
    }

    facts = _extract_known_facts("ghidra_decompile", {}, result)
    assert any("raw syscall instruction" in fact for fact in facts)
    assert any("menu dispatcher" in fact for fact in facts)
    assert any("overflow primitive" in fact for fact in facts)
    assert any("leak primitive" in fact for fact in facts)


def test_extract_known_facts_from_run_exploit() -> None:
    from agent.core import _extract_known_facts

    facts = _extract_known_facts(
        "run_exploit",
        {},
        {
            "stdout": (
                "That monkey holds this: 0x00007ffc12345678\n"
                "*** stack smashing detected ***: terminated"
            ),
            "stderr": "",
            "timed_out": True,
        },
    )
    assert any("leaks stack-looking values" in fact for fact in facts)
    assert any("stack canary protection" in fact for fact in facts)
    assert any("I/O desync" in fact for fact in facts)


def test_merge_known_facts_deduplicates_and_caps() -> None:
    from agent.core import _merge_known_facts

    merged = _merge_known_facts(
        ["fact a", "fact b"],
        ["fact b", "fact c", "fact d"],
        max_facts=3,
    )
    assert merged == ["fact a", "fact b", "fact c"]


def test_known_facts_message_renders_summary() -> None:
    from agent.core import _known_facts_message

    msg = _known_facts_message(["fact a", "fact b"])
    assert "Known facts summary" in msg
    assert "- fact a" in msg
    assert "- fact b" in msg


def test_display_known_facts_prints_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent.core import AutoPwnAgent

    printed = []
    monkeypatch.setattr("agent.core.console.print", lambda *args, **kwargs: printed.append(args))

    agent = AutoPwnAgent(max_iterations=0, api_key="test", verbose=True)
    agent._display_known_facts(["fact a", "fact b"])

    assert printed


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
