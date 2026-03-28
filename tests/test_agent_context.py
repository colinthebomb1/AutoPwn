"""Unit tests for conversation trimming and tool-result shaping (API cost controls)."""

from __future__ import annotations

import json

import pytest


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

