"""System prompts and tool descriptions for the pwn-solver agent."""

from pathlib import Path


def get_system_prompt() -> str:
    """Full system prompt including optional bundled knowledge file (see `agent/knowledge/`)."""
    knowledge_dir = Path(__file__).resolve().parent / "knowledge"

    parts: list[str] = []
    for name in ("system_intro.md", "system_playbooks.md", "system_rules.md"):
        p = knowledge_dir / name
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8").strip())

    kb = knowledge_dir / "pwn_notes.md"
    if kb.is_file():
        parts.append("---\n\n## Bundled knowledge base\n\n" + kb.read_text(encoding="utf-8").strip())

    return "\n\n".join([p for p in parts if p])


def format_tool_result(tool_name: str, result: object) -> str:
    """Format a tool result for inclusion in the conversation."""
    import json

    if isinstance(result, dict):
        formatted = json.dumps(result, separators=(",", ":"), default=str)
    elif isinstance(result, list):
        formatted = json.dumps(result, separators=(",", ":"), default=str)
    else:
        formatted = str(result)

    if len(formatted) > 4500:
        formatted = formatted[:4500] + "\n... [truncated]"

    return formatted
