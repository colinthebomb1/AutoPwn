"""System prompts and tool descriptions for the AutoPwn agent."""

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
