"""System prompt assembly for the AutoPwn agent."""
from pathlib import Path


def get_system_prompt() -> str:
    """Build the system prompt from the consolidated knowledge files."""
    knowledge_dir = Path(__file__).resolve().parent / "knowledge"

    parts: list[str] = []
    for name in ("system_prompt.md", "playbooks.md"):
        p = knowledge_dir / name
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8").strip())

    return "\n\n".join([p for p in parts if p])
