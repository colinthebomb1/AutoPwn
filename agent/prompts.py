"""System prompt and playbook assembly for the AutoPwn agent."""

from pathlib import Path
from typing import Any

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"
PLAYBOOK_CORPUS = KNOWLEDGE_DIR / "playbooks.md"

PLAYBOOKS: dict[str, dict[str, str]] = {
    "stack_layout": {
        "title": "Stack layout and canary basics",
        "start": "## Stack layout",
        "end": "## Technique Playbooks",
    },
    "ret2win": {
        "title": "ret2win",
        "start": "### ret2win",
        "end": "### ret2libc",
    },
    "ret2libc": {
        "title": "ret2libc and staged libc leaks",
        "start": "### ret2libc",
        "end": "### Static i386",
    },
    "static_i386": {
        "title": "Static i386 no /bin/sh",
        "start": "### Static i386",
        "end": "### Shellcode",
    },
    "shellcode": {
        "title": "Shellcode when NX is off",
        "start": "### Shellcode",
        "end": "### Format string",
    },
    "format_string": {
        "title": "Format string leaks and writes",
        "start": "### Format string",
        "end": "### Canary leak",
    },
    "canary": {
        "title": "Canary leak",
        "start": "### Canary leak",
        "end": "### Heap",
    },
    "heap_tcache": {
        "title": "Heap tcache/UAF and fastbin dup",
        "start": "### Heap",
        "end": "**House of Botcake",
    },
    "heap_botcake": {
        "title": "House of Botcake",
        "start": "**House of Botcake",
        "end": "**Heap overflow",
    },
    "heap_overflow_tcache": {
        "title": "Heap overflow to tcache poison",
        "start": "**Heap overflow",
        "end": "**Poison null byte",
    },
    "heap_poison_null_byte": {
        "title": "Poison null byte / House of Einherjar",
        "start": "**Poison null byte",
        "end": "**House of Apple 2",
    },
    "heap_apple2_fsop": {
        "title": "House of Apple 2 / FSOP",
        "start": "**House of Apple 2",
        "end": "## GDB / dynamic analysis",
    },
    "gdb_dynamic": {
        "title": "GDB, mitigations, and bootstrap usage",
        "start": "## GDB / dynamic analysis",
        "end": None,
    },
}


def _read_knowledge_file(name: str) -> str:
    path = KNOWLEDGE_DIR / name
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def _playbook_corpus() -> str:
    return PLAYBOOK_CORPUS.read_text(encoding="utf-8")


def available_playbooks() -> dict[str, str]:
    """Return playbook IDs and titles for tool schemas/prompts."""
    return {pid: meta["title"] for pid, meta in PLAYBOOKS.items()}


def _extract_playbook_text(playbook_id: str) -> str:
    meta = PLAYBOOKS.get(playbook_id)
    if meta is None:
        raise KeyError(playbook_id)

    corpus = _playbook_corpus()
    start = corpus.find(meta["start"])
    if start < 0:
        raise ValueError(f"playbook marker not found: {meta['start']}")

    end_marker = meta.get("end")
    end = len(corpus)
    if end_marker:
        found = corpus.find(end_marker, start + len(meta["start"]))
        if found >= 0:
            end = found

    return corpus[start:end].strip()


def load_playbook(playbook_id: str) -> dict[str, Any]:
    """Load one detailed playbook by ID for dynamic agent requests."""
    if playbook_id not in PLAYBOOKS:
        return {
            "error": f"Unknown playbook_id: {playbook_id}",
            "available": available_playbooks(),
        }
    text = _extract_playbook_text(playbook_id)
    return {
        "id": playbook_id,
        "title": PLAYBOOKS[playbook_id]["title"],
        "text": text,
        "chars": len(text),
    }


def get_playbook_index() -> str:
    """Compact always-loaded index that lets the agent request more detail."""
    lines = [
        "## Playbook Index",
        "",
        "Detailed playbooks are loaded selectively to control CTF solve costs. "
        "Use the loaded playbooks first. If later tool results prove a different "
        "technique is needed, call `load_playbook` with one of these IDs:",
    ]
    for pid, title in available_playbooks().items():
        lines.append(f"- `{pid}`: {title}")
    return "\n".join(lines)


def get_base_system_prompt() -> str:
    """Build the small cached base system prompt plus playbook index."""
    parts = [_read_knowledge_file("system_prompt.md"), get_playbook_index()]
    return "\n\n".join([p for p in parts if p])


def render_selected_playbooks(playbook_ids: list[str]) -> str:
    """Render selected detailed playbooks in deterministic order."""
    unique_ids = [pid for pid in PLAYBOOKS if pid in set(playbook_ids)]
    if not unique_ids:
        return ""

    parts = [
        "## Loaded Detailed Playbooks",
        "",
        "These playbooks were preselected from bootstrap/planner facts and are "
        "available in the cached prompt prefix for this run.",
    ]
    for pid in unique_ids:
        loaded = load_playbook(pid)
        if "text" in loaded:
            parts.append(f"\n<!-- playbook:{pid} -->\n{loaded['text']}")
    return "\n\n".join(parts).strip()


def _joined_lower(values: list[str] | None) -> str:
    if not values:
        return ""
    return "\n".join(str(v) for v in values).lower()


def select_playbooks(
    *,
    binary_path: str = "",
    checksec: dict | None = None,
    strategy: Any = None,
    func_names: list[str] | None = None,
    strings: list[str] | None = None,
) -> list[str]:
    """Select a small deterministic playbook set from bootstrap/planner facts."""
    selected: list[str] = []

    def add(*ids: str) -> None:
        for pid in ids:
            if pid in PLAYBOOKS and pid not in selected:
                selected.append(pid)

    checksec = checksec or {}
    hints = list(getattr(strategy, "technique_hints", []) or [])
    strategy_name = str(getattr(strategy, "name", "") or "")
    evidence_text = "\n".join(
        [
            binary_path.lower(),
            strategy_name.lower(),
            _joined_lower(func_names),
            _joined_lower(strings),
        ]
    )
    hint_text = " ".join(h.lower() for h in hints)
    text = evidence_text + "\n" + hint_text

    if (
        "format" in evidence_text
        or "%n" in evidence_text
        or ("printf(buf)" in evidence_text or "printf(user" in evidence_text)
    ):
        add("format_string")

    if checksec.get("canary"):
        add("stack_layout", "canary")

    if "heap" in strategy_name or any(word in text for word in ("alloc", "free", "chunk", "heap")):
        add("heap_tcache")
        if any(word in evidence_text for word in ("botcake", "double-free", "double free")):
            add("heap_botcake")
        if any(word in evidence_text for word in ("overflow", "is_admin")):
            add("heap_overflow_tcache")
        if any(
            word in evidence_text for word in ("poison_null", "poison null", "einherjar", "overlap")
        ):
            add("heap_poison_null_byte")
        if checksec.get("relro") == "Full" or any(
            word in evidence_text for word in ("apple2", "fsop")
        ):
            add("heap_apple2_fsop")
        return selected[:3]

    if checksec.get("nx") is False:
        add("shellcode")
    elif checksec:
        add("ret2libc")
        if not checksec.get("canary") and not checksec.get("pie"):
            add("ret2win")

    if "static" in text and "i386" in text:
        add("static_i386")

    return selected[:3]


def get_system_prompt(selected_playbooks: list[str] | None = None) -> str:
    """Build prompt text for tests/backward-compatible callers."""
    parts = [get_base_system_prompt()]
    if selected_playbooks:
        parts.append(render_selected_playbooks(selected_playbooks))
    return "\n\n".join([p for p in parts if p])
