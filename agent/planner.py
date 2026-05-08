"""Strategy planner — selects initial exploitation approach based on checksec output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Strategy:
    name: str
    description: str
    suggested_tools: list[str]
    technique_hints: list[str]


_HEAP_FUNC_KEYWORDS = {"alloc", "malloc", "free", "heap", "tcache", "chunk", "note", "edit"}
_HEAP_STRING_KEYWORDS = {"malloc", "tcache", "chunk at", "free()", "alloc", "heap"}


def _looks_like_heap(
    func_names: list[str] | None,
    strings: list[str] | None,
) -> bool:
    """Return True when function names or strings signal a heap challenge."""
    if func_names:
        lower_names = {n.lower() for n in func_names}
        heap_fn_hits = sum(
            1 for kw in _HEAP_FUNC_KEYWORDS if any(kw in n for n in lower_names)
        )
        if heap_fn_hits >= 2:
            return True
    if strings:
        joined = "\n".join(strings).lower()
        if sum(1 for kw in _HEAP_STRING_KEYWORDS if kw in joined) >= 2:
            return True
    return False


def plan_from_checksec(
    checksec_result: dict,
    func_names: list[str] | None = None,
    strings: list[str] | None = None,
) -> Strategy:
    """Given checksec output (and optional function names / strings), suggest a strategy."""
    canary = checksec_result.get("canary", False)
    nx = checksec_result.get("nx", False)
    pie = checksec_result.get("pie", False)
    relro = checksec_result.get("relro", "No RELRO")

    if _looks_like_heap(func_names, strings):
        return Strategy(
            name="heap",
            description=(
                "Heap challenge detected (menu-driven alloc/free/edit) — "
                "identify bug class (UAF, double-free, overflow) from source/decompilation, "
                "check glibc version for tcache/fastbin behaviour, "
                "use heap_safe_link to encode fd pointers."
            ),
            suggested_tools=["elf_symbols", "strings_search", "heap_safe_link", "gdb_run"],
            technique_hints=[
                "tcache_poison",
                "fastbin_dup",
                "house_of_botcake",
                "heap_overflow_tcache_poison",
            ],
        )

    techniques: list[str] = []
    tools: list[str] = ["elf_symbols", "strings_search"]

    if not canary and not nx and not pie:
        techniques.append("shellcode_injection")
        return Strategy(
            name="shellcode",
            description="No mitigations — classic shellcode injection likely works.",
            suggested_tools=tools + ["cyclic_pattern"],
            technique_hints=techniques,
        )

    if not canary and nx and not pie:
        techniques.extend(["ret2win", "ret2libc", "rop_chain"])
        tools.append("rop_gadgets")
        full_relro = relro == "Full"
        if not full_relro:
            techniques.append("got_overwrite")
        return Strategy(
            name="rop",
            description=(
                "NX enabled, no canary, no PIE — use ROP. "
                + (
                    "Full RELRO — GOT is read-only."
                    if full_relro
                    else "Partial RELRO — GOT overwrite possible."
                )
            ),
            suggested_tools=tools + ["cyclic_pattern"],
            technique_hints=techniques,
        )

    if not canary and pie:
        techniques.append("info_leak_needed")

        # Next-tier binaries usually still want ret2libc on PIE+NX.
        if nx:
            techniques.extend(["ret2libc", "pie_base_leak"])
            return Strategy(
                name="pie_ret2libc",
                description=(
                    "PIE enabled + NX — leak PIE base, then use staged ret2libc "
                    "(libc leak -> system)."
                ),
                suggested_tools=tools
                + ["rop_gadgets", "pie_base_from_leak", "libc_symbols", "libc_base_from_leak"],
                technique_hints=techniques,
            )

        techniques.append("partial_overwrite")
        return Strategy(
            name="pie_bypass",
            description="PIE enabled — need an info leak to defeat ASLR before ROP/ret2libc.",
            suggested_tools=tools + ["rop_gadgets"],
            technique_hints=techniques,
        )

    if canary and pie and nx:
        techniques.extend(["canary_leak", "ret2libc", "pie_base_leak"])
        return Strategy(
            name="canary_pie_ret2libc",
            description=(
                "PIE + NX + stack canary — leak canary and PIE base, then perform "
                "staged ret2libc with canary-aware payloads."
            ),
            suggested_tools=tools
            + ["rop_gadgets", "pie_base_from_leak", "libc_symbols", "libc_base_from_leak"],
            technique_hints=techniques,
        )

    if canary:
        techniques.append("canary_leak")
        techniques.append("format_string")
        return Strategy(
            name="canary_bypass",
            description="Stack canary present — need to leak or brute-force the canary.",
            suggested_tools=tools,
            technique_hints=techniques,
        )

    return Strategy(
        name="unknown",
        description=(
            "Could not determine a clear strategy from checksec alone. "
            "Proceed with manual analysis."
        ),
        suggested_tools=tools + ["rop_gadgets"],
        technique_hints=["manual_analysis"],
    )
