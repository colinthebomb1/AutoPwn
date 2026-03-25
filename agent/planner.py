"""Strategy planner — selects initial exploitation approach based on checksec output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Strategy:
    name: str
    description: str
    suggested_tools: list[str]
    technique_hints: list[str]


def plan_from_checksec(checksec_result: dict) -> Strategy:
    """Given checksec output, suggest an initial exploitation strategy."""
    canary = checksec_result.get("canary", False)
    nx = checksec_result.get("nx", False)
    pie = checksec_result.get("pie", False)
    relro = checksec_result.get("relro", "No RELRO")
    bits = checksec_result.get("bits", 64)

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
                f"NX enabled, no canary, no PIE — use ROP. "
                f"{'Full RELRO — GOT is read-only.' if full_relro else 'Partial RELRO — GOT overwrite possible.'}"
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
                description="PIE enabled + NX — leak PIE base, then use staged ret2libc (libc leak -> system).",
                suggested_tools=tools + ["rop_gadgets", "pie_base_from_leak", "libc_symbols", "libc_base_from_leak"],
                technique_hints=techniques,
            )

        techniques.append("partial_overwrite")
        return Strategy(
            name="pie_bypass",
            description="PIE enabled — need an info leak to defeat ASLR before ROP/ret2libc.",
            suggested_tools=tools + ["rop_gadgets"],
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
        description="Could not determine a clear strategy from checksec alone. Proceed with manual analysis.",
        suggested_tools=tools + ["rop_gadgets"],
        technique_hints=["manual_analysis"],
    )
