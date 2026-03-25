"""Tests for the strategy planner."""

from agent.planner import plan_from_checksec


class TestPlanFromChecksec:
    def test_no_mitigations(self):
        result = plan_from_checksec({
            "canary": False, "nx": False, "pie": False,
            "relro": "No RELRO", "bits": 64,
        })
        assert result.name == "shellcode"
        assert "shellcode_injection" in result.technique_hints

    def test_nx_only(self):
        result = plan_from_checksec({
            "canary": False, "nx": True, "pie": False,
            "relro": "Partial", "bits": 64,
        })
        assert result.name == "rop"
        assert "ret2win" in result.technique_hints or "ret2libc" in result.technique_hints
        assert "got_overwrite" in result.technique_hints

    def test_nx_full_relro(self):
        result = plan_from_checksec({
            "canary": False, "nx": True, "pie": False,
            "relro": "Full", "bits": 64,
        })
        assert result.name == "rop"
        assert "got_overwrite" not in result.technique_hints

    def test_pie_enabled(self):
        result = plan_from_checksec({
            "canary": False, "nx": True, "pie": True,
            "relro": "Full", "bits": 64,
        })
        assert result.name == "pie_ret2libc"
        assert "info_leak_needed" in result.technique_hints
        assert "ret2libc" in result.technique_hints

    def test_canary_present(self):
        result = plan_from_checksec({
            "canary": True, "nx": True, "pie": False,
            "relro": "Full", "bits": 64,
        })
        assert result.name == "canary_bypass"
        assert "canary_leak" in result.technique_hints

    def test_suggested_tools_always_present(self):
        for checksec in [
            {"canary": False, "nx": False, "pie": False, "relro": "No RELRO", "bits": 64},
            {"canary": True, "nx": True, "pie": True, "relro": "Full", "bits": 64},
        ]:
            result = plan_from_checksec(checksec)
            assert len(result.suggested_tools) > 0
            assert "elf_symbols" in result.suggested_tools
