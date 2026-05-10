"""Tests for the strategy planner."""

from agent.planner import plan_from_checksec


class TestPlanFromChecksec:
    def test_no_mitigations(self):
        result = plan_from_checksec(
            {
                "canary": False,
                "nx": False,
                "pie": False,
                "relro": "No RELRO",
                "bits": 64,
            }
        )
        assert result.name == "shellcode"
        assert "shellcode_injection" in result.technique_hints

    def test_nx_only(self):
        result = plan_from_checksec(
            {
                "canary": False,
                "nx": True,
                "pie": False,
                "relro": "Partial",
                "bits": 64,
            }
        )
        assert result.name == "rop"
        assert "ret2win" in result.technique_hints or "ret2libc" in result.technique_hints
        assert "got_overwrite" in result.technique_hints

    def test_nx_full_relro(self):
        result = plan_from_checksec(
            {
                "canary": False,
                "nx": True,
                "pie": False,
                "relro": "Full",
                "bits": 64,
            }
        )
        assert result.name == "rop"
        assert "got_overwrite" not in result.technique_hints

    def test_pie_enabled(self):
        result = plan_from_checksec(
            {
                "canary": False,
                "nx": True,
                "pie": True,
                "relro": "Full",
                "bits": 64,
            }
        )
        assert result.name == "pie_ret2libc"
        assert "info_leak_needed" in result.technique_hints
        assert "ret2libc" in result.technique_hints

    def test_canary_present(self):
        result = plan_from_checksec(
            {
                "canary": True,
                "nx": True,
                "pie": False,
                "relro": "Full",
                "bits": 64,
            }
        )
        assert result.name == "canary_bypass"
        assert "canary_leak" in result.technique_hints

    def test_canary_pie_nx(self):
        result = plan_from_checksec(
            {
                "canary": True,
                "nx": True,
                "pie": True,
                "relro": "Full",
                "bits": 64,
            }
        )
        assert result.name == "canary_pie_ret2libc"
        assert "canary_leak" in result.technique_hints
        assert "ret2libc" in result.technique_hints

    def test_suggested_tools_always_present(self):
        for checksec in [
            {"canary": False, "nx": False, "pie": False, "relro": "No RELRO", "bits": 64},
            {"canary": True, "nx": True, "pie": True, "relro": "Full", "bits": 64},
        ]:
            result = plan_from_checksec(checksec)
            assert len(result.suggested_tools) > 0
            assert "elf_symbols" in result.suggested_tools

    # --- heap detection --------------------------------------------------

    _HEAP_CHECKSEC = {"canary": False, "nx": True, "pie": False, "relro": "Partial", "bits": 64}

    def test_heap_detected_via_func_names(self):
        result = plan_from_checksec(
            self._HEAP_CHECKSEC,
            func_names=["do_alloc", "do_free", "do_edit", "do_show", "main"],
        )
        assert result.name == "heap"
        assert "heap_safe_link" in result.suggested_tools
        assert any("tcache" in h or "fastbin" in h for h in result.technique_hints)
        assert "poison_null_byte" in result.technique_hints

    def test_heap_detected_via_strings(self):
        result = plan_from_checksec(
            self._HEAP_CHECKSEC,
            strings=["fake_chunk at 0x404060", "1) alloc  2) free  3) edit", "chunk at %p"],
        )
        assert result.name == "heap"

    def test_heap_not_falsely_triggered(self):
        # Single keyword in func names should not trigger heap classification.
        result = plan_from_checksec(
            self._HEAP_CHECKSEC,
            func_names=["main", "vuln", "win"],
        )
        assert result.name == "rop"

    def test_heap_overrides_rop_classification(self):
        # Same mitigations as a ROP binary, but heap functions present → heap wins.
        result = plan_from_checksec(
            {"canary": False, "nx": True, "pie": False, "relro": "Partial", "bits": 64},
            func_names=["main", "do_alloc", "do_free", "do_edit"],
        )
        assert result.name == "heap"

    def test_heap_full_relro_suggests_fsop(self):
        result = plan_from_checksec(
            {"canary": False, "nx": True, "pie": False, "relro": "Full", "bits": 64},
            func_names=["do_alloc", "do_free", "do_edit", "do_show", "get_shell"],
        )
        assert result.name == "heap"
        assert "libc_fsop_targets" in result.suggested_tools
        assert "house_of_apple2" in result.technique_hints
        assert "fsop" in result.technique_hints

    def test_heap_partial_relro_no_fsop_hint(self):
        result = plan_from_checksec(
            {"canary": False, "nx": True, "pie": False, "relro": "Partial", "bits": 64},
            func_names=["do_alloc", "do_free", "do_edit", "do_show"],
        )
        assert result.name == "heap"
        assert "libc_fsop_targets" not in result.suggested_tools
        assert "house_of_apple2" not in result.technique_hints
        assert "fsop" not in result.technique_hints
