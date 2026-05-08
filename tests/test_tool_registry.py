"""Sanity checks that TOOL_REGISTRY and TOOL_MODULE_MAP stay in sync."""

import importlib

from agent.tools import TOOL_MODULE_MAP, TOOL_REGISTRY


class TestToolRegistrySync:
    def test_registry_and_module_map_same_keys(self):
        assert set(TOOL_REGISTRY.keys()) == set(TOOL_MODULE_MAP.keys()), (
            "TOOL_REGISTRY and TOOL_MODULE_MAP are out of sync.\n"
            f"  Only in TOOL_REGISTRY:  {set(TOOL_REGISTRY) - set(TOOL_MODULE_MAP)}\n"
            f"  Only in TOOL_MODULE_MAP: {set(TOOL_MODULE_MAP) - set(TOOL_REGISTRY)}"
        )

    def test_all_tools_resolve_to_callable(self):
        module_objects = {
            "exploit": importlib.import_module("agent.mcp_servers.exploit_tools.server"),
            "dynamic": importlib.import_module("agent.mcp_servers.dynamic_analysis.server"),
        }
        missing = []
        for tool_name, module_key in TOOL_MODULE_MAP.items():
            mod = module_objects.get(module_key)
            if mod is None:
                missing.append(f"{tool_name}: unknown module key {module_key!r}")
                continue
            if not callable(getattr(mod, tool_name, None)):
                missing.append(f"{tool_name}: not found in {module_key} module")
        assert not missing, (
            "Some tools in TOOL_MODULE_MAP don't resolve to callables:\n" + "\n".join(missing)
        )

    def test_registry_entries_have_required_fields(self):
        for name, spec in TOOL_REGISTRY.items():
            assert "description" in spec, f"{name}: missing 'description'"
            assert "input_schema" in spec, f"{name}: missing 'input_schema'"
            schema = spec["input_schema"]
            assert schema.get("type") == "object", f"{name}: input_schema type must be 'object'"
            assert "properties" in schema, f"{name}: input_schema missing 'properties'"
