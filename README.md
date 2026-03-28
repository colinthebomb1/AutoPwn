# pwn-solver

Agentic binary exploitation framework built around an LLM-driven ReAct loop, MCP tool servers, and pwntools execution.

`pwn-solver` analyzes ELF binaries, chooses exploitation strategies based on mitigations, and iterates toward working exploits with built-in dynamic-analysis and exploit-generation tools.

## Features

- ReAct-style exploitation loop with tool use (`checksec`, symbols, gadgets, GDB, exploit execution)
- MCP-backed tool servers for:
  - static/recon helpers (ELF symbols, strings, libc offsets, payload builders)
  - dynamic debugging helpers (GDB breakpoint/run/stack/vmmap)
- Exploit runner with machine-readable success signals (`shell_detected`, `flag_detected`)
- Prompt + knowledge-base driven strategy guidance
- Test suite with challenge fixtures for ret2win/ret2libc/format/shellcode workflows

## Project Layout

- `agent/` - ReAct loop, prompts, planner, CLI entrypoint
- `mcp-servers/` - MCP tool servers (`exploit-tools`, `dynamic-analysis`)
- `tests/` - unit/integration tests + challenge binaries/sources
- `exploits/` - generated solve scripts and latest attempt mirrors

## Requirements

- Python 3.11+
- `gdb` available for dynamic-analysis tools
- optional: `pwntools` extras for exploit workflows
- optional: [Ghidra](https://ghidra-sre.org/) + a JDK for the `ghidra_decompile` tool (set `GHIDRA_HOME` / `PWN_GHIDRA_HOME`; put `java` on `PATH` or set `JAVA_HOME` / `PWN_JAVA_HOME`)

## Installation

```bash
git clone https://github.com/colinthebomb1/pwn-solver.git
cd pwn-solver
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,pwn]"
```

## Configuration

Copy `.env.example` to `.env` and set at least:

- `ANTHROPIC_API_KEY` (required)

Optional knobs:

- `PWN_AGENT_MAX_ITERATIONS` (default: `30`)
- `PWN_AGENT_CONTEXT_TURNS`
- `PWN_AGENT_TOOL_RESULT_MAX`
- `PWN_AGENT_RUN_EXPLOIT_SCRIPT_SNIP`
- `PWN_AGENT_MAX_OUTPUT_TOKENS`
- `PWN_AGENT_BOOTSTRAP_GHIDRA` (default: `1`) — run headless Ghidra once at startup; set `0` to skip
- `PWN_AGENT_BOOTSTRAP_MAX_CHARS_WITH_GHIDRA` — larger bootstrap JSON cap when decompilation succeeds (default `12000`)
- `JAVA_HOME` or `PWN_JAVA_HOME` — if `java` is not on your `PATH` (common in some venvs/IDE launches), point at a JDK so Ghidra can start

## Quick Start

Run against a local challenge binary:

```bash
pwn-solver tests/challenges/ret2win_x64
```

Override model / iteration budget:

```bash
pwn-solver tests/challenges/ret2libc_real_x64 -m claude-sonnet-4-20250514 -n 20
```

Use remote target:

```bash
pwn-solver ./chall -r host:port
```

## Testing

Run all tests:

```bash
pytest -q
```

In constrained environments where PTYs are limited, skip dynamic GDB tests:

```bash
pytest -q --ignore=tests/test_mcp_dynamic.py
```

## Notes

- Latest attempted exploit is mirrored to `exploits/last_attempt_<binary>.py`.
- Successful solves save to `exploits/solve_<binary>.py`.
- The framework is intended for CTF/research and controlled targets you are authorized to test.

## License

MIT
