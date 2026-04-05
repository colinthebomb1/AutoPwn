"""Tool registry and module routing for the AutoPwn agent."""

from __future__ import annotations

from typing import Any

# Maps tool name → which module provides it
TOOL_MODULE_MAP: dict[str, str] = {
    "checksec": "exploit",
    "elf_symbols": "exploit",
    "elf_search": "exploit",
    "rop_gadgets": "exploit",
    "cyclic_pattern": "exploit",
    "strings_search": "exploit",
    "shellcraft_generate": "exploit",
    "libc_symbols": "exploit",
    "libc_base_from_leak": "exploit",
    "pie_base_from_leak": "exploit",
    "ret2libc_stage1_payload": "exploit",
    "ret2libc_stage2_payload": "exploit",
    "format_string_payload": "exploit",
    "ghidra_decompile": "exploit",
    "run_exploit": "exploit",
    "gdb_find_offset": "dynamic",
    "gdb_run": "dynamic",
    "gdb_breakpoint": "dynamic",
    "gdb_examine": "dynamic",
    "gdb_vmmap": "dynamic",
    "gdb_stack": "dynamic",
}


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    # --- Exploit tools ---
    "checksec": {
        "description": "Run checksec on a binary to identify security mitigations (RELRO, Canary, NX, PIE). Call this FIRST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
            },
            "required": ["binary_path"],
        },
    },
    "elf_symbols": {
        "description": "List symbols from an ELF binary: functions, PLT, GOT, and sections. On static binaries, prefer the default auto/user-focused scope unless you truly need runtime noise.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "symbol_type": {
                    "type": "string",
                    "enum": ["all", "functions", "plt", "got"],
                    "description": "Type of symbols to list. Defaults to 'all'.",
                },
                "symbol_scope": {
                    "type": "string",
                    "enum": ["auto", "all", "user"],
                    "description": "Function filtering scope. 'auto' defaults to 'user' on static binaries; use 'all' only when you explicitly need libc/runtime symbols.",
                },
            },
            "required": ["binary_path"],
        },
    },
    "elf_search": {
        "description": "Search for a byte pattern in an ELF binary and return virtual addresses. Essential for finding '/bin/sh' addresses for ROP chains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search_string": {
                    "type": "string",
                    "description": "The string or hex bytes to search for. e.g. '/bin/sh' or '5fc3'",
                },
                "search_type": {
                    "type": "string",
                    "enum": ["string", "hex"],
                    "description": "'string' for ASCII, 'hex' for raw bytes. Default 'string'.",
                },
            },
            "required": ["binary_path", "search_string"],
        },
    },
    "rop_gadgets": {
        "description": "Search for ROP gadgets in a binary. Uses pwntools ROP engine plus raw byte-pattern search for common gadgets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search": {
                    "type": "string",
                    "description": "Filter string (e.g. 'pop rdi', 'ret'). If omitted, returns all gadgets.",
                },
                "max_results": {"type": "integer", "description": "Max gadgets to return. Default 50."},
            },
            "required": ["binary_path"],
        },
    },
    "cyclic_pattern": {
        "description": "Generate or query a De Bruijn cyclic pattern for finding buffer overflow offsets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["generate", "find"],
                    "description": "'generate' to create a pattern, 'find' to locate offset of a crash value.",
                },
                "length": {"type": "integer", "description": "Pattern length in bytes (for generate). Default 200."},
                "value": {"type": "string", "description": "Hex value to find (for find action), e.g. '0x61616168'."},
            },
            "required": ["action"],
        },
    },
    "strings_search": {
        "description": "Extract printable strings from a binary. Defaults to a curated, capped result set to avoid noisy static-binary dumps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "min_length": {"type": "integer", "description": "Minimum string length. Default 4."},
                "encoding": {
                    "type": "string",
                    "enum": ["ascii", "unicode"],
                    "description": "String encoding. Defaults to 'ascii'.",
                },
                "interesting_only": {
                    "type": "boolean",
                    "description": "When true, filter out most low-signal assembly-ish fragments. Defaults to true.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of strings to return after filtering. Default 200.",
                },
            },
            "required": ["binary_path"],
        },
    },
    "shellcraft_generate": {
        "description": (
            "Generate shellcode via pwntools shellcraft. Prefer exploit_lines (asm(shellcraft...)); "
            "use exploit_lines_hex if the transcript mangles shellcraft."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "payload_type": {
                    "type": "string",
                    "enum": ["sh", "cat_flag", "execve", "nop_sled"],
                    "description": "Type of shellcode: 'sh' for /bin/sh shell, 'cat_flag' to read flag.txt, 'execve' same as sh, 'nop_sled' for NOP padding.",
                },
                "arch": {
                    "type": "string",
                    "enum": ["amd64", "i386"],
                    "description": "Target architecture. Default 'amd64'.",
                },
            },
            "required": ["payload_type"],
        },
    },
    "libc_symbols": {
        "description": "Resolve useful libc symbol offsets and /bin/sh offset from a libc .so file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "libc_path": {"type": "string", "description": "Path to libc shared object."},
                "symbols": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional symbol names. Defaults to puts/system/__libc_start_main.",
                },
            },
            "required": ["libc_path"],
        },
    },
    "libc_base_from_leak": {
        "description": "Compute libc base from one leaked symbol address and return resolved runtime addresses (system, /bin/sh).",
        "input_schema": {
            "type": "object",
            "properties": {
                "libc_path": {"type": "string", "description": "Path to libc shared object."},
                "leaked_symbol": {"type": "string", "description": "Leaked symbol name, e.g. puts."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
            },
            "required": ["libc_path", "leaked_symbol", "leaked_address"],
        },
    },
    "pie_base_from_leak": {
        "description": "Compute PIE base from one leaked symbol address (pie_base = leak - elf.symbols[symbol]).",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target PIE ELF path."},
                "leaked_symbol": {"type": "string", "description": "Symbol name you leaked (e.g. 'main')."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
            },
            "required": ["binary_path", "leaked_symbol", "leaked_address"],
        },
    },
    "ret2libc_stage1_payload": {
        "description": "Build stage-1 payload: leak GOT via puts@plt and return to main/vuln for a second stage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target ELF path."},
                "offset": {"type": "integer", "description": "Overflow offset to saved RIP."},
                "leak_symbol": {"type": "string", "description": "Imported symbol to leak. Default puts."},
                "reentry_symbol": {"type": "string", "description": "Symbol to return to after leak. Default main."},
                "pie_base": {"type": "string", "description": "Optional PIE base as hex/int string. If omitted, treated as 0."},
                "canary": {"type": "string", "description": "Optional leaked stack canary as hex/int string (e.g. 0xdeadbeef...)."},
                "canary_offset": {"type": "integer", "description": "Byte offset from input start to canary slot (required if canary is provided)."},
                "saved_rbp": {"type": "string", "description": "Optional saved RBP value to place after canary. Default 0x0."},
            },
            "required": ["binary_path", "offset"],
        },
    },
    "ret2libc_stage2_payload": {
        "description": "Build stage-2 payload: compute libc base from leak and call system('/bin/sh').",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target ELF path."},
                "libc_path": {"type": "string", "description": "Libc path used by target."},
                "offset": {"type": "integer", "description": "Overflow offset to saved RIP."},
                "leaked_symbol": {"type": "string", "description": "Symbol name used for base calc (e.g. puts)."},
                "leaked_address": {"type": "string", "description": "Leaked runtime address as hex/int string."},
                "pie_base": {"type": "string", "description": "Optional PIE base as hex/int string. If omitted, treated as 0."},
                "canary": {"type": "string", "description": "Optional leaked stack canary as hex/int string (e.g. 0xdeadbeef...)."},
                "canary_offset": {"type": "integer", "description": "Byte offset from input start to canary slot (required if canary is provided)."},
                "saved_rbp": {"type": "string", "description": "Optional saved RBP value to place after canary. Default 0x0."},
            },
            "required": ["binary_path", "libc_path", "offset", "leaked_symbol", "leaked_address"],
        },
    },
    "ghidra_decompile": {
        "description": (
            "Decompile specific functions to Ghidra pseudocode (C-like) via local headless Ghidra. "
            "The agent bootstrap often runs this already for a bounded set of symbols — check "
            "bootstrap `ghidra_decompile` before repeating. Use for extra functions or after "
            "bootstrap truncation. Requires GHIDRA_HOME (or PWN_GHIDRA_HOME) and Java. "
            "Pass symbol names (e.g. main, vuln, handler_fn)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF or binary"},
                "functions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Function/symbol names to decompile (e.g. main, vuln).",
                },
                "ghidra_home": {
                    "type": "string",
                    "description": "Optional Ghidra install root (overrides GHIDRA_HOME / PWN_GHIDRA_HOME).",
                },
                "timeout": {
                    "type": "integer",
                    "description": "analyzeHeadless timeout in seconds. Default 600.",
                },
                "max_chars_per_function": {
                    "type": "integer",
                    "description": "Trim long decompilation text. Default 24000.",
                },
            },
            "required": ["binary_path", "functions"],
        },
    },
    "format_string_payload": {
        "description": (
            "Generate a format string write payload (pwntools fmtstr_payload). "
            "Prefer exploit_lines (readable fmtstr_payload call). Use exploit_lines_hex / payload_hex "
            "only if the model corrupts specifiers — never hand-edit %N$ or addresses."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "offset": {
                    "type": "integer",
                    "description": "Stack index where your input starts (from AAAA%p.%p... tests).",
                },
                "writes": {
                    "type": "object",
                    "description": "Dict of {hex_address: value}. Example: {'0x4033dc': 1} for a flag byte.",
                },
                "arch": {"type": "string", "description": "Default 'amd64'."},
                "written": {
                    "type": "integer",
                    "description": "Chars already printed in THIS printf only. Usually 0 if prefix was a separate printf(3) call.",
                },
                "write_size": {
                    "type": "string",
                    "enum": ["byte", "short", "int"],
                    "description": "Prefer 'byte' for small writes (default). Use 'int' for full 32-bit values.",
                },
                "no_dollars": {
                    "type": "boolean",
                    "description": "Set true if the binary rejects positional %N$ (pwntools no_dollars). Default false.",
                },
            },
            "required": ["offset", "writes"],
        },
    },
    "run_exploit": {
        "description": (
            "Execute a pwntools exploit script; returns stdout/stderr/exit_code plus "
            "shell_detected (uid= seen), flag_detected / flags_found (CTF PREFIX{...} pattern). "
            "If shell_detected or flag_detected, exploitation succeeded — stop further run_exploit/GDB "
            "unless the user needs a cleaned-up final script only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "The pwntools exploit script as a Python string."},
                "binary_path": {"type": "string", "description": "Path to target binary (optional, set as BINARY env var)."},
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds. Default 30.",
                },
                "save_script": {"type": "boolean", "description": "Set true to save the script under /exploits. Default false."},
            },
            "required": ["script"],
        },
    },
    # --- Dynamic analysis (GDB) tools ---
    "gdb_find_offset": {
        "description": "Find the exact buffer overflow offset by crashing the binary with a cyclic pattern in GDB and analyzing the crash state. Much more reliable than guessing offsets; on canary binaries this may abort at __stack_chk_fail before RIP control.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "pattern_length": {"type": "integer", "description": "Length of cyclic pattern. Default 300."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_run": {
        "description": "Run a binary in GDB and return the crash/exit state including registers and signal info.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "stdin_data": {"type": "string", "description": "Data to pipe as stdin."},
                "args": {"type": "string", "description": "Command line arguments."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_breakpoint": {
        "description": "Set a breakpoint in GDB, run the binary, return registers, stack_dump, compact disassembly at RIP (disassembly), and a shortened run transcript (output).",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "address": {"type": "string", "description": "Breakpoint address (hex like '0x401234' or symbol like 'vuln')."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional GDB commands to run at the breakpoint.",
                },
            },
            "required": ["binary_path", "address"],
        },
    },
    "gdb_examine": {
        "description": "Examine memory at an address in GDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "address": {"type": "string", "description": "Memory address to examine (hex or $register)."},
                "count": {"type": "integer", "description": "Number of units to display. Default 16."},
                "format": {"type": "string", "description": "GDB format (e.g. 'gx' for giant hex, 'wx' for word hex, 's' for string). Default 'gx'."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "break_at": {"type": "string", "description": "Optional breakpoint to set before running."},
            },
            "required": ["binary_path", "address"],
        },
    },
    "gdb_vmmap": {
        "description": "Show the memory map of a running process in GDB. Useful for finding stack/heap addresses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
            },
            "required": ["binary_path"],
        },
    },
    "gdb_stack": {
        "description": "Dump stack words around RSP. Useful for understanding stack layout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "count": {"type": "integer", "description": "Number of 8-byte words to dump. Default 32."},
                "stdin_data": {"type": "string", "description": "Optional stdin data."},
                "break_at": {"type": "string", "description": "Optional breakpoint (address or symbol)."},
            },
            "required": ["binary_path"],
        },
    },
}
