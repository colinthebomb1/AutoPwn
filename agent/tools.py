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
    "rop_write_string_and_call_payload": "exploit",
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
        "description": "Identify mitigations (RELRO, Canary, NX, PIE) for a binary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
            },
            "required": ["binary_path"],
        },
    },
    "elf_symbols": {
        "description": "List ELF functions, PLT/GOT entries, or named objects. Prefer narrower scope on static binaries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "symbol_type": {
                    "type": "string",
                    "enum": ["all", "functions", "plt", "got", "objects"],
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
        "description": "Search an ELF for a string or hex byte pattern and return virtual addresses.",
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
        "description": "Find ROP gadgets in a binary. With no `search`, returns a curated common gadget set.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search": {
                    "type": "string",
                    "description": "Optional filter string (e.g. 'pop rdi', 'ret'). If omitted, returns the common gadget pack.",
                },
                "max_results": {"type": "integer", "description": "Max gadgets to return. Default 128."},
            },
            "required": ["binary_path"],
        },
    },
    "cyclic_pattern": {
        "description": "Generate or query a cyclic pattern for offset discovery.",
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
        "description": "Extract printable strings from a binary with curated filtering by default.",
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
        "description": "Generate pwntools shellcraft snippets or shellcode payload bytes.",
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
        "description": "Resolve useful libc symbol offsets, including `/bin/sh` when present.",
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
        "description": "Compute libc base from one leaked symbol and resolve key runtime addresses.",
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
        "description": "Compute PIE base from one leaked binary symbol address.",
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
        "description": "Build a stage-1 ret2libc payload that leaks a GOT entry and returns for stage 2.",
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
        "description": "Build a stage-2 ret2libc payload that calls `system('/bin/sh')`.",
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
    "rop_write_string_and_call_payload": {
        "description": "Build a ROP payload that writes attacker-controlled bytes, then calls a target function on them.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Target ELF path."},
                "offset": {"type": "integer", "description": "Overflow offset to saved RIP."},
                "string_data": {
                    "type": "string",
                    "description": "Bytes to stage into writable memory. Defaults to '/bin/sh'.",
                },
                "call_symbol": {
                    "type": "string",
                    "description": "Function to call after writing the string. Defaults to system.",
                },
                "writer_symbol": {
                    "type": "string",
                    "description": "Writer function to use, usually gets or read. Defaults to auto.",
                },
                "writable_address": {
                    "type": "string",
                    "description": "Optional writable target address as hex/int string. Defaults to .bss + 0x80.",
                },
                "pie_base": {
                    "type": "string",
                    "description": "Optional PIE base as hex/int string. If omitted, treated as 0.",
                },
                "canary": {
                    "type": "string",
                    "description": "Optional leaked stack canary as hex/int string.",
                },
                "canary_offset": {
                    "type": "integer",
                    "description": "Byte offset from input start to canary slot (required if canary is provided).",
                },
                "saved_rbp": {
                    "type": "string",
                    "description": "Optional saved RBP value to place after canary. Default 0x0.",
                },
            },
            "required": ["binary_path", "offset"],
        },
    },
    "ghidra_decompile": {
        "description": "Decompile named functions to Ghidra pseudocode using local headless Ghidra.",
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
        "description": "Generate a pwntools `fmtstr_payload` write payload for a chosen offset and writes map.",
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
        "description": "Execute a pwntools exploit script and return transcript, exit status, and success signals.",
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
        "description": "Find a buffer overflow offset in GDB using a cyclic pattern.",
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
        "description": "Run a binary in GDB and return crash or exit state plus registers.",
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
        "description": "Break in GDB at an address or symbol and return registers, stack, disassembly, and transcript.",
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
        "description": "Show the process memory map in GDB.",
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
        "description": "Dump stack words around RSP in GDB.",
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
