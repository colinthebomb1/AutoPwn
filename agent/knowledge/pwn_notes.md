# Pwn knowledge base (operator notes)

Concise reference distilled from practice writeups and tooling cheatsheets. **Heuristics are 64-bit Linux–biased and not universal** — always confirm with GDB / `elf_symbols` / leaks for the target binary and libc version.

## GDB / analysis

- **Disassembly:** `disassemble main` (or `vuln`), `set disassembly-flavor intel` for readability.
- **Stepping:** `ni` (next instruction, no step-into), `si` (step into call).
- **State:** `info registers`, breakpoints on compares / `call printf`.
- **Inspection:** `x/s $rsp` or `x/gx` for qwords; **telescope** (pwndbg/gef) for stack chunks.
- **Memory maps:** `vmmap` / `info proc mappings` — note **R W X** per segment before writing shellcode or ROP data.
- **Frames:** `i f` — see `$rip` and saved frame pointer context.

## Static & syscall tooling

- **objdump:** `objdump -d -M intel <binary>` (disasm), `objdump -x <binary>` (headers, sections).
- **Runtime tracing:** `strace <binary>` (syscalls), `ltrace <binary>` (library calls).
- **Gadgets:** `ROPgadget --binary ./b` (pipe through `grep` for `pop rdi`, `syscall`, etc.); `--ropchain` for quick chains when applicable.

## Mitigations (quick)

- **RELRO:** Full → GOT read-only after relocation; **Partial/None** → GOT overwrite sometimes viable (with write primitive).
- **PIE:** Code addresses slide — need leak or known base from `%p` / pointer leak.
- **NX:** Stack non-executable → ROP / ret2libc, not raw stack shellcode (unless mprotect path exists).
- **Canary:** Stack smash aborts on mismatch — leak canary (format string, partial read) or avoid smashing past it until leaked.

Use the agent’s **`checksec`** first; confirm with **`elf_symbols`** (PLT/GOT).

## Format string — reading (leaks)

- Loop **`%{i}$p`** (or `%{i}$p|` with a delimiter) to map stack slots.
- **Rough leak triage (amd64, heuristic):**
  - **`0x55…` / `0x56…`** → often **PIE** mapping → `leaked - offset(symbol)` ≈ binary base.
  - **`0x7fff…` / `0x7ffc…`** → often **stack** → distances to saved RIP / saved pointers (use **`gdb_stack`** / telescope).
  - **`0x7f…`** but not the stack prefix above → often **libc** / loader → subtract known symbol offset for libc base (symbol varies by libc build; prefer **`__libc_start_main`** / `puts` / `_IO_2_1_stdout_` etc. from your ELF).
- **Multiplex:** one send like `%11$p%16$p%9$p` when layout is stable; parse fixed widths carefully or use delimiters.
- **String leak:** `%{i}$s` only when the **i-th “argument” is a valid readable pointer** — otherwise crash. Use for flag buffers / env already on stack.

## Format string — writing

- **`numbwritten`:** Count bytes **already printed by the same `printf` call** before your format string is processed.  
  - `printf("Hello, "); printf(buf);` → second call → **`written = 0`**.  
  - `printf("PREFIX %s", buf)` where `buf` is *only data* — not a format bug.  
  - `printf(buf)` alone after an **`sprintf` or single call** that built `buf` with a visible prefix included in **this** `printf` — then add prefix length.
- **`printf` vs `fgets`:** `fgets` does not stop on interior `\\x00` before newline. **`printf(buf)` stops at the first `\\x00` in `buf`** — do not put the target address **before** specifiers if that inserts an early NUL; prefer **`fmtstr_payload`** layout (specifiers first, pointer bytes after) or tool output **verbatim**.
- **Filtered `$`:** Some binaries strip or block positional `$`. Use pwntools **`fmtstr_payload(..., no_dollars=True)`** (longer payloads). The MCP **`format_string_payload`** tool exposes **`no_dollars`** when needed.
- **GOT overwrite:** Only if RELRO allows; target **already-resolved** PLT/GOT entries after a call has happened if you need a valid function pointer.
- **Legacy heap hook note:** **`__malloc_hook` / `__free_hook`** were removed in modern glibc (≈ 2.34+). Treat hook-based writes as **version-specific**; verify libc.

## Buffer overflow

- **Offset:** cyclic pattern + crash → `cyclic_find` on faulting register / `gdb_find_offset` (agent tool).
- **Alignment (x86_64):** before calls like `system`, stack often must be 16-byte aligned at `call` — sometimes an extra **`ret`** gadget fixes “movaps” / segfault-after-success issues.

## ret2libc / ROP patterns

- **`ROP(elf)` / `ROP(libc)`** in pwntools: `rop.call(...)`, `rop.chain()`, **`rop.execve(path,0,0)`** after setting `libc.address`.
- **Leak loop:** e.g. overflow once → **`pop rdi; got[puts]; puts_plt; main`** → parse leak → set **`libc.address`** → second stage ROP to **`system("/bin/sh")`**.
- **Mid-function entry:** jumping into the middle of a function may skip prologue; you may need an extra **dummy pop / saved RBP** slot at the end of the chain to satisfy epilogue of the wrong entry point.

## Canary leak (common pattern)

- Fill buffer up to canary with **non-null** bytes; if output prints the buffer until **NUL**, you often leak up to the first byte of the canary.
- Canary low byte is often **0x00** on amd64; reconstruct with e.g. `u64(recv(7).ljust(8, b"\\x00"))` patterns — adjust count to match I/O.

## Heap (tcache, glibc ≥ 2.26)

- Per-thread **tcache**: small chunks cached; **~7** chunks per size class before falling back to other bins (simplified).
- **Safe-linking** and newer hardening change pointer encoding — treat writeups as **version-specific**.
- Further reading: tcache internals and “safe linking” posts (search tcache glibc 2.26 / 2.32+).

**FSOP (glibc ≥ 2.34):** hooks removed — abuse a live `FILE *` + trigger (`fflush` / `fclose`). **Partial
RELRO:** `fflush` fake-write into GOT is viable. **Full RELRO:** no GOT overwrite — use libc-relative
vtable tricks (e.g. **`_IO_wfile_jumps - 0x18`** + wfile underflow chains on modern glibc) or
**`_IO_str_overflow` / `fclose`**-style paths; all are **libc-version-sensitive**. Leak **`libc.base`**
from the **vtable qword at `FILE+0xd8`** minus **`_IO_file_jumps`**. `_IO_FILE` is ~0x1d8 bytes;
`_IO_vtable_check` rejects arbitrary heap “fake vtables”. Use **`FileStructure`** and **`gdb_examine
&_IO_2_1_stdout_`** on the target libc before crafting payloads.

## Misc tricks

- **Predictable `rand`:** seed `srand(time(NULL))` and match with **ctypes** `libc.srand` / `libc.rand` in sync with `process()` start when the challenge uses wall-clock time naively.
- **Float-only I/O:** pack QWORDs as two **IEEE floats** (split hi/lo 32 bits) when the program only accepts floats.
- **Credits / further reading:** many leak recipes echo common CTF writeups (e.g. Starshard-style `%p` base triage). Cross-check offsets against **your** libc and binary.
