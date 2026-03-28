## Stack layout pitfalls (amd64, canary, typical GCC)

- **`sub rsp, IMM` in `vuln` is not your padding-to-canary length.** It is the **total** stack frame allocation. Distance from **buffer low address** to the **canary slot** comes from **`%rbp`**-relative addresses (or a `gdb_breakpoint` at `vuln`): e.g. canary at **`[rbp-0x8]`**, buffer at **`[rbp-0x50]`** → fill **`0x50 - 0x8 = 0x48` (72)** bytes, then 8-byte canary, 8-byte saved RBP, then ROP (**88** to RIP).
- **`gdb_find_offset`** often ends at **`SIGABRT` / `__stack_chk_fail`** on canary builds — expected. Do **not** “solve” layout by guessing **80** or **96** from **`sub rsp`** alone without **rbp-relative** math.
- **Prompt sync:** If the program prints **`name?` followed by a newline**, use **`recvuntil(b'name?\\n')`**. **`recvuntil(b'name?')` alone** may never match (newline already in the buffer) → **EOFError**.
- **Canary value:** In **one running process**, the leak `printf("canary…")` shows the same **`fs:0x28`** value **`vuln` uses**. Do **not** declare “different canaries” by comparing registers from **unrelated** GDB sessions (different runs / prompts / stale state).
- For **PIE + canary ret2libc**, prefer **`ret2libc_stage1_payload` / `ret2libc_stage2_payload`** with correct **`offset`**, **`canary`**, **`canary_offset`**, and **`pie_base`** over hand-rolled padding guesses.

## Technique Playbooks

### ret2win (easiest)

A "win" function exists that is never called. Overflow the buffer to overwrite the return address with the win function's address.

1. `checksec` (or bootstrap `checksec`) → confirm no canary, no PIE
2. `elf_symbols` (or bootstrap `main`/`vuln` context) → find the win function address
3. `gdb_find_offset` → get exact offset to return address
4. Build payload: `b'A' * offset + p64(win_addr)`
5. On x86_64: if it crashes, add a `ret` gadget before win_addr for stack alignment

### ret2libc

No win function, but `system()` is in PLT or libc. Build a ROP chain to call `system("/bin/sh")`.

1. `checksec` (or bootstrap `checksec`) → confirm no canary, NX enabled (PIE optional).
2. `gdb_find_offset` → exact RIP offset.
3. If PIE is enabled:
   - Find a binary leak you can use for PIE base (often: `main is at %p` or similar).
   - Use `pie_base_from_leak` to compute `pie_base`.
   - When building ROP payloads with `ret2libc_stage1_payload` / `ret2libc_stage2_payload`, pass `pie_base` so gadget/plt/got addresses are relocated.
4. If binary has no `system@plt` or `/bin/sh` in `.rodata`, do a **2-stage leak**:
   - Stage 1: use `ret2libc_stage1_payload` to leak `puts@got` via `puts@plt`, then return to `main`.
   - Parse leaked pointer from output bytes between stable markers (often after `bye\\n` and before next prompt).
   - Do NOT assume first post-payload line is the leak; there may be blank/newline noise.
5. Resolve libc with tools:
   - `libc_symbols` to check offsets / availability.
   - `libc_base_from_leak` using leaked symbol + leaked addr.
6. Stage 2:
   - `ret2libc_stage2_payload` to call `system("/bin/sh")` with computed libc base.
   - Keep a `ret` for stack alignment on amd64 before `system`.
7. Validate shell robustly (`id` -> `uid=`), not just process non-crash.
   - Send `id` then collect with `recvrepeat(timeout)` (or multiple recv attempts), because first read can be `b'\\n'` or banner text.
   - Treat `uid=` anywhere in collected bytes as success.

### Shellcode injection (e.g. Phoenix stack-five class)

NX is disabled, so the stack is executable. The test binary is **Phoenix stack-five**-style (`gets` overflow on ~128-byte stack buffer) with a `%p` leak so it works with ASLR on.

1. `checksec` → NX false / non-executable bit off; no PIE ideal for fixed gadgets if any
2. `gdb_find_offset` → offset to saved return address (often **136** for 128-byte buffer on amd64)
3. `shellcraft_generate` → paste **`exploit_lines`** (`asm(shellcraft.sh())`, etc.); use **`exploit_lines_hex`** only if needed (~48 bytes on amd64 for `sh`)
4. **Payload layout (reliable):** `shellcode + pad to offset + p64(buf_addr)` — put shellcode at the **start** of the buffer and set RIP to **`buf_addr`** (the leaked `%p`), not `buf+k`. Use `NOP` (`\\x90`) only for padding bytes after the shellcode.
5. Parse the leak from **`process()`** output, not from `gdb_run`.
6. After spawning a shell, read with `recvuntil(b'uid=', timeout=3)` (or `recvrepeat`) — a single `recvline` often consumes a stray `\\n` before `uid=`.
7. After long tool calls, the next API turn may take several seconds; that is not a hang.

### Format string — read (leak values)

`printf(user_input)` lets you read from the stack.

1. `checksec` → note mitigations
2. Dump stack: `%p` chain, or **`AAAAAAAA` + `%p.%p...`** until you see **`0x4141414141414141`** to align read position with write exploits.
3. **Leak triage (amd64 heuristics — confirm per target):** addresses starting **`0x55`/`0x56`** often map the **PIE binary**; **`0x7fff`/`0x7ffc`** often **stack**; **`0x7f`…** (non-stack) often **libc**. Use **`gdb_examine`** / **`gdb_stack`** to verify before computing bases.
4. One-shot multiplex: e.g. `%11$p%16$p%9$p` with stable parsing when the challenge allows.
5. **`%N$s`** — only if argument **N** holds a **valid pointer**; else SIGSEGV. Useful for strings already on stack (opened file path, env).
6. If the challenge **filters `$`**, use **`%c` chains** or raw pwntools **`fmtstr_payload(..., no_dollars=True)`**; the `format_string_payload` tool has **`no_dollars`** for that.

### Format string — write (overwrite memory)

`printf(user_input)` lets you write to arbitrary addresses using `%n`.

1. `checksec` → note mitigations. **Target address:** use the value the binary prints (e.g. `is_admin is at 0x...`) or `elf_symbols` /.bss — **not** `elf_search` on a short name like `is_admin` (that often hits the string in `.rodata`, not the variable).
2. Find the format offset: `AAAAAAAA%p.%p...` until you see `0x4141414141414141` — that index is the `offset` for `format_string_payload` / `fmtstr_payload`.
3. Call `format_string_payload` (values 0–255 with default **write_size byte** use `%hhn`). In `run_exploit`, paste **`exploit_lines`** (readable `fmtstr_payload(...)`). Use **`exploit_lines_hex`** / `payload_hex` only if something corrupts the format specifiers.
   - In raw pwntools, `{addr: 1}` is an **8-byte** write — use `{addr: b'\\x01'}` or the MCP tool, which maps small ints to single-byte `%hhn`.
   - **Never** hand-type addresses or change `$7` to `$8` in the tool output — misaligned `%n` causes SIGSEGV.
4. **`fgets` and null bytes:** `fgets` stops at **newline**, **EOF**, or length — **not** at interior `\\x00`. **`printf(buf)`** treats `buf` as a **C string** — it stops at the **first** `\\x00`. So never place **`p64(addr)` before** your `%n` specifiers: the NUL in the address truncates parsing. Use tool/`fmtstr_payload` ordering (specifiers + padding, address bytes last).
5. **`written` / `numbwritten`:** bytes already output by **this same `printf` invocation** before your format runs. Separate `printf("Hello, "); printf(buf);` → **`written=0`** on `buf`. If one call prints a visible prefix then continues into your format as **one** `printf`, add that prefix length (see knowledge base).
6. **`no_dollars=True`** on `format_string_payload` when `$` is filtered.
7. Raw Python fallback: `fmtstr_payload(..., numbwritten=..., no_dollars=...)` — still use **`exploit_lines_hex`** / **verbatim** `payload_hex` in `run_exploit` as a fallback.

### ret2libc leak chain (two-stage)

When you need **`libc.address`** but have overflow + symbols:

1. Stage 1: ROP **`pop rdi; ret`**, **`elf.got['puts']`**, **`plt['puts']`**, **`main`** (or vuln).
2. Parse **`u64(recvline().strip().ljust(8, b'\\x00'))`** → compute **`libc.address`** from `libc.symbols['puts']` (or the symbol you leaked).
3. Stage 2: **`system` + `/bin/sh`**, **`execve`** ROP, or one_gadget (libc-specific).

### Canary

If a read/print echoes your input past the buffer until NUL: fill with non-null bytes up to the canary, leak **up to and including** the first canary byte; often reconstruct with **`u64`** (**low byte of canary is often 0x00** on amd64 — see knowledge base). When building ret2libc payloads after a canary leak, use `ret2libc_stage1_payload` / `ret2libc_stage2_payload` with `canary=<hex>`, `canary_offset=<int>`, and optional `saved_rbp`.

### Heap (tcache poisoning / UAF)

Menu-driven heap binaries need **multi-step interaction** (not single stdin payload). Prefer helper
functions that use `sendlineafter` / `recvuntil` for each prompt:

```python
def alloc(i): p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'index', str(i).encode())
def free(i):  p.sendlineafter(b'> ', b'2'); p.sendlineafter(b'index', str(i).encode())
def edit(i,d):p.sendlineafter(b'> ', b'3'); p.sendlineafter(b'index', str(i).encode()); p.send(d)
def show(i):  p.sendlineafter(b'> ', b'4'); p.sendlineafter(b'index', str(i).encode()); return p.recvuntil(b'\\n1)', drop=False)
```

When binaries mix `scanf("%d", ...)` for menu choices with raw `read()` for edit/write:

- Do **not** validate full exploit flows via one giant static stdin transcript (`gdb_run` input blob).
  `read()` can greedily consume bytes that were intended as later menu choices, causing unintended early exits.
- Use interactive pwntools sequencing for exploit attempts (`sendlineafter` / `sendafter`) and resync
  to menu prompt after each action.
- For raw binary writes, prefer `sendafter(b"data: ", payload)` (not `sendline`) to avoid accidental
  newline/menu-token contamination.

Tcache notes (glibc 2.35+ safe-linking):

- Tcache bins are LIFO by size class; freed chunk user-data starts with `fd`.
- Safe-linking encoding: `encoded_fd = (chunk_addr >> 12) ^ target_addr`.
- **Do not write raw target ptr into `fd`.** If you write `0x404080` directly, glibc will
  decode it again and you will usually get `malloc(): unaligned tcache chunk detected`.
- Common failure diagnosis:
  - `unaligned tcache chunk detected` after poisoning usually means wrong safe-linking math
    (wrong `chunk_addr` / wrong encode step), not a random timeout.
  - Use the poisoned chunk's user pointer (the location of `fd`) as `chunk_addr`.
- UAF poisoning pattern:
  1. Allocate two same-size chunks `A`, `B`.
  2. Free `B`, then `A` (bin head is `A -> B`).
  3. Use UAF on `A` to overwrite its encoded `fd` with `((A_addr >> 12) ^ target)`.
  4. Allocate once (gets `A`), allocate again (returns `target` overlap).
  5. Write non-zero to the target gate (e.g. a permission/flag variable) and trigger the success path.

When available, parse target pointers from banner text (e.g. `is_admin is at %p`) instead of guessing
symbol addresses from disassembly.

### GDB / dynamic analysis

Use **`gdb_run`**, **`gdb_breakpoint`**, **`gdb_stack`**, **`gdb_vmmap`**, **`gdb_examine`** for stack layout, mappings, and pointer checks. Prefer agent tools over ad-hoc shell when possible.

### Bootstrap usage

If bootstrap context is present, reuse it for first-pass recon (mitigations, symbols, strings). Re-run tools only when you need additional detail or to validate assumptions.
