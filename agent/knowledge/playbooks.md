## Stack layout (amd64, canary, GCC)

- **`sub rsp, IMM`** is total frame, not padding-to-canary. Distance from buffer to canary comes from `rbp`-relative addresses: e.g. canary at `[rbp-0x8]`, buffer at `[rbp-0x50]` → fill `0x48` bytes, then 8-byte canary, 8-byte saved RBP, then ROP.
- `gdb_find_offset` often hits `SIGABRT`/`__stack_chk_fail` on canary builds. Don't guess layout from `sub rsp` alone.
- Menu-driven binaries: `gdb_find_offset` is optional. Raw cyclic stdin may not reach the bug.
- Prompt sync: if program prints `name?\n`, use `recvuntil(b'name?\n')` — without `\n` may never match.
- Canary is consistent within one process; don't compare across GDB sessions.

## Technique Playbooks

### ret2win

1. Bootstrap/`checksec` → no canary, no PIE
2. `elf_symbols` → win function address
3. `gdb_find_offset` → offset to RIP
4. Payload: `b'A' * offset + p64(win_addr)`
5. If crash: add `ret` gadget before win_addr for alignment

### ret2libc (staged leak)

1. `checksec` → no canary, NX on. If PIE: leak PIE base via `pie_base_from_leak`.
2. `gdb_find_offset` for offset (single-shot targets), else derive from disassembly.
3. Gadgets: `rop_gadgets(binary_path)` with no search first.
4. **If no `system@plt` or `/bin/sh`** → two-stage leak:
   - Stage 1: `ret2libc_stage1_payload` — leak `puts@got` via `puts@plt`, return to `main`.
   - Parse leak: after stable marker (e.g. `recvuntil(b'bye\n')`), read 6 bytes, `u64(...ljust(8, b'\x00'))`.
   - `libc_base_from_leak` → resolve system + /bin/sh.
   - Stage 2: `ret2libc_stage2_payload` → `system("/bin/sh")` with `ret` alignment.
5. **If `system@plt` exists but no `/bin/sh`**: use `rop_write_string_and_call_payload` to stage `/bin/sh` into `.bss` via `gets`/`read`.
6. Validate shell: send `id`, collect with `recvrepeat(1.5)`, check for `uid=`.

### Shellcode (NX off)

1. `checksec` → NX false
2. `gdb_find_offset` → offset (often 136 for 128-byte buffer)
3. `shellcraft_generate` → use `exploit_lines` (asm); `exploit_lines_hex` as fallback
4. Layout: `shellcode + pad to offset + p64(buf_addr)` — shellcode at start, RIP = leaked `buf_addr`
5. Parse leak from `process()` output, not `gdb_run`
6. Validate: `recvrepeat` after sending `id`

### Format string — read (leaks)

- Loop `%{i}$p` to map stack slots. Triage (amd64 heuristic):
  - `0x55…`/`0x56…` → PIE binary mapping
  - `0x7fff…`/`0x7ffc…` → stack
  - `0x7f…` (non-stack) → libc/loader
- Multiplex: `%11$p%16$p%9$p` with delimiters when layout is stable.
- `%{i}$s` only when slot holds a valid readable pointer.
- Filtered `$`: use `fmtstr_payload(..., no_dollars=True)`.

### Format string — write

- Find offset: `AAAAAAAA%p.%p...` until you see `0x4141414141414141`.
- Target address: use printed address or `elf_symbols` .bss — **not** `elf_search` on variable names.
- `format_string_payload` with `write_size="byte"` for small values. Use `exploit_lines` verbatim.
- **Never** hand-edit `%n` specifiers or addresses.
- `printf(buf)` stops at first NUL → don't put `p64(addr)` before specifiers.
- `written`/`numbwritten`: bytes printed by **this same printf** before your format. Separate `printf("prefix"); printf(buf);` → `written=0`.

### Canary leak

- Fill buffer to canary with non-null bytes; if output echoes past buffer, leak canary (low byte often `0x00` on amd64).
- Reconstruct: `u64(recv(7).ljust(8, b'\x00'))` (adjust to match I/O).
- Then use `ret2libc_stage1_payload`/`ret2libc_stage2_payload` with `canary=`, `canary_offset=`.

### Heap (tcache poisoning / UAF)

Menu-driven: use `sendlineafter`/`recvuntil` helpers per prompt. Do **not** use one giant stdin blob.

```python
def alloc(i): p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'index', str(i).encode())
def free(i):  p.sendlineafter(b'> ', b'2'); p.sendlineafter(b'index', str(i).encode())
def edit(i,d):p.sendlineafter(b'> ', b'3'); p.sendlineafter(b'index', str(i).encode()); p.send(d)
def show(i):  p.sendlineafter(b'> ', b'4'); p.sendlineafter(b'index', str(i).encode()); return p.recvuntil(b'\n1)', drop=False)
```

**Tcache (glibc 2.35+ safe-linking):**

- `encoded_fd = (chunk_addr >> 12) ^ target_addr` — do NOT write raw target.
- `unaligned tcache chunk detected` = wrong safe-linking math.
- UAF pattern: alloc A,B → free B,A → UAF edit A's fd → alloc twice → write target.
- Parse target pointers from banner text when available.

## GDB / dynamic analysis

Use `gdb_run`, `gdb_breakpoint`, `gdb_stack`, `gdb_vmmap`, `gdb_examine` for layout/state.

- Menu-driven: default to `gdb_breakpoint` over `gdb_run`.
- Only use `gdb_find_offset` after proving input reaches the vulnerable read.
- `vmmap` / `info proc mappings` for R/W/X per segment.

## Mitigations quick ref

| Mitigation | Impact |
|---|---|
| Full RELRO | GOT read-only after relocation |
| PIE | Code addresses slide — need leak |
| NX | Stack not executable → ROP/ret2libc |
| Canary | Leak or avoid smashing past it |

## Misc tricks

- **`rand` prediction:** match `srand(time(NULL))` with ctypes in sync with `process()` start.
- **`__malloc_hook`/`__free_hook`:** removed in glibc ≈ 2.34+; version-specific.
- **Stack alignment (x86_64):** extra `ret` gadget fixes movaps/segfault before `system`/`puts`.

## Bootstrap usage

Reuse bootstrap for first-pass recon. Re-run tools only when you need more detail. Avoid broad `strings_search(interesting_only=false)` as an opening move on static binaries.
