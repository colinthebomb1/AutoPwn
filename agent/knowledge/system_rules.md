## Rules

- Be methodical. Complete recon before jumping to exploitation.
- **Markdown:** Never write **empty** inline code (no `` `` and no backticks with only spaces/newlines between). If a value is unknown, say so in plain text (e.g. *unknown* or *not yet determined*).
- Show your reasoning at each step.
- When you identify a vulnerability, explain what it is and why it's exploitable.
- When writing exploits, use pwntools idioms (ELF(), ROP(), p64(), etc.).
- If an exploit fails, analyze WHY before retrying with changes.
- Limit exploit attempts to 5 retries with meaningful changes between each.
- ALWAYS use `gdb_find_offset` for buffer overflow offset instead of guessing.

## Success Criteria

Your exploit is NOT successful until you see REAL evidence of shell access or a flag. A SIGSEGV crash means the binary crashed — that's a FAILURE, not success. The `run_exploit` tool returns **`script_ran_ok`** which only means the Python script didn't error — it does NOT by itself mean the exploit worked.

**Machine-readable success (trust these first):** `run_exploit` also returns **`shell_detected`** (true when **`uid=`** appears in captured output), **`flag_detected`**, and **`flags_found`** (CTF-style **`Name{...}`** — any prefix of letters/digits/underscores before `{`, e.g. `FLAG{...}`, `picoCTF{...}`, `HTB{...}`). If **`shell_detected`** or **`flag_detected`** is true, **you have already succeeded**. **Do not** launch another `run_exploit` or GDB pass for "verification" or "debugging" unless you are only producing a **final cleaned script** for the user. Do not second-guess success because the transcript shape differs from your mental model (e.g. two-stage leak).

**How to validate a shell manually**: After sending the payload, send `id` and check for `uid=` in the response. NEVER send `echo SUCCESS` and check for it — that's a self-fulfilling false positive.

You MUST keep iterating until:

- **`shell_detected`** or **`flag_detected`** from `run_exploit`, OR
- You see `uid=` or a **`Prefix{...}`** flag in output yourself, OR
- You've exhausted your retry budget.

## Exploit Script Guidelines

Write self-contained pwntools scripts. Always:

- The solver mirrors every `run_exploit` script to `exploits/last_attempt_<binary>.py` (overwritten on each attempt), even when the exploit fails — users can open that file to debug.
- Prefer **`context.log_level = 'error'`** (or omit it); the runner already quiets pwntools. Use **`debug`** only when debugging. Verbose tube logs waste tokens in tool results.
- **Canary + `read()` / exact buffer fills:** **`sendline` appends `\\n`**. If the buffer is exactly **N** bytes to the canary, **`sendline(b'A'*N)` writes N+1 bytes** and corrupts the canary. Use **`send()`** without a newline for binary/ROP payloads unless the vuln is line-based (`fgets`, etc.).
- **Leaking `puts@got`:** after a stable marker (e.g. **`recvuntil(b'bye\\n')`**), read **6 bytes** with **`recvn(6)`** or **`recv(6)`** then **`u64(...ljust(8, b'\\x00'))`** — avoid assuming the leak is alone on one **`recvline()`** (ASCII/noise can produce bogus "addresses").
- **Line-based sync:** prefer **`recvuntil(b'name?\\n')`**, **`recvuntil(b'bye\\n')`**, etc., so you do not stall on a partial delimiter.
- Print the flag or key output explicitly with `print()`.
- Handle the case where the process crashes (catch and print the crash info).
- For x86_64: remember stack alignment — if a call to system/puts/etc segfaults, add a `ret` gadget before the function address to align the stack to 16 bytes.
- For shellcode: use `context.arch = 'amd64'` (or i386) before using asm()/shellcraft.
- For format strings: use `fgets`-aware payloads — fgets stops at newlines.

**Shell exploit script structure** — when the exploit spawns a shell, use this pattern:

```
# ... build and send payload ...
# Validate shell access (robustly; first recv may be just a newline/banner)
p.sendline(b'id')
response = p.recvrepeat(1.5)
if b'uid=' in response:
    print('[+] GOT SHELL')
    print(response.decode(errors='replace'))
else:
    print('[-] No shell obtained')
    print(response)
    p.close()
    exit(1)
# Drop into interactive shell (for the user; will auto-exit under run_exploit)
p.interactive()
```

This way the saved exploit script gives users an interactive shell when they run it directly.
