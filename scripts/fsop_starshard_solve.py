#!/usr/bin/env python3
"""
Skeleton solve for tests/challenges/fsop_starshard_x64 — Starshard / HTB University FSOP style.

Follow the chain from public write-ups (format → OOB FILE leak → fclose UAF → malloc reclaim →
fputs → _IO_wfile_overflow → _IO_wdoallocbuf → wide_vtable[0x68]).

Reference layout (adapt offsets to your libc / pwntools):
  - build_fake_file_patch() in seks99x / Medium article: flags, /bin/sh at +8, wide_data=self,
    _IO_wfile_jumps at +0xd8, wide vtable at FILE+0x100, system at wide_vtable+0x68.

This repo does **not** require this script to succeed in CI — libc and heap layout are
environment-specific. Use against a matching libc (e.g. LD_PRELOAD) when developing.
"""

from __future__ import annotations

# Example outline (not a complete working exploit):
#
# 1) io.recvuntil(b"Tinselwick Tinkerer Name: "); io.sendline(b"%9$p")  # tune index
# 2) parse leak → libc.address
# 3) menu 1 (arm): send 0x18 bytes routine name (no newline) → OOB leak FILE* from printf %s
# 4) menu 3 (cancel): fclose UAF
# 5) menu 2 (feed): malloc(0x1d0) or matching FILE chunk size; fgets fake FILE blob
# 6) menu 4 (commit): fputs → FSOP
#
# from pwn import *
# context.binary = ELF("tests/challenges/fsop_starshard_x64")
# ...

raise SystemExit(
    "Edit this script with your libc offsets and run locally — skeleton only by design."
)
