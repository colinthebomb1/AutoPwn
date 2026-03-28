"""Shared test fixtures — compiles test binaries if needed."""

from __future__ import annotations

import os
import subprocess

import pytest

CHALLENGES_DIR = os.path.join(os.path.dirname(__file__), "challenges")


def _compile_if_missing(binary_name: str) -> str:
    """Compile test binaries via Make if they don't exist."""
    binary = os.path.join(CHALLENGES_DIR, binary_name)
    if not os.path.isfile(binary):
        result = subprocess.run(
            ["make", binary_name],
            cwd=CHALLENGES_DIR,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"Cannot compile test binary: {result.stderr}")
    return binary


@pytest.fixture
def ret2win_binary() -> str:
    return _compile_if_missing("ret2win_x64")


@pytest.fixture
def ret2libc_binary() -> str:
    return _compile_if_missing("ret2libc_x64")


@pytest.fixture
def ret2libc_real_binary() -> str:
    return _compile_if_missing("ret2libc_real_x64")


@pytest.fixture
def ret2libc_pie_real_binary() -> str:
    return _compile_if_missing("ret2libc_pie_real_x64")


@pytest.fixture
def ret2libc_pie_canary_real_binary() -> str:
    return _compile_if_missing("ret2libc_pie_canary_real_x64")


@pytest.fixture
def shellcode_binary() -> str:
    return _compile_if_missing("shellcode_x64")


@pytest.fixture
def format_read_binary() -> str:
    return _compile_if_missing("format_read_x64")


@pytest.fixture
def format_write_binary() -> str:
    return _compile_if_missing("format_write_x64")


@pytest.fixture
def heap_tcache_poison_binary() -> str:
    return _compile_if_missing("heap_tcache_poison_x64")
