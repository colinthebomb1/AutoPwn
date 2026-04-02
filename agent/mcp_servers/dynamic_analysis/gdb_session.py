"""Persistent GDB/pwndbg session manager using pexpect."""

from __future__ import annotations

import os
import re

import pexpect

# CSI sequences, including bracketed paste (\\e[?2004h / \\e[?2004l) and SGR.
ANSI_ESCAPE = re.compile(
    r"\x1b\[\?[0-9;]*[a-zA-Z]"
    r"|\x1b\[[0-9;]*[a-zA-Z]"
    r"|\x1b\([a-zA-Z]"
)
PROMPT_PATTERN = [r"pwndbg>", r"\(gdb\)"]
PROMPT_RE = re.compile(r"(?:pwndbg>|\(gdb\))\s*$")

# Box-drawing, blocks, pwndbg arrows, em dash — strip for LLM-friendly MCP payloads.
_MESSY_UNICODE_RE = re.compile(
    r"[\u2500-\u257F\u2580-\u259F\u25A0-\u25FF\u2190-\u21FF\u2014\u2011]"
)

# After GDB attaches, shrink pwndbg context noise. Harmless "undefined command" on plain GDB.
_GDB_INIT_COMMANDS = (
    "set pagination off",
    "set confirm off",
    "set context-code-lines 6",
    "set context-sections regs disasm",
)


_GDB_SKIP_SUBSTRINGS = (
    "Thread debugging using libthread_db",
    "Using host libthread_db",
)


def compact_gdb_transcript(text: str, max_chars: int = 2000) -> str:
    """Strip decorative Unicode, whitespace, and cap length for tool responses."""
    if not text:
        return text
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = ANSI_ESCAPE.sub("", text)
    text = _MESSY_UNICODE_RE.sub(" ", text)
    lines_out: list[str] = []
    for line in text.split("\n"):
        cleaned = re.sub(r"  +", " ", line).strip()
        if not cleaned:
            continue
        if any(s in cleaned for s in _GDB_SKIP_SUBSTRINGS):
            continue
        lines_out.append(cleaned)
    text = "\n".join(lines_out)
    if len(text) > max_chars:
        drop = len(text) - max_chars
        text = f"[... {drop} chars omitted ...]\n{text[-max_chars:]}"
    return text


class GDBSession:
    """Manages a persistent GDB process via a PTY."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._proc: pexpect.spawn | None = None
        self._binary: str | None = None

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.isalive()

    def start(self, binary_path: str | None = None) -> str:
        """Start a new GDB session, optionally loading a binary."""
        self.close()
        cmd = "gdb -q"
        if binary_path:
            binary_path = os.path.abspath(binary_path)
            cmd += f" {binary_path}"
            self._binary = binary_path

        self._proc = pexpect.spawn(cmd, timeout=self.timeout, encoding=None)
        self._proc.expect(PROMPT_PATTERN, timeout=self.timeout)
        banner = self._clean(self._proc.before)
        for init_cmd in _GDB_INIT_COMMANDS:
            self.command(init_cmd, timeout=5)
        return banner

    def command(self, cmd: str, timeout: int | None = None) -> str:
        """Send a command to GDB and return the cleaned output."""
        if not self.alive:
            raise RuntimeError("GDB session is not running. Call start() first.")

        t = timeout or self.timeout
        self._proc.sendline(cmd)
        try:
            self._proc.expect(PROMPT_PATTERN, timeout=t)
        except pexpect.TIMEOUT:
            return f"[TIMEOUT after {t}s waiting for GDB prompt]"
        except pexpect.EOF:
            return "[GDB process terminated unexpectedly]"

        return self._clean(self._proc.before)

    def run_with_stdin(self, stdin_data: bytes, timeout: int | None = None) -> str:
        """Run the loaded binary, piping stdin_data to it, and return output."""
        if not self.alive:
            raise RuntimeError("GDB session is not running.")

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(stdin_data)
            input_file = f.name

        try:
            return self.command(f"run < {input_file}", timeout=timeout)
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    def close(self) -> None:
        """Terminate the GDB session."""
        if self._proc is not None:
            if self._proc.isalive():
                self._proc.sendline("quit")
                try:
                    self._proc.expect(pexpect.EOF, timeout=3)
                except (pexpect.TIMEOUT, pexpect.EOF):
                    pass
                if self._proc.isalive():
                    self._proc.terminate(force=True)
            self._proc = None
            self._binary = None

    def _clean(self, data: bytes | str) -> str:
        """Strip ANSI codes and clean up GDB output."""
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data
        text = ANSI_ESCAPE.sub("", text)
        # Remove the echoed command (first line is usually the command itself)
        lines = text.split("\n")
        if lines and lines[0].strip() == "":
            lines = lines[1:]
        return "\n".join(lines).strip()

    def __del__(self):
        self.close()
