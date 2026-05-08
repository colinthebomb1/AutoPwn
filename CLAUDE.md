# AutoPwn — Claude guidance

## Before pushing or opening a PR

Always run these two commands and fix any failures before pushing:

```bash
pwn-env/bin/python3 -m ruff check .
pwn-env/bin/python3 -m pytest --ignore=tests/test_mcp_dynamic.py --ignore=tests/test_ghidra_decompile.py -x -q
```
