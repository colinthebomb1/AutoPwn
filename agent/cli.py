"""CLI entry point for AutoPwn."""

from __future__ import annotations

import os
import sys

import click
from dotenv import load_dotenv
from rich.console import Console

console = Console()


@click.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--remote", "-r", default=None, help="Remote target as host:port")
@click.option("--model", "-m", default="claude-sonnet-4-20250514", help="Anthropic model to use")
@click.option(
    "--max-iterations",
    "-n",
    default=None,
    type=int,
    help="Max ReAct iterations (default: env PWN_AGENT_MAX_ITERATIONS, else 30)",
)
@click.option(
    "--notes",
    default=None,
    type=str,
    help="Optional challenge context: CTF description, constraints, or suspected solve path.",
)
@click.option(
    "--notes-file",
    "notes_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Read notes from a UTF-8 file (use for long writeups). Overrides --notes if both are set.",
)
def main(
    binary: str,
    remote: str | None,
    model: str,
    max_iterations: int | None,
    notes: str | None,
    notes_file: str | None,
) -> None:
    """AutoPwn — Agentic binary exploitation powered by LLMs and MCP tools."""
    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] ANTHROPIC_API_KEY not set. "
            "Copy .env.example to .env and fill it in."
        )
        sys.exit(1)

    from agent.core import AutoPwnAgent

    user_context: str | None = None
    if notes_file:
        with open(notes_file, encoding="utf-8") as nf:
            user_context = nf.read()
    elif notes is not None:
        user_context = notes

    agent = AutoPwnAgent(model=model, max_iterations=max_iterations, api_key=api_key)
    result = agent.solve(binary_path=binary, remote=remote, user_context=user_context)

    console.print()
    if result.success:
        console.print("[bold green]✓ Solve complete[/bold green]")
        if result.exploit_script:
            # Save final exploit to a predictable path
            binary_name = os.path.splitext(os.path.basename(binary))[0]
            exploits_dir = os.path.join(os.path.dirname(__file__), "..", "exploits")
            os.makedirs(exploits_dir, exist_ok=True)
            final_path = os.path.join(exploits_dir, f"solve_{binary_name}.py")
            with open(final_path, "w") as f:
                f.write(result.exploit_script)

            console.print(f"\n[bold]Final exploit saved to:[/bold] {os.path.abspath(final_path)}")
            console.print()
            from rich.syntax import Syntax
            console.print(Syntax(result.exploit_script, "python", theme="monokai"))
    else:
        console.print("[bold red]✗ Solve failed[/bold red]")
        binary_name = os.path.splitext(os.path.basename(binary))[0]
        exploits_dir = os.path.join(os.path.dirname(__file__), "..", "exploits")
        last_path = os.path.abspath(os.path.join(exploits_dir, f"last_attempt_{binary_name}.py"))
        if os.path.isfile(last_path):
            console.print(f"[dim]Latest run_exploit script (if any): {last_path}[/dim]")

    console.print(
        f"\n[dim]Iterations: {result.iterations} | "
        f"Tool calls: {len(result.tool_calls)}[/dim]"
    )


if __name__ == "__main__":
    main()
