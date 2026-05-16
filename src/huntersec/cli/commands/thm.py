"""``hunter thm`` sub-commands — TryHackMe room solver.

TryHackMe rooms share the same recon/enum primitives as HTB machines, so
this command is a thin re-use of :class:`~huntersec.solvers.htb.solver.HTBSolver`
with a THM-specific report filename prefix.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
import typer

from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError

log: structlog.stdlib.BoundLogger = structlog.get_logger("cli.thm")

app = typer.Typer(name="thm", help="TryHackMe room solvers.")


@app.command("solve")
def solve(
    target: str = typer.Option(..., "--target", "-t", help="Target IP."),
    scope: Path = typer.Option(
        ...,
        "--scope",
        "-s",
        help="Scope file authorising the THM subnet.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Run the solver. Omit for a dry-run that only validates scope.",
    ),
) -> None:
    """Run the THM recon/enum pipeline against TARGET."""
    if not execute:
        typer.secho(
            f"[DRY-RUN] THM solve dry-run — target {target!r} would be probed.",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  Scope file : {scope}")
        return

    from huntersec.solvers.htb.solver import HTBSolver

    try:
        solver = HTBSolver(target_ip=target, scope_file=scope)
    except (ScopeNotConfiguredError, OutOfScopeError) as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    typer.secho(f"\n[LIVE] THM solver starting against {target} ...\n", fg=typer.colors.GREEN)
    result = asyncio.run(solver.solve())
    typer.echo(f"Status        : {result['status']}")
    typer.echo(f"Steps taken   : {result['steps_taken']}")
    typer.echo(f"Duration (s)  : {result['duration_seconds']}")
    typer.echo(f"User flag     : {result['user_flag']}")
    typer.echo(f"Root flag     : {result['root_flag']}")
    if result["report_path"]:
        typer.secho(f"\n✓ Report saved: {result['report_path']}", fg=typer.colors.GREEN)
