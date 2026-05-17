"""``hunter htb`` sub-commands — HackTheBox machine solver."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
import typer

from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError

log: structlog.stdlib.BoundLogger = structlog.get_logger("cli.htb")

app = typer.Typer(name="htb", help="HackTheBox machine solvers.")


@app.command("solve")
def solve(
    target: str = typer.Option(..., "--target", "-t", help="Target IP."),
    scope: Path = typer.Option(
        ...,
        "--scope",
        "-s",
        help="Scope file authorising the HTB subnet.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Run the solver. Omit for a dry-run that only validates scope.",
    ),
    network: str = typer.Option(
        "bridge",
        "--network",
        "-n",
        help=(
            "Sandbox network mode (bridge|internal|none|host). "
            "Use 'host' on Linux/WSL2 to reach a host-side VPN tunnel."
        ),
    ),
) -> None:
    """Run the HTB recon/enum pipeline against TARGET."""
    if not execute:
        typer.secho(
            f"[DRY-RUN] HTB solve dry-run - target {target!r} would be probed.",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  Scope file : {scope}")
        return

    from huntersec.settings import SafetySettings, SandboxSettings, Settings
    from huntersec.solvers.htb.solver import HTBSolver

    if network == "host":
        typer.secho(
            "[WARN] host network mode: container shares host network. "
            "HTB VPN (tun0) will be accessible. Linux/WSL2 only.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    try:
        app_settings = Settings(
            safety=SafetySettings(scope_file=scope),
            sandbox=SandboxSettings(network_mode=network),  # type: ignore[arg-type]
        )
        solver = HTBSolver(target_ip=target, scope_file=scope, settings=app_settings)
    except (ScopeNotConfiguredError, OutOfScopeError) as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    typer.secho(f"\n[LIVE] HTBSolver starting against {target} ...\n", fg=typer.colors.GREEN)
    result = asyncio.run(solver.solve())
    typer.echo(f"Status        : {result['status']}")
    typer.echo(f"Steps taken   : {result['steps_taken']}")
    typer.echo(f"Duration (s)  : {result['duration_seconds']}")
    typer.echo(f"User flag     : {result['user_flag']}")
    typer.echo(f"Root flag     : {result['root_flag']}")
    if result["report_path"]:
        typer.secho(f"\n[OK] Report saved: {result['report_path']}", fg=typer.colors.GREEN)
