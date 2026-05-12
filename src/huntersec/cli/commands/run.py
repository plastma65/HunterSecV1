"""``hunter run`` command — launch an autonomous recon/pentest session."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
import typer

from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError
from huntersec.safety.audit import AuditLogger
from huntersec.safety.scope import ScopeValidator
from huntersec.settings import SafetySettings

log: structlog.stdlib.BoundLogger = structlog.get_logger("cli.run")


def run(
    target: str = typer.Option(..., "--target", "-t", help="Target IP, hostname, or URL."),
    scope: Path = typer.Option(
        ...,
        "--scope",
        "-s",
        help="Path to scope.yaml defining authorized targets.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Actually run tools.  Omit for dry-run (default: dry-run).",
    ),
    provider: str = typer.Option(
        "anthropic",
        "--provider",
        "-p",
        help="LLM provider to use (anthropic|openai|ollama).",
    ),
    objective: str = typer.Option(
        "recon",
        "--objective",
        "-o",
        help="Assessment objective: recon | exploit | ctf.",
    ),
) -> None:
    """Run an autonomous security assessment against TARGET.

    By default operates in **dry-run** mode: safety checks run and the planned
    steps are printed, but no tool is executed.  Pass ``--execute`` to actually
    run tools inside the Docker sandbox.

    The scope file MUST exist and TARGET must be in scope — the session is
    aborted otherwise.
    """
    settings = SafetySettings(scope_file=scope)

    # Validate scope before doing anything else
    try:
        validator = ScopeValidator.load(scope)
    except ScopeNotConfiguredError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    try:
        validator.assert_in_scope(target)
    except OutOfScopeError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    audit = AuditLogger(settings.audit_log_dir)
    audit.log_event(
        "session.start",
        {
            "target": target,
            "scope_file": str(scope),
            "dry_run": not execute,
            "provider": provider,
            "objective": objective,
        },
    )
    log.info(
        "session.start",
        target=target,
        scope=str(scope),
        dry_run=not execute,
        provider=provider,
        objective=objective,
    )

    if not execute:
        typer.secho(
            "\n[DRY-RUN] Safety checks passed. Re-run with --execute to launch the agent.\n",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  Target    : {target}")
        typer.echo(f"  Scope     : {scope}")
        typer.echo(f"  Objective : {objective}")
        typer.echo(f"  Provider  : {provider}")
        typer.echo(f"  Audit     : {audit.path}")
        return

    # Live execution — wire Session and run the LangGraph agent
    typer.secho(
        f"\n[LIVE] Starting agent against {target!r} ...\n",
        fg=typer.colors.GREEN,
    )
    try:
        from huntersec.core.session import Session
        from huntersec.settings import Settings

        app_settings = Settings(safety=SafetySettings(scope_file=scope))
        session = Session(
            target=target,
            scope_file=scope,
            objective=objective,
            settings=app_settings,
            provider=provider,
        )
        report_path = asyncio.run(session.run())
        typer.secho(f"\n✓ Report saved: {report_path}", fg=typer.colors.GREEN)
    except (ScopeNotConfiguredError, OutOfScopeError) as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except RuntimeError as exc:
        typer.secho(f"ERROR: Session failed — {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(3) from exc
