"""``hunter run`` command — launch an autonomous recon/pentest session."""

from __future__ import annotations

from pathlib import Path

import structlog
import typer

log: structlog.stdlib.BoundLogger = structlog.get_logger("cli.run")


def run(
    target: str = typer.Option(..., "--target", "-t", help="Target IP, hostname, or URL."),
    scope: Path = typer.Option(  # noqa: B008
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
) -> None:
    """Run an autonomous security assessment against TARGET.

    By default operates in **dry-run** mode: safety checks run and the planned
    steps are printed, but no tool is executed.  Pass ``--execute`` to actually
    run tools inside the Docker sandbox.

    The scope file MUST exist and TARGET must be in scope — the session is
    aborted otherwise.
    """
    from huntersec.exceptions import ScopeNotConfiguredError
    from huntersec.safety.audit import AuditLogger
    from huntersec.safety.scope import ScopeValidator
    from huntersec.settings import SafetySettings, SandboxSettings

    settings = SafetySettings(scope_file=scope)

    # Validate scope before doing anything else
    try:
        validator = ScopeValidator.load(scope)
    except ScopeNotConfiguredError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    if not validator.is_in_scope(target):
        typer.secho(
            f"ERROR: target {target!r} is not in the scope defined by {scope}.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    audit = AuditLogger(settings.audit_log_dir)
    audit.log_event(
        "session.start",
        {
            "target": target,
            "scope_file": str(scope),
            "dry_run": not execute,
            "provider": provider,
        },
    )

    log.info(
        "session.start",
        target=target,
        scope=str(scope),
        dry_run=not execute,
        provider=provider,
    )

    if not execute:
        typer.secho(
            "\n[DRY-RUN] Safety checks passed. "
            "Re-run with --execute to launch the agent.\n",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  Target  : {target}")
        typer.echo(f"  Scope   : {scope}")
        typer.echo(f"  Provider: {provider}")
        typer.echo(f"  Audit   : {audit.path}")
        return

    # Live execution path — agent loop would be wired here
    typer.secho(
        f"\n[LIVE] Starting agent against {target!r} ...",
        fg=typer.colors.GREEN,
    )
    typer.echo("Agent integration not yet wired — extend this command with LangGraph agent.")
    audit.log_event("session.end", {"target": target, "reason": "stub"})
