"""``hunter scope`` sub-commands — scope file inspection utilities."""

from __future__ import annotations

from pathlib import Path

import typer

from huntersec.settings import SafetySettings

app = typer.Typer(help="Inspect and validate the active scope configuration.")


@app.command("check")
def check(
    target: str = typer.Argument(..., help="IP, hostname, or URL to check."),
    scope_file: Path = typer.Option(  # noqa: B008
        None,
        "--scope",
        "-s",
        help="Path to scope.yaml.  Defaults to HUNTERSEC_SAFETY_SCOPE_FILE or configs/scope.yaml.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Check whether TARGET is authorized by the active scope file.

    Exits 0 if in scope, 1 if out of scope, 2 if the scope file is missing.
    """
    import structlog

    from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError
    from huntersec.safety.scope import ScopeValidator

    log: structlog.stdlib.BoundLogger = structlog.get_logger("cli.scope.check")

    settings = SafetySettings()
    resolved_scope = scope_file or settings.scope_file

    try:
        validator = ScopeValidator.load(resolved_scope)
    except ScopeNotConfiguredError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    try:
        validator.assert_in_scope(target)
        typer.secho(f"IN SCOPE: {target!r}", fg=typer.colors.GREEN)
        log.info("scope.check.in_scope", target=target, scope_file=str(resolved_scope))
    except OutOfScopeError as exc:
        typer.secho(f"OUT OF SCOPE: {exc}", fg=typer.colors.RED)
        log.warning("scope.check.out_of_scope", target=target, reason=str(exc))
        raise typer.Exit(1) from exc
