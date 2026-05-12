"""``hunter version`` command — print version information."""

from __future__ import annotations

import sys

import typer

from huntersec import __version__


def version(ctx: typer.Context) -> None:  # noqa: ARG001
    """Print HunterSecV1 version and Python runtime information."""
    typer.echo(f"HunterSecV1 {__version__}")
    typer.echo(f"Python {sys.version}")
