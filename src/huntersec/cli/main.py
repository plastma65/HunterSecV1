"""HunterSecV1 CLI entry point.

Invoked as ``hunter`` (see ``[project.scripts]`` in ``pyproject.toml``).

Sub-commands:
    run      — launch an autonomous agent session.
    scope    — inspect and validate scope files.
    version  — print version information.
"""

from __future__ import annotations

import typer

from huntersec.cli.commands.run import run
from huntersec.cli.commands.scope import app as scope_app
from huntersec.cli.commands.version import version

app = typer.Typer(
    name="hunter",
    help="HunterSecV1 — autonomous offensive-security agent (ethical, open-source).",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

app.command("run")(run)
app.command("version")(version)
app.add_typer(scope_app, name="scope")


if __name__ == "__main__":
    app()
