"""HunterSecV1 CLI entry point.

Invoked as ``hunter`` (see ``[project.scripts]`` in ``pyproject.toml``).

Sub-commands:
    run      — launch an autonomous agent session.
    scope    — inspect and validate scope files.
    version  — print version information.
"""

from __future__ import annotations

import io
import sys

import typer


# Force UTF-8 on stdout/stderr so the CLI can emit non-ASCII glyphs (e.g.
# warning markers in localized messages) on Windows consoles, which default
# to cp1252 and would otherwise raise UnicodeEncodeError mid-run.
def _force_utf8(stream: object) -> object:
    enc = getattr(stream, "encoding", None)
    if enc and enc.lower() == "utf-8":
        return stream
    buf = getattr(stream, "buffer", None)
    if buf is None:
        return stream
    return io.TextIOWrapper(buf, encoding="utf-8", errors="replace", line_buffering=True)


sys.stdout = _force_utf8(sys.stdout)  # type: ignore[assignment]
sys.stderr = _force_utf8(sys.stderr)  # type: ignore[assignment]


from huntersec.cli.commands.htb import app as htb_app  # noqa: E402
from huntersec.cli.commands.run import run  # noqa: E402
from huntersec.cli.commands.scope import app as scope_app  # noqa: E402
from huntersec.cli.commands.thm import app as thm_app  # noqa: E402
from huntersec.cli.commands.version import version  # noqa: E402

app = typer.Typer(
    name="hunter",
    help="HunterSecV1 — autonomous offensive-security agent (ethical, open-source).",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

app.command("run")(run)
app.command("version")(version)
app.add_typer(scope_app, name="scope")
app.add_typer(htb_app, name="htb")
app.add_typer(thm_app, name="thm")


if __name__ == "__main__":
    app()
