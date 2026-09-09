"""``cvss-adjust programs`` — list programs.

Doubles as the smallest authenticated request, so it is the fastest way to prove
a key and URL are working before running the workflow.
"""

from __future__ import annotations

import typer

from cvss_adjuster.app import output
from cvss_adjuster.app.cli.context import Context

COLUMNS = ("id", "name")


def programs(
    ctx: typer.Context,
    json_out: output.JSONOption = False,
) -> None:
    """List programs. The cheapest authenticated call — use it to verify auth."""
    c: Context = ctx.obj
    output.emit_rows(c.paramify.list_programs(), COLUMNS, as_json=json_out)
