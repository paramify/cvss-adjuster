"""``cvss-adjust score`` — max NVD CVSS base score across some CVEs.

A read-only one-shot: no Paramify call, no writes. Useful on its own, and the
quickest way to see which CVE in a set is driving an issue's level.
"""

from __future__ import annotations

import typer

from cvss_adjuster.app import output
from cvss_adjuster.app.cli.context import Context
from cvss_adjuster.app.services import ScoreResult, score_cves
from cvss_adjuster.core.vuln.selection import cvss_score_to_level


def score(
    ctx: typer.Context,
    cve_ids: list[str] = typer.Argument(..., help="One or more CVE IDs"),
    json_out: output.JSONOption = False,
) -> None:
    """Max NVD CVSS base score across the given CVEs.

    Exits 0 on a successful lookup even when nothing could be scored — check
    ``nvd_score`` (null when no CVE in the set had a usable metric), and read the
    warnings on stderr for why.
    """
    c: Context = ctx.obj
    result = score_cves(c.nvd, cve_ids)

    def human(r: ScoreResult) -> None:
        nvd = "—" if r.nvd_score is None else f"{r.nvd_score} ({cvss_score_to_level(r.nvd_score)})"
        typer.echo(f"NVD score:   {nvd}")
        typer.echo(f"Winning CVE: {r.winning_cve or '—'}")
        typer.echo(f"Vector:      {r.winning_vector or '—'}")
        for w in r.warnings:
            typer.echo(f"warn: {w}", err=True)

    output.emit(result, as_json=json_out, human=human)
