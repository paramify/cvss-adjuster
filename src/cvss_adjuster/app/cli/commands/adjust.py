"""``cvss-adjust adjust-program`` — the workflow.

Scores every CVE-bearing issue in a program against NVD and syncs a matching
risk-adjustment deviation onto each one. Writes are opt-in: without
``--post-deviations`` this is a dry run and reports ``would-create`` /
``would-update`` / ``unchanged``.

The command itself only parses args and renders; the work is in
``app.services.adjust_program`` plus the pure planners in ``core.vuln``.
"""

from __future__ import annotations

import typer

from cvss_adjuster.app import output
from cvss_adjuster.app.cli.context import Context
from cvss_adjuster.app.services import IssueResult
from cvss_adjuster.app.services import adjust_program as run_adjust
from cvss_adjuster.core.vuln.selection import cvss_score_to_level


def adjust_program(
    ctx: typer.Context,
    program_id: str | None = typer.Option(None, "--program-id", help="Defaults to PROGRAM_ID"),
    post_deviations: bool = typer.Option(
        False, "--post-deviations", help="Write deviations back to Paramify"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Force a dry run even with --post-deviations"
    ),
    json_out: output.JSONOption = False,
) -> None:
    """Score a program's CVE-bearing issues from NVD and sync their deviations.

    Idempotent: rerunning only rewrites deviations whose score or level actually
    moved, and it never touches a deviation this tool did not create. Exits 0 on a
    successful run, including one where the program has no CVE-bearing issues.
    """
    c: Context = ctx.obj
    write = post_deviations and not dry_run
    results = run_adjust(c.paramify, c.nvd, c.settings, program_id=program_id, write=write)

    def human(rows: list[IssueResult]) -> None:
        for r in rows:
            label = r.poam_id or r.issue_id
            s = r.score
            if s.nvd_score is None:
                nvd = "—"
            else:
                nvd = f"{s.nvd_score}({cvss_score_to_level(s.nvd_score)})"
            dev = f"\tdeviation={r.deviation_action}" if r.deviation_action else ""
            typer.echo(f"{label}\t{r.title or ''}\tNVD={nvd}\tCVE={s.winning_cve or '—'}{dev}")
            for w in s.warnings:
                typer.echo(f"warn: {label}: {w}", err=True)
        if not rows:
            typer.echo("No CVE-bearing issues in this program.", err=True)
        elif not write:
            typer.echo(
                "(dry run: nothing written — pass --post-deviations to apply)", err=True
            )

    output.emit(results, as_json=json_out, human=human)
