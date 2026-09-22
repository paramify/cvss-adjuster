"""``cvss-adjust set-original-levels`` — the original-risk-rating workflow.

Resolves each container-scan issue's original risk rating down a three-rung
ladder (NVD base score, then the scanner's own CVSS, then the scanner's severity
category) and writes it to the issue's ``originalLevel``.

Writes are opt-in. Without ``--apply`` this is a dry run reporting
``would-set`` / ``noop`` / ``skip``, which is the form meant to be reviewed
before anything touches a live POA&M.

The summary breaks results down **by which rung resolved them**, because that is
the thing to sanity-check: if the scanner-severity rung is carrying most of the
population, that is expected (a large share of scan rows carry a CVSS of 0) but
it is also exactly what a broken NVD fetch would look like.
"""

from __future__ import annotations

from collections import Counter

import typer

from cvss_adjuster.app import output
from cvss_adjuster.app.cli.context import Context
from cvss_adjuster.app.report import build_report, write_report
from cvss_adjuster.app.scans import load_scan_findings, summarize
from cvss_adjuster.app.services import OriginalLevelResult, resolve_scope
from cvss_adjuster.app.services import set_original_levels as run_levels
from cvss_adjuster.core.vuln.resolution import SOURCE_LABELS

_NONE = "—"
_COLUMNS = ("POAM", "CURRENT", "TARGET", "SOURCE", "SCORE", "ACTION", "TITLE")
_RIGHT = {4}
_TITLE_WIDTH = 34

_LEVEL_COLOR = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MODERATE": "yellow",
    "LOW": "green",
    "CHILL": "cyan",
    "NOT_SET": "bright_black",
}
_ACTION_COLOR = {
    "would-set": "green",
    "set": "green",
    "noop": "bright_black",
    "skip": "bright_black",
    "error": "bright_red",
}


def set_original_levels(
    ctx: typer.Context,
    program_id: str | None = typer.Option(None, "--program-id", help="Defaults to PROGRAM_ID"),
    scan_dir: str | None = typer.Option(
        None, "--scan-dir", help="Directory of scanner CSV exports. Defaults to SCAN_DIR."
    ),
    assessment: str | None = typer.Option(
        None, "--assessment", help="Assessment to adjust, by name or id. Defaults to ASSESSMENT."
    ),
    apply_changes: bool = typer.Option(
        False, "--apply", help="Write originalLevel back to Paramify"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Force a dry run even with --apply"),
    only_raise: bool = typer.Option(
        False, "--only-raise", help="Never lower an existing originalLevel"
    ),
    out: list[str] = typer.Option(
        [],
        "--out",
        metavar="PATH",
        help=(
            "Write the whole run to a file: .json for the full record, .csv for a "
            "table. Repeatable, so one run can produce both."
        ),
    ),
    json_out: output.JSONOption = False,
) -> None:
    """Resolve and sync each container-scan issue's original risk rating.

    Ladder: NVD base score, then the scanner's CVSS, then the scanner's severity
    category. A CVSS of 0 counts as absent at every rung. Idempotent — a rerun
    reports ``noop`` for issues already at the resolved level.
    """
    c: Context = ctx.obj
    write = apply_changes and not dry_run

    # Scope first, so a run always records which assessment it adjusted.
    scope = resolve_scope(c.paramify, assessment or c.settings.assessment)
    if scope.shared:
        # Printed unconditionally, --json included: this is what the run takes on
        # trust, and it belongs on the record for automated callers most of all.
        typer.secho(
            f"Assuming {scope.name!r} is the only assessment on mechanism "
            f"{scope.origin!r} in this program. Also on that mechanism workspace-wide: "
            f"{', '.join(scope.sharing_names)}. Verify in Paramify if unsure — the API "
            "cannot confirm it.",
            fg="yellow",
            err=True,
        )
    elif not json_out:
        typer.echo(
            f"Scope: assessment {scope.name!r} (origin {scope.origin!r}), "
            "the only assessment on that mechanism.",
            err=True,
        )

    directory = scan_dir or c.settings.scan_dir
    findings = {}
    scan_summary = None
    if directory:
        loaded = load_scan_findings(directory)
        findings = loaded.findings
        scan_summary = summarize(loaded)
        if not json_out:
            typer.echo(
                f"Scans: {scan_summary['files']} file(s), {scan_summary['rows_read']:,} rows "
                f"-> {scan_summary['cves']:,} CVEs "
                f"({scan_summary['with_usable_cvss']:,} with a usable CVSS, "
                f"{scan_summary['severity_conflicts']:,} with conflicting severities)",
                err=True,
            )
    elif not json_out:
        typer.echo(
            "No --scan-dir given: running NVD-only. Rungs 2 and 3 of the ladder "
            "(scanner CVSS, scanner severity) are unavailable without the exports.",
            err=True,
        )

    results = run_levels(
        c.paramify,
        c.nvd,
        c.settings,
        program_id=program_id,
        findings=findings,
        origin=scope.origin,
        only_raise=only_raise,
        write=write,
    )

    if out:
        # Built and written before rendering, so the files exist even if the
        # terminal output is interrupted or piped somewhere that goes away. A run
        # takes minutes against a real program; losing it to a broken pipe is not
        # a recoverable mistake.
        report = build_report(
            results,
            scope=scope,
            program_id=program_id or c.settings.program_id,
            scan_summary=scan_summary,
            wrote=write,
        )
        for target in out:
            typer.echo(f"Wrote {write_report(target, report, results)}", err=True)

    def human(rows: list[OriginalLevelResult]) -> None:
        if not rows:
            typer.echo("No matching issues in this program.", err=True)
            return
        if output.interactive():
            _render_table(rows)
        else:
            _render_tsv(rows)
        _render_summary(rows)
        if not write:
            typer.echo("(dry run: nothing written — pass --apply to write)", err=True)

    output.emit(results, as_json=json_out, human=human)


def _label(r: OriginalLevelResult) -> str:
    return r.poam_id or r.issue_id


def _row(r: OriginalLevelResult) -> list[str]:
    score = f"{r.resolution.score:.1f}" if r.resolution.score is not None else _NONE
    return [
        _label(r),
        r.current_level or "NOT_SET",
        r.resolution.level or _NONE,
        SOURCE_LABELS.get(r.resolution.source, r.resolution.source),
        score,
        r.applied,
        output._cell(r.title or ""),
    ]


def _render_tsv(rows: list[OriginalLevelResult]) -> None:
    typer.echo("\t".join(_COLUMNS))
    for r in rows:
        typer.echo("\t".join(_row(r)))


def _render_table(rows: list[OriginalLevelResult]) -> None:
    data = [_row(r) for r in rows]
    for i, row in enumerate(data):
        row[6] = _truncate(row[6], _TITLE_WIDTH)
        data[i] = row
    widths = [
        max(len(_COLUMNS[i]), *(len(row[i]) for row in data)) for i in range(len(_COLUMNS))
    ]
    header = "  ".join(
        _COLUMNS[i].rjust(widths[i]) if i in _RIGHT else _COLUMNS[i].ljust(widths[i])
        for i in range(len(_COLUMNS))
    )
    typer.secho(header, bold=True)
    for row in data:
        cells = []
        for i, raw in enumerate(row):
            padded = raw.rjust(widths[i]) if i in _RIGHT else raw.ljust(widths[i])
            cells.append(_style(i, raw, padded))
        typer.echo("  ".join(cells))


def _style(index: int, raw: str, padded: str) -> str:
    if index in (1, 2) and raw in _LEVEL_COLOR:
        return typer.style(padded, fg=_LEVEL_COLOR[raw])
    if index == 5 and raw in _ACTION_COLOR:
        return typer.style(padded, fg=_ACTION_COLOR[raw])
    return padded


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _render_summary(rows: list[OriginalLevelResult]) -> None:
    actions = Counter(r.applied for r in rows)
    sources = Counter(r.resolution.source for r in rows)
    directions = Counter(r.plan.direction for r in rows if r.plan.action == "set")

    typer.echo("", err=True)
    typer.secho(f"{len(rows):,} issues in scope", bold=True, err=True)
    typer.echo(
        "  actions:   "
        + ", ".join(f"{k} {v:,}" for k, v in sorted(actions.items(), key=lambda kv: -kv[1])),
        err=True,
    )
    typer.echo(
        "  resolved by: "
        + ", ".join(
            f"{SOURCE_LABELS.get(k, k)} {v:,}"
            for k, v in sorted(sources.items(), key=lambda kv: -kv[1])
        ),
        err=True,
    )
    if directions:
        typer.echo(
            "  changes:   "
            + ", ".join(f"{k} {v:,}" for k, v in sorted(directions.items(), key=lambda kv: -kv[1])),
            err=True,
        )
    lowered = directions.get("lower", 0)
    if lowered:
        typer.secho(
            f"  ! {lowered:,} issue(s) would have originalLevel LOWERED. "
            "Review before --apply, or rerun with --only-raise.",
            fg="yellow",
            err=True,
        )
    errors = [r for r in rows if r.error]
    for r in errors[:5]:
        typer.secho(f"  error {_label(r)}: {r.error}", fg="red", err=True)
    if len(errors) > 5:
        typer.secho(f"  … and {len(errors) - 5:,} more errors", fg="red", err=True)
