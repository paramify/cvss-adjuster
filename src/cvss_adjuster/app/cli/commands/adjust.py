"""``cvss-adjust adjust-program`` — the workflow.

Scores every CVE-bearing issue in a program against NVD and syncs a matching
risk-adjustment deviation onto each one. Writes are opt-in: without
``--post-deviations`` this is a dry run and reports ``would-create`` /
``would-update`` / ``unchanged``.

The command itself only parses args and renders; the work is in
``app.services.adjust_program`` plus the pure planners in ``core.vuln``.

Text output has two forms, picked by ``output.interactive()``: aligned columns
with a summary for a terminal, the original tab-separated rows for a pipe or a
redirect. A program can run to a hundred-odd rows, which is unreadable as raw
TSV and unusable as anything else if the TSV were dropped.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

import typer

from cvss_adjuster.app import output
from cvss_adjuster.app.cli.context import Context
from cvss_adjuster.app.services import IssueResult
from cvss_adjuster.app.services import adjust_program as run_adjust
from cvss_adjuster.core.vuln.selection import cvss_score_to_level

#: Shown for a score/level/CVE an issue does not have. Not a value the JSON emits.
_NONE = "—"

#: Display-only action for an issue that could not be scored, so it got no
#: deviation at all. ``deviation_action`` is null in the JSON for these.
_SKIPPED = "skipped"

_COLUMNS = ("POAM", "SCORE", "CURRENT", "ADJUSTED", "CVE", "ACTION", "TITLE")
_RIGHT = {1}  # SCORE reads better right-aligned under a decimal point
_TITLE_WIDTH = 36

#: Column indices that carry a severity level and an action, for styling.
_CURRENT_COL, _ADJUSTED_COL, _ACTION_COL = 2, 3, 5

_LEVEL_COLOR = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MODERATE": "yellow",
    "LOW": "green",
    "CHILL": "cyan",
}
_ACTION_COLOR = {
    "would-create": "green",
    "created": "green",
    "would-update": "yellow",
    "updated": "yellow",
    "unchanged": "bright_black",
    _SKIPPED: "bright_black",
}
#: Severity order, most severe first. Doubles as the summary ordering and as the
#: rank used to call an adjustment a raise or a drop.
_LEVEL_ORDER = ("CRITICAL", "HIGH", "MODERATE", "LOW", "CHILL")
_RANK = {level: i for i, level in enumerate(_LEVEL_ORDER)}


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
        if not rows:
            typer.echo("No CVE-bearing issues in this program.", err=True)
            return
        if output.interactive():
            _render_table(rows)
        else:
            _render_tsv(rows)
        if not write:
            typer.echo(
                "(dry run: nothing written — pass --post-deviations to apply)", err=True
            )

    output.emit(results, as_json=json_out, human=human)


def _label(r: IssueResult) -> str:
    return r.poam_id or r.issue_id


def _render_tsv(rows: Iterable[IssueResult]) -> None:
    """The original pipe-friendly form: one tab-separated row, warnings inline.

    Unchanged on purpose — anything already parsing this keeps working.
    """
    for r in rows:
        s = r.score
        nvd = _NONE if s.nvd_score is None else f"{s.nvd_score}({cvss_score_to_level(s.nvd_score)})"
        dev = f"\tdeviation={r.deviation_action}" if r.deviation_action else ""
        typer.echo(f"{_label(r)}\t{r.title or ''}\tNVD={nvd}\tCVE={s.winning_cve or _NONE}{dev}")
        for w in s.warnings:
            typer.echo(f"warn: {_label(r)}: {w}", err=True)


def _render_table(rows: list[IssueResult]) -> None:
    """Aligned columns, worst score first, then the warnings and a summary.

    Warnings are held back until after the table rather than printed per issue:
    stderr and stdout interleave on a terminal, and a warning landing mid-table
    shreds the column alignment it is sitting in.
    """
    ordered = sorted(rows, key=_severity_first)
    output.aligned(
        [_row(r) for r in ordered], _COLUMNS, right=_RIGHT, style=_style_cell
    )
    _render_warnings(ordered)
    _render_summary(rows)


def _severity_first(r: IssueResult) -> tuple[int, float, str]:
    """Scored issues before unscored, highest score first, then stable by label."""
    score = r.score.nvd_score
    return (1 if score is None else 0, -(score or 0.0), _label(r))


def _adjusted_level(r: IssueResult) -> str | None:
    """The level this run's deviation records — None when the issue never scored."""
    score = r.score.nvd_score
    return None if score is None else cvss_score_to_level(score)


def _current_level(r: IssueResult) -> str | None:
    """The issue's level as Paramify already has it, normalized for comparison."""
    return (r.current_level or "").strip().upper() or None


def _row(r: IssueResult) -> list[str]:
    score = r.score.nvd_score
    adjusted = _adjusted_level(r)
    current = _current_level(r)
    return [
        _label(r),
        _NONE if score is None else f"{score:.1f}",
        current or _NONE,
        adjusted or _NONE,
        r.score.winning_cve or _NONE,
        r.deviation_action or _SKIPPED,
        _truncate(r.title or "", _TITLE_WIDTH),
    ]


def _style_cell(index: int, raw: str, padded: str) -> str:
    """Colour ADJUSTED and ACTION; dim CURRENT and the em dash of an unscored row.

    CURRENT is deliberately dim: it is the "before" for comparison, and colouring
    both level columns the same way makes it hard to see which one is the outcome.
    """
    if raw == _NONE:
        return typer.style(padded, fg="bright_black")
    if index == _CURRENT_COL:
        return typer.style(padded, fg="bright_black")
    if index == _ADJUSTED_COL and raw in _LEVEL_COLOR:
        return typer.style(padded, fg=_LEVEL_COLOR[raw])
    if index == _ACTION_COL and raw in _ACTION_COLOR:
        return typer.style(padded, fg=_ACTION_COLOR[raw])
    return padded


def _render_warnings(rows: Iterable[IssueResult]) -> None:
    warnings = [(_label(r), w) for r in rows for w in r.score.warnings]
    if not warnings:
        return
    typer.echo(f"\n{len(warnings)} warning(s):", err=True)
    width = max(len(label) for label, _ in warnings)
    for label, w in warnings:
        typer.echo(f"  {label.ljust(width)}  {w}", err=True)


def _movement(r: IssueResult) -> str:
    """Where this issue's level lands relative to where Paramify has it now.

    ``unknown`` covers both an issue with no level set and one whose level is a
    value outside the CVSS bands — either way there is nothing to compare against,
    so it must not be silently counted as "same".
    """
    current, adjusted = _current_level(r), _adjusted_level(r)
    if current not in _RANK or adjusted not in _RANK:
        return "unknown"
    if _RANK[adjusted] < _RANK[current]:  # index 0 is the most severe
        return "raised"
    if _RANK[adjusted] > _RANK[current]:
        return "lowered"
    return "same"


def _render_summary(rows: list[IssueResult]) -> None:
    actions = Counter(r.deviation_action or _SKIPPED for r in rows)
    scored = [r for r in rows if _adjusted_level(r) is not None]
    levels = Counter(_adjusted_level(r) for r in scored)

    parts = [f"{len(rows)} issue(s)"]
    parts += [f"{n} {action}" for action, n in actions.most_common()]
    typer.echo(f"\n{' · '.join(parts)}", err=True)

    if levels:
        by_severity = [f"{levels[lv]} {lv.lower()}" for lv in _LEVEL_ORDER if levels.get(lv)]
        typer.echo(f"adjusted levels: {' · '.join(by_severity)}", err=True)

    moves = Counter(_movement(r) for r in scored)
    if moves:
        order = ("raised", "lowered", "same", "unknown")
        typer.echo(
            "vs current: " + " · ".join(f"{moves[m]} {m}" for m in order if moves.get(m)),
            err=True,
        )


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"
