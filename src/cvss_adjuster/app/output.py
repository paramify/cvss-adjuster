"""Unified output — the one place text-vs-JSON lives, so no command re-implements it.

A command builds its result (dataclass / pydantic model / dict / list) and hands
it to ``emit``. The JSON branch is generic (dataclasses and pydantic models
included); human output is a per-command callback, or ``emit_rows`` for the common
list-of-dicts table. ``JSONOption`` declares the ``--json`` flag once for reuse.

Design goal: ``--json`` is the stable machine format, and text output adapts to
where it is going. A terminal gets aligned, headed columns; a pipe or a redirect
gets the same rows tab-separated, so awk/cut keep working unchanged. That single
contract is what makes the plumbing tier composable in a pipeline *and* readable
by a human, without a flag to remember either way.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
from collections.abc import Callable, Collection, Sequence
from enum import Enum
from typing import Annotated, Any

import typer

#: Reusable ``--json`` flag. Put ``json_out: output.JSONOption = False`` in a
#: command signature instead of re-declaring the option each time.
JSONOption = Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")]

_TRUTHY = {"1", "true", "yes", "on"}


def json_enabled(flag: bool) -> bool:
    """Whether to emit JSON: the ``--json`` flag, or ``CVSS_ADJUST_JSON`` in the environment.

    The env var lets an agent (or a CI job) opt into machine output once for the
    whole session instead of threading ``--json`` through every call.
    """
    return flag or os.environ.get("CVSS_ADJUST_JSON", "").strip().lower() in _TRUTHY


def interactive() -> bool:
    """Whether text output should be rendered for a human reading a terminal.

    True only when stdout is a TTY, so ``| awk`` and ``> file`` still receive the
    tab-separated rows. ``CVSS_ADJUST_PLAIN=1`` forces the tab-separated form even
    on a terminal, which is the escape hatch for a script that allocates a TTY
    (``script``, some CI runners) and still wants parseable output.
    """
    if os.environ.get("CVSS_ADJUST_PLAIN", "").strip().lower() in _TRUTHY:
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):  # stream replaced, or already closed
        return False


def jsonable(obj: Any) -> Any:
    """Coerce dataclasses / pydantic models / enums into JSON-serializable data.

    Public so anything that needs to hand back the same shape ``--json`` emits
    can reuse it rather than re-implementing the coercion.
    """
    if isinstance(obj, list):
        return [jsonable(x) for x in obj]
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "model_dump"):  # pydantic model
        return obj.model_dump(exclude_none=True)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return jsonable(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    return obj


def emit_json(data: Any) -> None:
    """Print ``data`` as indented, JSON-serializable output."""
    typer.echo(json.dumps(jsonable(data), indent=2, default=str))


def emit(data: Any, *, as_json: bool, human: Callable[[Any], None]) -> None:
    """Print ``data`` as indented JSON (``--json``/``CVSS_ADJUST_JSON``) or via ``human``."""
    if json_enabled(as_json):
        emit_json(data)
    else:
        human(data)


def table(rows: Sequence[dict[str, Any]], columns: Sequence[str]) -> None:
    """Tab-separated rows for a list of dicts — pipe/awk-friendly human output."""
    for row in rows:
        typer.echo("\t".join(_cell(row.get(c)) for c in columns))


#: Signature of an ``aligned`` cell styler: (column index, raw value, padded cell).
Styler = Callable[[int, str, str], str]


def aligned(
    rows: Sequence[Sequence[str]],
    headers: Sequence[str],
    *,
    right: Collection[int] = (),
    style: Styler | None = None,
) -> None:
    """Column-aligned table with a header row — the terminal form of ``table``.

    ``style`` is handed the *padded* cell and returns the string to print. Styling
    after padding is what keeps ANSI escapes out of the width arithmetic; colour
    the raw value instead and every column to the right of a coloured one drifts
    by the length of the escape codes.
    """
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[: len(widths)]):
            widths[i] = max(widths[i], len(cell))

    def render(cells: Sequence[str], styler: Styler | None) -> str:
        out = []
        last = len(cells) - 1
        for i, cell in enumerate(cells):
            if i in right:
                pad = cell.rjust(widths[i])
            elif i == last:
                pad = cell  # no trailing whitespace on the final column
            else:
                pad = cell.ljust(widths[i])
            out.append(styler(i, cell, pad) if styler else pad)
        return "  ".join(out)

    typer.echo(render(headers, lambda _i, _raw, pad: typer.style(pad, bold=True)))
    for row in rows:
        typer.echo(render(row, style))


def emit_rows(
    rows: Sequence[dict[str, Any]], columns: Sequence[str], *, as_json: bool
) -> None:
    """Shortcut for list-of-dicts commands: JSON, aligned columns, or tab-separated."""

    def human(rs: Sequence[dict[str, Any]]) -> None:
        if interactive():
            aligned([[_cell(r.get(c)) for c in columns] for r in rs], [c.upper() for c in columns])
        else:
            table(rs, columns)

    emit(list(rows), as_json=as_json, human=human)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)
