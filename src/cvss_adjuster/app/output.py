"""Unified output — the one place text-vs-JSON lives, so no command re-implements it.

A command builds its result (dataclass / pydantic model / dict / list) and hands
it to ``emit``. The JSON branch is generic (dataclasses and pydantic models
included); human output is a per-command callback, or ``emit_rows`` for the common
list-of-dicts table. ``JSONOption`` declares the ``--json`` flag once for reuse.

Design goal: human output is tab-separated so it stays awk/cut-friendly, and
``--json`` gives stable machine output. That single contract is what makes the
plumbing tier composable in a pipeline.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Callable, Sequence
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


def emit_rows(
    rows: Sequence[dict[str, Any]], columns: Sequence[str], *, as_json: bool
) -> None:
    """Shortcut for list-of-dicts commands: JSON, or a tab-separated table."""
    emit(list(rows), as_json=as_json, human=lambda rs: table(rs, columns))


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)
