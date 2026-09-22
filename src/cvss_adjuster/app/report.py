"""Write a complete record of a run to a file.

Redirecting ``--json`` captures the per-issue rows and nothing else: the scope
assumption, the scan counts and the summary all go to stderr, so a redirected
run loses exactly the context needed to read it later. This writes one file
holding all of it.

Format follows the extension — ``.json`` for the full record, ``.csv`` for a
flat one-row-per-issue table that opens in a spreadsheet, which is how these get
reviewed in practice.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cvss_adjuster.app.output import jsonable
from cvss_adjuster.app.services import OriginalLevelResult, ScopeResolution
from cvss_adjuster.core.vuln.resolution import SOURCE_LABELS

CSV_COLUMNS = (
    "poam_id",
    "issue_id",
    "title",
    "cve_ids",
    "current_level",
    "target_level",
    "resolved_by",
    "score",
    "action",
    "direction",
    "applied",
    "detail",
)


class ReportError(ValueError):
    """The requested output path cannot be written as a report."""


def summarize_results(results: list[OriginalLevelResult]) -> dict[str, Any]:
    return {
        "issues": len(results),
        "actions": dict(Counter(r.applied for r in results).most_common()),
        "resolved_by": dict(Counter(r.resolution.source for r in results).most_common()),
        "directions": dict(
            Counter(r.plan.direction for r in results if r.plan.action == "set").most_common()
        ),
        "errors": sum(1 for r in results if r.error),
    }


def build_report(
    results: list[OriginalLevelResult],
    *,
    scope: ScopeResolution,
    program_id: str | None,
    scan_summary: dict[str, Any] | None,
    wrote: bool,
) -> dict[str, Any]:
    """Assemble the run record: what was asked, what was assumed, what came back."""
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "wrote": wrote,
        "dry_run": not wrote,
        "program_id": program_id,
        "scope": {
            "assessment": scope.name,
            "assessment_id": scope.assessment.get("id"),
            "origin": scope.origin,
            "mechanism_shared_with": scope.sharing_names,
            # Restated here because it is the run's central caveat and a file
            # read weeks later has no stderr to fall back on.
            "assumption": (
                f"{scope.name!r} is the only assessment on mechanism {scope.origin!r} "
                "in this program; the API cannot confirm it"
                if scope.shared
                else None
            ),
        },
        "scans": scan_summary,
        "summary": summarize_results(results),
        "results": jsonable(results),
    }


def _row(result: OriginalLevelResult) -> dict[str, Any]:
    return {
        "poam_id": result.poam_id or "",
        "issue_id": result.issue_id,
        "title": result.title or "",
        "cve_ids": " ".join(result.cve_ids),
        "current_level": result.current_level or "NOT_SET",
        "target_level": result.resolution.level or "",
        "resolved_by": SOURCE_LABELS.get(result.resolution.source, result.resolution.source),
        "score": "" if result.resolution.score is None else result.resolution.score,
        "action": result.plan.action,
        "direction": result.plan.direction,
        "applied": result.applied,
        "detail": result.resolution.detail,
    }


def write_report(
    path: str | Path, report: dict[str, Any], results: list[OriginalLevelResult]
) -> Path:
    """Write the run to ``path``, choosing the format from its extension.

    ``results`` is passed alongside the assembled report because the CSV form is
    built from the objects rather than the serialized nesting.
    """
    target = Path(path).expanduser()
    suffix = target.suffix.lower()
    if suffix not in (".json", ".csv"):
        raise ReportError(
            f"cannot write {target.name!r}: use a .json path for the full record "
            "or .csv for a flat table"
        )
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)

    if suffix == ".json":
        target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return target

    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for result in results:
            writer.writerow(_row(result))
    return target
