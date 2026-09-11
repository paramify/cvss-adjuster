"""Pure deviation logic: build the desired deviation, decide create/update/noop.

No HTTP. ``plan_deviation`` takes the deviations already returned inline on a
Paramify issue and returns a ``DeviationPlan`` the service layer executes (or, for
``--dry-run``, just reports). Keeping the decision pure makes reruns idempotent
and lets it be tested with plain data — no HTTP mocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from cvss_adjuster.core.vuln.selection import cvss_score_to_level

# Stable prefix marking a deviation this tool created, so we update our own rather
# than stacking duplicates — and never touch a human-authored one.
DEVIATION_SIGNATURE = "NVD CVSS max base score"


@dataclass
class DeviationPlan:
    action: Literal["create", "update", "noop"]
    issue_id: str
    body: dict[str, Any] | None = None
    deviation_id: str | None = None
    existing: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)


def build_description(
    nvd_score: float,
    winning_cve: str,
    cve_ids: list[str],
    label: str,
    vector: str | None = None,
) -> str:
    cve_list = ", ".join(cve_ids)
    winning = f"winning CVE: {winning_cve}"
    if vector:
        winning += f", vector {vector}"
    return f"{DEVIATION_SIGNATURE} {nvd_score} ({winning}). Issue {label}. CVEs: {cve_list}."


def find_managed_deviations(
    deviations: list[dict[str, Any]] | None, *, deviation_type: str
) -> list[dict[str, Any]]:
    """Deviations this tool created (our type + signature prefix)."""
    return [
        d
        for d in (deviations or [])
        if d.get("type") == deviation_type
        and (d.get("description") or "").startswith(DEVIATION_SIGNATURE)
    ]


def _body(
    description: str,
    adjusted_level: str,
    *,
    status: str,
    deviation_type: str,
    method: str,
) -> dict[str, Any]:
    return {
        "description": description,
        "method": method,
        "type": deviation_type,
        "deviationMetadata": {"status": status, "adjustedLevel": adjusted_level},
    }


def plan_deviation(
    issue_id: str,
    *,
    nvd_score: float,
    winning_cve: str,
    cve_ids: list[str],
    vector: str | None,
    existing_deviations: list[dict[str, Any]] | None,
    deviation_type: str,
    method: str,
    default_status: str,
    label: str | None = None,
) -> DeviationPlan:
    """Decide whether to create, update, or leave alone this issue's deviation."""
    label = label or issue_id
    description = build_description(nvd_score, winning_cve, cve_ids, label, vector)
    adjusted_level = cvss_score_to_level(nvd_score)

    managed = find_managed_deviations(existing_deviations, deviation_type=deviation_type)
    warnings: list[str] = []
    if len(managed) > 1:
        warnings.append(
            f"{len(managed)} tool-created {deviation_type} deviations on issue {label}; "
            "updating the first and leaving the rest. Consider deleting the extras."
        )

    if not managed:
        body = _body(
            description,
            adjusted_level,
            status=default_status,
            deviation_type=deviation_type,
            method=method,
        )
        return DeviationPlan("create", issue_id, body=body, warnings=warnings)

    existing = managed[0]
    meta = existing.get("deviationMetadata") or {}
    # Compare descriptions *normalized*: the API appends a trailing newline when it
    # stores one, so a byte-exact comparison against what we generate never matches
    # and every rerun would plan a pointless update of a row that is already correct.
    already_matches = (
        (existing.get("description") or "").strip() == description.strip()
        and existing.get("type") == deviation_type
        and existing.get("method") == method
        and meta.get("adjustedLevel") == adjusted_level
    )
    if already_matches:
        return DeviationPlan(
            "noop",
            issue_id,
            existing=existing,
            deviation_id=existing.get("id"),
            warnings=warnings,
        )

    # Preserve a human-set acceptance status; only resync the fields we own.
    status = meta.get("status") or default_status
    body = _body(
        description,
        adjusted_level,
        status=status,
        deviation_type=deviation_type,
        method=method,
    )
    return DeviationPlan(
        "update",
        issue_id,
        body=body,
        deviation_id=existing.get("id"),
        existing=existing,
        warnings=warnings,
    )
