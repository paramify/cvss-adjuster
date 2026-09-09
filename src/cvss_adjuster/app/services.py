"""Orchestration: compose the NVD + Paramify clients with pure ``core`` logic.

This layer does I/O and knows both clients, but imports *down* into ``clients``
and ``core`` — never *up* into ``cli``. The CLI passes clients + settings in,
which keeps these functions testable and front-end-agnostic: the CLI and any
future scheduled job call the same two functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cvss_adjuster.app.clients.nvd import NvdClient
from cvss_adjuster.app.clients.paramify import ParamifyClient
from cvss_adjuster.app.settings import Settings
from cvss_adjuster.core.vuln.deviation import DeviationPlan, plan_deviation
from cvss_adjuster.core.vuln.scoring import recompute_from_vector
from cvss_adjuster.core.vuln.selection import DEFAULT_METRIC_KEYS, pick_metric


@dataclass
class ScoreResult:
    nvd_score: float | None
    computed_score: float | None
    winning_cve: str | None
    winning_vector: str | None
    selected: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class IssueResult:
    issue_id: str
    poam_id: str | None
    title: str | None
    cve_ids: list[str]
    current_level: str | None
    score: ScoreResult
    deviation: dict[str, Any] | None = None
    deviation_action: str | None = None


def score_cves(
    nvd: NvdClient,
    cve_ids: list[str],
    *,
    metric_keys: tuple[str, ...] = DEFAULT_METRIC_KEYS,
    records_by_id: dict[str, dict[str, Any]] | None = None,
) -> ScoreResult:
    """Max NVD base score across a CVE set; reuses a shared record cache if given."""
    if records_by_id is None:
        records = nvd.fetch_cves(cve_ids)
        records_by_id = {r["cve_id"]: r for r in records}

    selected: list[dict[str, Any]] = []
    warnings: list[str] = []
    for cve_id in dict.fromkeys(c.strip().upper() for c in cve_ids):
        record = records_by_id.get(cve_id)
        if record is None or record.get("missing"):
            warnings.append(f"{cve_id}: not in NVD response")
            continue
        metric = pick_metric(record["metrics"], metric_keys)
        if metric is None:
            warnings.append(f"{cve_id}: no {'/'.join(metric_keys)} metric")
            continue
        entry = {"cve_id": cve_id, **metric}
        entry["computed_score"] = recompute_from_vector(metric.get("vector"))
        selected.append(entry)

    if not selected:
        return ScoreResult(None, None, None, None, [], warnings)

    winner = max(selected, key=lambda m: m["base_score"])
    return ScoreResult(
        nvd_score=winner["base_score"],
        computed_score=winner.get("computed_score"),
        winning_cve=winner["cve_id"],
        winning_vector=winner.get("vector"),
        selected=selected,
        warnings=warnings,
    )


def _apply_plan(
    paramify: ParamifyClient, plan: DeviationPlan, *, write: bool
) -> tuple[str, dict[str, Any] | None]:
    if plan.action == "noop":
        return "unchanged", plan.existing
    if not write:
        return f"would-{plan.action}", plan.existing  # dry-run
    if plan.action == "create":
        return "created", paramify.create_deviation(plan.issue_id, plan.body or {})
    return "updated", paramify.update_deviation(
        plan.issue_id, plan.deviation_id or "", plan.body or {}
    )


def adjust_program(
    paramify: ParamifyClient,
    nvd: NvdClient,
    settings: Settings,
    *,
    program_id: str | None = None,
    metric_keys: tuple[str, ...] = DEFAULT_METRIC_KEYS,
    write: bool = False,
) -> list[IssueResult]:
    """Issues with cveIds -> NVD max score per issue -> idempotent deviation sync.

    One Paramify read (deviations ride along inline) and one batched NVD fetch for
    the whole program; writes happen only for issues whose deviation actually needs
    to change. With ``write=False`` the actions come back as ``would-*``.
    """
    program_id = program_id or settings.program_id
    issues = [i for i in paramify.get_issues(project_id=program_id) if i.get("cveIds")]
    if not issues:
        return []

    all_cves: list[str] = []
    for issue in issues:
        all_cves.extend(issue.get("cveIds") or [])
    records = nvd.fetch_cves(all_cves)
    by_id = {r["cve_id"]: r for r in records}

    results: list[IssueResult] = []
    for issue in issues:
        cve_ids = issue.get("cveIds") or []
        score = score_cves(nvd, cve_ids, metric_keys=metric_keys, records_by_id=by_id)
        result = IssueResult(
            issue_id=issue["id"],
            poam_id=issue.get("poamId"),
            title=issue.get("title"),
            cve_ids=cve_ids,
            current_level=issue.get("level"),
            score=score,
        )

        if score.nvd_score is not None:
            plan = plan_deviation(
                issue["id"],
                nvd_score=score.nvd_score,
                winning_cve=score.winning_cve or "",
                cve_ids=cve_ids,
                vector=score.winning_vector,
                existing_deviations=issue.get("deviations"),
                label=issue.get("poamId") or issue["id"],
                deviation_type=settings.deviation_type,
                method=settings.deviation_method,
                default_status=settings.deviation_status,
            )
            score.warnings.extend(plan.warnings)
            action, deviation = _apply_plan(paramify, plan, write=write)
            result.deviation_action = action
            result.deviation = deviation

        results.append(result)
    return results
