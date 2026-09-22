"""Orchestration: compose the NVD + Paramify clients with pure ``core`` logic.

This layer does I/O and knows both clients, but imports *down* into ``clients``
and ``core`` — never *up* into ``cli``. The CLI passes clients + settings in,
which keeps these functions testable and front-end-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cvss_adjuster.app.clients.nvd import NvdClient
from cvss_adjuster.app.clients.paramify import ParamifyClient
from cvss_adjuster.app.settings import Settings
from cvss_adjuster.core.vuln.original_level import LevelPlan, plan_original_level
from cvss_adjuster.core.vuln.resolution import Resolution, resolve_level
from cvss_adjuster.core.vuln.scanner import ScannerFinding, higher_level
from cvss_adjuster.core.vuln.selection import DEFAULT_METRIC_KEYS, pick_metric


@dataclass
class ScoreResult:
    nvd_score: float | None
    winning_cve: str | None
    winning_vector: str | None
    selected: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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
        selected.append({"cve_id": cve_id, **metric})

    if not selected:
        return ScoreResult(None, None, None, [], warnings)

    winner = max(selected, key=lambda m: m["base_score"])
    return ScoreResult(
        nvd_score=winner["base_score"],
        winning_cve=winner["cve_id"],
        winning_vector=winner.get("vector"),
        selected=selected,
        warnings=warnings,
    )


# --- original risk rating -------------------------------------------------
#
# The workflow the customer actually asked for: score each container-scan issue
# against NVD, fall back to the scanner's own CVSS and then its severity
# category, and write the result to the issue's `originalLevel`.


@dataclass
class OriginalLevelResult:
    issue_id: str
    poam_id: str | None
    title: str | None
    cve_ids: list[str]
    current_level: str | None
    resolution: Resolution
    plan: LevelPlan
    applied: str = "pending"
    error: str | None = None


def merge_findings_for_issue(
    cve_ids: list[str], findings: dict[str, ScannerFinding]
) -> ScannerFinding | None:
    """Collapse an issue's CVEs into one scanner view.

    An issue can carry several CVEs, and the same "higher bar wins" rule that
    merges duplicate scan rows applies again here.
    """
    matched = [findings[c.strip().upper()] for c in cve_ids if c.strip().upper() in findings]
    if not matched:
        return None
    level: str | None = None
    cvss: float | None = None
    seen: set[str] = set()
    rows = 0
    for f in matched:
        level = higher_level(level, f.severity_level)
        if f.cvss is not None:
            cvss = f.cvss if cvss is None else max(cvss, f.cvss)
        seen.update(f.severities_seen or ([f.severity_level] if f.severity_level else []))
        rows += f.row_count
    return ScannerFinding(matched[0].cve_id, level, cvss, rows, tuple(sorted(seen)))


def select_issues(
    issues: list[dict[str, Any]],
    *,
    origin: str | None,
    scan_cves: set[str] | None,
) -> list[dict[str, Any]]:
    """Scope the run to one scan type.

    Two independent filters, because neither is sufficient alone. `origin.name`
    is the only scan-type signal the API exposes (there is no assessment id on
    an issue), but several assessments can share one mechanism element, so it
    cannot isolate a single assessment. Intersecting with the CVEs actually
    present in the supplied exports is what pins the run to the scans in hand.
    """
    selected = []
    for issue in issues:
        cve_ids = [c.strip().upper() for c in (issue.get("cveIds") or []) if c and c.strip()]
        if not cve_ids:
            continue
        if origin and ((issue.get("origin") or {}).get("name") or "") != origin:
            continue
        if scan_cves is not None and not any(c in scan_cves for c in cve_ids):
            continue
        selected.append(issue)
    return selected


def set_original_levels(
    paramify: ParamifyClient,
    nvd: NvdClient,
    settings: Settings,
    *,
    program_id: str | None = None,
    findings: dict[str, ScannerFinding] | None = None,
    origin: str | None = None,
    only_raise: bool = False,
    metric_keys: tuple[str, ...] = DEFAULT_METRIC_KEYS,
    write: bool = False,
) -> list[OriginalLevelResult]:
    """Resolve and sync `originalLevel` for a program's container-scan issues.

    One Paramify read, one batched NVD fetch, then a per-issue plan. Writes only
    happen for issues whose `originalLevel` actually changes, and only when
    `write` is true — otherwise the plan comes back unapplied for review.
    """
    program_id = program_id or settings.program_id
    findings = findings or {}
    scan_cves = set(findings) if findings else None

    issues = select_issues(
        paramify.get_issues(project_id=program_id), origin=origin, scan_cves=scan_cves
    )
    if not issues:
        return []

    all_cves: list[str] = []
    for issue in issues:
        all_cves.extend(issue.get("cveIds") or [])
    by_id = {r["cve_id"]: r for r in nvd.fetch_cves(all_cves)}

    results: list[OriginalLevelResult] = []
    for issue in issues:
        cve_ids = [c.strip().upper() for c in (issue.get("cveIds") or []) if c and c.strip()]
        score = score_cves(nvd, cve_ids, metric_keys=metric_keys, records_by_id=by_id)
        resolution = resolve_level(
            nvd_score=score.nvd_score,
            nvd_cve_id=score.winning_cve,
            finding=merge_findings_for_issue(cve_ids, findings),
        )
        # `originalLevel` is the field under test here, not `level` — `level`
        # already reflects any risk adjustment layered on top of it.
        current = issue.get("originalLevel")
        plan = plan_original_level(
            issue["id"],
            current_level=current,
            target_level=resolution.level,
            only_raise=only_raise,
        )

        result = OriginalLevelResult(
            issue_id=issue["id"],
            poam_id=issue.get("poamId"),
            title=issue.get("title"),
            cve_ids=cve_ids,
            current_level=current,
            resolution=resolution,
            plan=plan,
        )
        if plan.action != "set":
            result.applied = plan.action
        elif not write:
            result.applied = "would-set"
        else:
            try:
                paramify.update_issue(issue["id"], plan.body)
                result.applied = "set"
            except Exception as exc:  # reported per issue; one failure must not end the run
                result.applied = "error"
                result.error = f"{type(exc).__name__}: {exc}"
        results.append(result)
    return results


# --- scope resolution -----------------------------------------------------


class ScopeError(RuntimeError):
    """The requested assessment could not be turned into a usable scope."""


@dataclass
class ScopeResolution:
    """The assessment being adjusted, and the origin name that stands for it."""

    origin: str
    assessment: dict[str, Any]
    #: Other assessments on the same mechanism, workspace-wide. When this is
    #: non-empty the origin name alone cannot separate them, and the run rests on
    #: the operator's assertion that the others are in different programs.
    also_sharing: list[dict[str, Any]] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.assessment.get("name", "?"))

    @property
    def sharing_names(self) -> list[str]:
        return [str(a.get("name", "?")) for a in self.also_sharing]

    @property
    def shared(self) -> bool:
        return bool(self.also_sharing)


def resolve_scope(paramify: ParamifyClient, assessment: str | None) -> ScopeResolution:
    """Turn an assessment name or id into the ``origin.name`` its issues carry.

    Scope is always expressed as an assessment, because that is the unit the
    work is actually organized around. The API cannot filter by it — an issue
    carries no assessment id — so the assessment is resolved to its *mechanism
    element*, which is what appears as ``issue.origin.name``.

    That mapping is many-to-one. When other assessments share the mechanism they
    are returned in ``also_sharing`` so the caller can say what it is assuming:
    that within the target program this mechanism belongs to the named
    assessment alone. That holds whenever the others sit in other programs —
    ``projectId`` is enforced server-side — and the API offers no way to confirm
    it, since a program carries no list of its assessments.
    """
    if not assessment:
        raise ScopeError(
            "no assessment given. Scope is always an assessment: pass --assessment "
            "(or set ASSESSMENT) so the run records which one it adjusted."
        )

    assessments = paramify.list_assessments()
    needle = assessment.strip().lower()
    matched = [
        a
        for a in assessments
        if str(a.get("id", "")).lower() == needle or str(a.get("name") or "").lower() == needle
    ]
    if not matched:
        names = ", ".join(sorted(str(a.get("name") or "?") for a in assessments))
        raise ScopeError(f"no assessment named {assessment!r}. Available: {names}")

    found = matched[0]
    mechanism = (found.get("mechanism") or {}).get("name")
    if not mechanism:
        raise ScopeError(
            f"assessment {found.get('name')!r} has no mechanism element, so its issues "
            "carry no origin name to filter on"
        )

    sharing = [
        a
        for a in assessments
        if ((a.get("mechanism") or {}).get("name")) == mechanism and a.get("id") != found.get("id")
    ]
    return ScopeResolution(mechanism, found, sharing)
