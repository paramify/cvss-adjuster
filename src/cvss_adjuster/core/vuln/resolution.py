"""The original-risk-rating fallback ladder. Pure; no I/O.

Order, stated by the customer and confirmed on the call — "looking at NVD first,
scanner severity second, and the category third":

    1. NVD          usable CVSS base score for the CVE
    2. SCANNER_CVSS the scanner's own numeric CVSS on the scan row
    3. SCANNER_SEV  the scanner's severity category (critical/high/medium/low)

Two properties of this ladder are easy to get wrong, and both were observed in
the real data rather than assumed:

**Presence in NVD is not the same as a usable score.** Sampling CVEs the scanner
scored 0 found all of them present in NVD, but three in eight carried no metric
at all because NVD had marked them ``Deferred`` and stripped the scores. One was
``Deferred`` *and* scored. So the gate is "did a metric survive selection", never
``vulnStatus`` and never mere presence — testing presence is what made the
previous implementation skip issues it should have rated.

**Zero is absent at every rung.** A 0.0 is how both NVD and the scanner encode
"we have no opinion". Treating it as a real score maps a finding the scanner
called ``critical`` down to the lowest level. A large share of scan rows carry
CVSS 0, so this is the common path, not an edge case.
"""

from __future__ import annotations

from dataclasses import dataclass

from cvss_adjuster.core.vuln.scanner import ScannerFinding
from cvss_adjuster.core.vuln.selection import cvss_score_to_level

SOURCE_NVD = "nvd"
SOURCE_SCANNER_CVSS = "scanner_cvss"
SOURCE_SCANNER_SEVERITY = "scanner_severity"
SOURCE_UNRESOLVED = "unresolved"

# Human labels for the report Luis reviews before anything is written.
SOURCE_LABELS: dict[str, str] = {
    SOURCE_NVD: "NVD",
    SOURCE_SCANNER_CVSS: "scanner CVSS",
    SOURCE_SCANNER_SEVERITY: "scanner severity",
    SOURCE_UNRESOLVED: "unresolved",
}


@dataclass(frozen=True)
class Resolution:
    """Which rung produced the level, and the evidence behind it."""

    level: str | None
    source: str
    score: float | None = None
    cve_id: str | None = None
    detail: str = ""

    @property
    def resolved(self) -> bool:
        return self.level is not None

    @property
    def source_label(self) -> str:
        return SOURCE_LABELS.get(self.source, self.source)


def usable_score(score: float | None) -> float | None:
    """A base score is usable only when it is present and greater than zero."""
    if score is None:
        return None
    return score if score > 0 else None


def resolve_level(
    *,
    nvd_score: float | None = None,
    nvd_cve_id: str | None = None,
    finding: ScannerFinding | None = None,
) -> Resolution:
    """Walk the ladder and return the first rung that yields a level.

    ``nvd_score`` is whatever metric selection already chose (highest base score
    across the issue's CVEs); passing ``None`` means NVD had nothing usable.
    """
    nvd = usable_score(nvd_score)
    if nvd is not None:
        return Resolution(
            level=cvss_score_to_level(nvd),
            source=SOURCE_NVD,
            score=nvd,
            cve_id=nvd_cve_id,
            detail=f"NVD base score {nvd}",
        )

    if finding is not None:
        scanner_cvss = usable_score(finding.cvss)
        if scanner_cvss is not None:
            return Resolution(
                level=cvss_score_to_level(scanner_cvss),
                source=SOURCE_SCANNER_CVSS,
                score=scanner_cvss,
                cve_id=finding.cve_id,
                detail=f"scanner CVSS {scanner_cvss} (no usable NVD score)",
            )

        if finding.severity_level is not None:
            conflict = (
                f", highest of {'/'.join(finding.severities_seen)}"
                if finding.has_conflict
                else ""
            )
            return Resolution(
                level=finding.severity_level,
                source=SOURCE_SCANNER_SEVERITY,
                score=None,
                cve_id=finding.cve_id,
                detail=(
                    f"scanner severity {finding.severity_level}{conflict} "
                    "(no usable NVD or scanner CVSS score)"
                ),
            )

    return Resolution(
        level=None,
        source=SOURCE_UNRESOLVED,
        score=None,
        cve_id=nvd_cve_id or (finding.cve_id if finding else None),
        detail="no usable NVD score, scanner CVSS, or scanner severity",
    )
