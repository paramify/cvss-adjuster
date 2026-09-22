"""Load scanner exports (Twistlock container scans) off disk.

I/O only: find the CSVs, pull the three columns that matter, hand them to
``core.vuln.scanner`` for normalization and merging. Lives in ``app`` because it
touches the filesystem; every rule about what the values *mean* stays in ``core``.

Column names are matched case- and space-insensitively against a set of known
aliases rather than by exact header text, because the three observed monthly
exports arrive under different filenames from the same pipeline and header
drift is the likeliest way this silently breaks. A missing required column
raises instead of yielding an empty result, so a bad export cannot look like
"no findings".
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvss_adjuster.core.vuln.scanner import (
    ScannerFinding,
    UnknownSeverityError,
    merge_rows,
    normalize_severity,
    parse_cvss,
)

CVE_COLUMNS = ("cve id", "cveid", "cve", "cve_id")
CVSS_COLUMNS = ("cvss", "cvss score", "cvss_score", "base score")
SEVERITY_COLUMNS = ("severity", "sev", "severity level")


class ScanLoadError(RuntimeError):
    """The export could not be read, or lacks a column the ladder depends on."""


@dataclass
class ScanLoadResult:
    findings: dict[str, ScannerFinding]
    files: list[Path] = field(default_factory=list)
    rows_read: int = 0
    rows_skipped: int = 0
    unknown_severities: dict[str, int] = field(default_factory=dict)

    @property
    def cve_ids(self) -> set[str]:
        return set(self.findings)


def _index_headers(fieldnames: Sequence[str] | None) -> dict[str, str]:
    return {(name or "").strip().lower(): name for name in (fieldnames or [])}


def _pick(headers: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if candidate in headers:
            return headers[candidate]
    return None


def find_scan_files(scan_dir: str | Path) -> list[Path]:
    root = Path(scan_dir).expanduser()
    if not root.exists():
        raise ScanLoadError(f"scan directory not found: {root}")
    if root.is_file():
        return [root]
    files = sorted(p for p in root.rglob("*.csv") if p.is_file())
    if not files:
        raise ScanLoadError(f"no .csv files under {root}")
    return files


def load_scan_findings(
    scan_dir: str | Path, *, strict_severity: bool = True
) -> ScanLoadResult:
    """Read every CSV under ``scan_dir`` into one merged finding per CVE.

    ``strict_severity=False`` downgrades an unmapped severity word from fatal to
    counted-and-skipped, for the case where a new export has to be triaged
    without blocking the run. The count is always reported either way.
    """
    files = find_scan_files(scan_dir)
    rows: list[tuple[str, str | None, float | None]] = []
    rows_read = 0
    rows_skipped = 0
    unknown: dict[str, int] = {}

    for path in files:
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            headers = _index_headers(reader.fieldnames)
            cve_col = _pick(headers, CVE_COLUMNS)
            sev_col = _pick(headers, SEVERITY_COLUMNS)
            cvss_col = _pick(headers, CVSS_COLUMNS)
            if cve_col is None:
                raise ScanLoadError(
                    f"{path.name}: no CVE column (looked for {', '.join(CVE_COLUMNS)})"
                )
            if sev_col is None and cvss_col is None:
                raise ScanLoadError(
                    f"{path.name}: neither a severity nor a CVSS column — "
                    "the fallback ladder has nothing to stand on"
                )

            for row in reader:
                rows_read += 1
                cve_id = (row.get(cve_col) or "").strip().upper()
                if not cve_id.startswith("CVE-"):
                    rows_skipped += 1
                    continue
                raw_sev = row.get(sev_col) if sev_col else None
                try:
                    level = normalize_severity(raw_sev)
                except UnknownSeverityError:
                    key = (raw_sev or "").strip()
                    unknown[key] = unknown.get(key, 0) + 1
                    if strict_severity:
                        raise
                    level = None
                cvss = parse_cvss(row.get(cvss_col) if cvss_col else None)
                rows.append((cve_id, level, cvss))

    return ScanLoadResult(
        findings=merge_rows(rows),
        files=files,
        rows_read=rows_read,
        rows_skipped=rows_skipped,
        unknown_severities=unknown,
    )


def summarize(result: ScanLoadResult) -> dict[str, Any]:
    """Counts for the run header, so the operator sees what was actually loaded."""
    conflicts = sum(1 for f in result.findings.values() if f.has_conflict)
    with_cvss = sum(1 for f in result.findings.values() if f.cvss is not None)
    with_sev = sum(1 for f in result.findings.values() if f.severity_level is not None)
    return {
        "files": len(result.files),
        "rows_read": result.rows_read,
        "rows_skipped": result.rows_skipped,
        "cves": len(result.findings),
        "with_usable_cvss": with_cvss,
        "with_severity": with_sev,
        "severity_conflicts": conflicts,
        "unknown_severities": result.unknown_severities,
    }
