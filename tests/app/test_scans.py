"""Reading scanner exports off disk.

Header drift is the likeliest silent breakage: the three observed monthly
exports arrive under different filenames from the same pipeline, so columns are
matched by alias rather than exact text, and a missing one is fatal rather than
empty.
"""

from __future__ import annotations

import pytest

from cvss_adjuster.app.scans import ScanLoadError, load_scan_findings, summarize
from cvss_adjuster.core.vuln.scanner import UnknownSeverityError

HEADER = "Registry,Repository,CVE ID,Severity,CVSS,Description\n"


def _write(tmp_path, name, body, header=HEADER):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + body, encoding="utf-8")
    return path


def test_reads_severity_and_cvss(tmp_path):
    _write(tmp_path, "scan.csv", "r,repo,CVE-2026-1,high,0,desc\nr,repo,CVE-2026-2,low,7.5,desc\n")
    result = load_scan_findings(tmp_path)

    assert result.findings["CVE-2026-1"].severity_level == "HIGH"
    assert result.findings["CVE-2026-1"].cvss is None  # 0 means absent
    assert result.findings["CVE-2026-2"].cvss == 7.5


def test_walks_subdirectories_and_merges_across_months(tmp_path):
    _write(tmp_path, "2026.06/a.csv", "r,repo,CVE-2026-1,low,0,d\n")
    _write(tmp_path, "2026.07/b_different_name.csv", "r,repo,CVE-2026-1,critical,0,d\n")
    result = load_scan_findings(tmp_path)

    assert len(result.files) == 2
    assert result.findings["CVE-2026-1"].severity_level == "CRITICAL"
    assert result.findings["CVE-2026-1"].row_count == 2


def test_column_aliases_survive_header_drift(tmp_path):
    _write(
        tmp_path, "scan.csv", "r,repo,CVE-2026-1,high,7.5,d\n",
        header="Registry,Repository,cve_id,SEVERITY,CVSS Score,Description\n",
    )
    assert load_scan_findings(tmp_path).findings["CVE-2026-1"].cvss == 7.5


def test_non_cve_rows_are_skipped_not_fatal(tmp_path):
    _write(
        tmp_path,
        "scan.csv",
        "r,repo,,high,0,d\nr,repo,COMPLIANCE-1,high,0,d\nr,repo,CVE-2026-1,high,0,d\n",
    )
    result = load_scan_findings(tmp_path)

    assert set(result.findings) == {"CVE-2026-1"}
    assert result.rows_skipped == 2


def test_missing_cve_column_is_fatal(tmp_path):
    _write(tmp_path, "scan.csv", "r,repo,high,0\n", header="Registry,Repository,Severity,CVSS\n")
    with pytest.raises(ScanLoadError, match="no CVE column"):
        load_scan_findings(tmp_path)


def test_missing_both_severity_and_cvss_is_fatal(tmp_path):
    """Without either, the ladder has no rungs 2 or 3 — better to say so."""
    _write(
        tmp_path,
        "scan.csv",
        "r,repo,CVE-2026-1,d\n",
        header="Registry,Repository,CVE ID,Description\n",
    )
    with pytest.raises(ScanLoadError, match="neither a severity nor a CVSS"):
        load_scan_findings(tmp_path)


def test_missing_directory_is_fatal(tmp_path):
    with pytest.raises(ScanLoadError, match="scan directory not found"):
        load_scan_findings(tmp_path / "nope")


def test_directory_with_no_csvs_is_fatal(tmp_path):
    (tmp_path / "notes.txt").write_text("hi", encoding="utf-8")
    with pytest.raises(ScanLoadError, match="no .csv files"):
        load_scan_findings(tmp_path)


def test_unknown_severity_is_fatal_by_default(tmp_path):
    _write(tmp_path, "scan.csv", "r,repo,CVE-2026-1,spicy,0,d\n")
    with pytest.raises(UnknownSeverityError):
        load_scan_findings(tmp_path)


def test_unknown_severity_can_be_counted_instead(tmp_path):
    _write(tmp_path, "scan.csv", "r,repo,CVE-2026-1,spicy,0,d\n")
    result = load_scan_findings(tmp_path, strict_severity=False)

    assert result.unknown_severities == {"spicy": 1}
    assert result.findings["CVE-2026-1"].severity_level is None


def test_bom_prefixed_header_is_handled(tmp_path):
    path = tmp_path / "scan.csv"
    path.write_text("﻿" + HEADER + "r,repo,CVE-2026-1,high,0,d\n", encoding="utf-8")
    assert "CVE-2026-1" in load_scan_findings(tmp_path).findings


def test_summary_counts(tmp_path):
    _write(
        tmp_path,
        "scan.csv",
        "r,repo,CVE-2026-1,high,0,d\n"
        "r,repo,CVE-2026-1,low,5.0,d\n"
        "r,repo,CVE-2026-2,low,0,d\n",
    )
    summary = summarize(load_scan_findings(tmp_path))

    assert summary["cves"] == 2
    assert summary["rows_read"] == 3
    assert summary["with_usable_cvss"] == 1
    assert summary["with_severity"] == 2
    assert summary["severity_conflicts"] == 1
