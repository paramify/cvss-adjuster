"""Writing a run to a file.

The point of `--out` over `--json > file` is that stderr context — the scope
assumption, the scan counts, the summary — survives into the artifact.
"""

from __future__ import annotations

import csv
import json

import pytest

from cvss_adjuster.app.report import ReportError, build_report, write_report
from cvss_adjuster.app.services import OriginalLevelResult, ScopeResolution
from cvss_adjuster.core.vuln.original_level import plan_original_level
from cvss_adjuster.core.vuln.resolution import resolve_level
from cvss_adjuster.core.vuln.scanner import ScannerFinding


def _result(issue_id="ISS-1", current="NOT_SET", nvd=None, severity="HIGH"):
    resolution = resolve_level(
        nvd_score=nvd,
        nvd_cve_id="CVE-1",
        finding=ScannerFinding("CVE-1", severity, None),
    )
    plan = plan_original_level(
        issue_id, current_level=current, target_level=resolution.level
    )
    return OriginalLevelResult(
        issue_id=issue_id,
        poam_id="FM-1",
        title="openssl",
        cve_ids=["CVE-1"],
        current_level=current,
        resolution=resolution,
        plan=plan,
        applied="would-set",
    )


def _scope(shared=False):
    return ScopeResolution(
        origin="Twistlock",
        assessment={"id": "A1", "name": "monthly-container-scan"},
        also_sharing=[{"id": "A2", "name": "staging-container-scan"}] if shared else [],
    )


def _report(results=None, *, shared=False, scans=None, wrote=False):
    return build_report(
        results if results is not None else [_result()],
        scope=_scope(shared),
        program_id="P1",
        scan_summary=scans if scans is not None else {"files": 3, "cves": 42},
        wrote=wrote,
    )


def test_json_report_carries_scope_scans_and_summary(tmp_path):
    """The three things a redirected --json loses."""
    path = write_report(tmp_path / "run.json", _report(), [_result()])
    data = json.loads(path.read_text())

    assert data["scope"]["assessment"] == "monthly-container-scan"
    assert data["scans"] == {"files": 3, "cves": 42}
    assert data["summary"]["issues"] == 1
    assert data["summary"]["resolved_by"] == {"scanner_severity": 1}
    assert data["results"][0]["issue_id"] == "ISS-1"


def test_a_shared_mechanism_records_the_assumption(tmp_path):
    """A file read weeks later has no stderr to fall back on."""
    path = write_report(tmp_path / "run.json", _report(shared=True), [_result()])
    scope = json.loads(path.read_text())["scope"]

    assert "only assessment on mechanism" in scope["assumption"]
    assert scope["mechanism_shared_with"] == ["staging-container-scan"]


def test_an_unshared_mechanism_records_no_assumption(tmp_path):
    path = write_report(tmp_path / "run.json", _report(), [_result()])
    assert json.loads(path.read_text())["scope"]["assumption"] is None


def test_dry_run_is_recorded(tmp_path):
    dry = json.loads(write_report(tmp_path / "a.json", _report(), [_result()]).read_text())
    live = json.loads(
        write_report(tmp_path / "b.json", _report(wrote=True), [_result()]).read_text()
    )

    assert dry["dry_run"] is True and dry["wrote"] is False
    assert live["dry_run"] is False and live["wrote"] is True


def test_csv_is_one_flat_row_per_issue(tmp_path):
    results = [_result("ISS-1"), _result("ISS-2", current="HIGH", nvd=9.5)]
    path = write_report(tmp_path / "run.csv", _report(results), results)
    rows = list(csv.DictReader(path.open()))

    assert [r["issue_id"] for r in rows] == ["ISS-1", "ISS-2"]
    assert rows[0]["resolved_by"] == "scanner severity"
    assert rows[0]["target_level"] == "HIGH"
    assert rows[1]["resolved_by"] == "NVD"
    assert rows[1]["score"] == "9.5"
    assert rows[1]["direction"] == "raise"
    assert rows[0]["cve_ids"] == "CVE-1"


def test_summary_counts_actions_directions_and_errors():
    failed = _result("ISS-3")
    failed.applied = "error"
    failed.error = "boom"
    report = _report([_result(), failed])

    assert report["summary"]["issues"] == 2
    assert report["summary"]["errors"] == 1
    assert report["summary"]["actions"]["would-set"] == 1


def test_an_unknown_extension_is_refused(tmp_path):
    with pytest.raises(ReportError, match="use a .json path"):
        write_report(tmp_path / "run.txt", _report(), [_result()])


def test_missing_parent_directories_are_created(tmp_path):
    path = write_report(tmp_path / "deep" / "nested" / "run.json", _report(), [_result()])
    assert path.exists()


def test_extension_matching_is_case_insensitive(tmp_path):
    assert write_report(tmp_path / "run.JSON", _report(), [_result()]).exists()
    assert write_report(tmp_path / "run.CSV", _report(), [_result()]).exists()
