"""Orchestration for the original-risk-rating workflow, with fake clients.

Covers what only exists once scans, NVD and Paramify are composed: scoping the
run to one scan type, choosing `originalLevel` (not `level`) as the field under
test, the ladder running per issue, and dry-run vs write.
"""

from __future__ import annotations

import pytest

from cvss_adjuster.app.services import (
    ScopeError,
    merge_findings_for_issue,
    resolve_scope,
    select_issues,
    set_original_levels,
)
from cvss_adjuster.app.settings import Settings
from cvss_adjuster.core.vuln.scanner import ScannerFinding

SETTINGS = Settings(paramify_api_key="k")


def _record(cve_id: str, score: float | None):
    metrics = (
        [
            {
                "metric_key": "cvssMetricV31",
                "type": "Primary",
                "source": "nvd@nist.gov",
                "vector": "CVSS:3.1/AV:N",
                "base_score": score,
                "version": "3.1",
            }
        ]
        if score is not None
        else []
    )
    return {"cve_id": cve_id, "missing": False, "metrics": metrics}


class FakeNvd:
    def __init__(self, records):
        self._records = {r["cve_id"]: r for r in records}
        self.calls: list[list[str]] = []

    def fetch_cves(self, cve_ids):
        self.calls.append(list(cve_ids))
        return [
            self._records.get(c, {"cve_id": c, "metrics": [], "missing": True})
            for c in dict.fromkeys(c.strip().upper() for c in cve_ids)
        ]


class FakeParamify:
    def __init__(self, issues):
        self._issues = issues
        self.patches: list[tuple[str, dict]] = []

    def get_issues(self, *, project_id=None, **_):
        return self._issues

    def update_issue(self, issue_id, body):
        self.patches.append((issue_id, body))
        return {"id": issue_id, **body}


def _issue(iid, cves, *, origin="Twistlock", original="NOT_SET", level="HIGH", poam=None):
    return {
        "id": iid,
        "poamId": poam or iid,
        "title": f"issue {iid}",
        "cveIds": cves,
        "origin": {"name": origin},
        "originalLevel": original,
        "level": level,
    }


# --- requirement: limit the run to container scans ------------------------


def test_scope_excludes_other_scanners():
    issues = [
        _issue("a", ["CVE-1"], origin="Twistlock"),
        _issue("b", ["CVE-2"], origin="Nessus"),
        _issue("c", ["CVE-3"], origin="Invicti"),
    ]
    picked = select_issues(issues, origin="Twistlock", scan_cves=None)
    assert [i["id"] for i in picked] == ["a"]


def test_scope_excludes_issues_absent_from_the_supplied_exports():
    """Two assessments can share one mechanism element, so origin alone is not
    enough to pin the run to the scans in hand."""
    issues = [_issue("a", ["CVE-1"]), _issue("b", ["CVE-9"])]
    picked = select_issues(issues, origin="Twistlock", scan_cves={"CVE-1"})
    assert [i["id"] for i in picked] == ["a"]


def test_scope_excludes_issues_with_no_cves():
    issues = [_issue("a", []), _issue("b", ["CVE-1"])]
    picked = select_issues(issues, origin=None, scan_cves=None)
    assert [i["id"] for i in picked] == ["b"]


def test_no_origin_filter_keeps_every_scanner():
    issues = [_issue("a", ["CVE-1"]), _issue("b", ["CVE-2"], origin="Nessus")]
    assert len(select_issues(issues, origin=None, scan_cves=None)) == 2


# --- requirement: an issue's several CVEs collapse to one view ------------


def test_multi_cve_issue_takes_the_higher_bar():
    findings = {
        "CVE-1": ScannerFinding("CVE-1", "LOW", 3.0),
        "CVE-2": ScannerFinding("CVE-2", "CRITICAL", None),
    }
    merged = merge_findings_for_issue(["CVE-1", "CVE-2"], findings)
    assert merged.severity_level == "CRITICAL"
    assert merged.cvss == 3.0


def test_multi_cve_issue_with_no_scan_match_is_none():
    findings = {"CVE-1": ScannerFinding("CVE-1", "LOW", None)}
    assert merge_findings_for_issue(["CVE-9"], findings) is None


# --- requirement: the ladder drives originalLevel -------------------------


def test_nvd_resolves_and_writes_original_level():
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="NOT_SET")])
    nvd = FakeNvd([_record("CVE-1", 9.5)])
    findings = {"CVE-1": ScannerFinding("CVE-1", "LOW", None)}

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock", findings=findings, write=True
    )

    assert result.resolution.source == "nvd"
    assert result.plan.target_level == "CRITICAL"
    assert result.applied == "set"
    assert paramify.patches == [("a", {"originalLevel": "CRITICAL"})]


def test_falls_through_to_scanner_severity_when_nvd_is_unusable():
    """The 'Deferred, metrics stripped' case — previously skipped entirely."""
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="NOT_SET")])
    nvd = FakeNvd([_record("CVE-1", None)])
    findings = {"CVE-1": ScannerFinding("CVE-1", "HIGH", None)}

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock", findings=findings, write=True
    )

    assert result.resolution.source == "scanner_severity"
    assert paramify.patches == [("a", {"originalLevel": "HIGH"})]


def test_scanner_cvss_sits_between_the_two():
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="NOT_SET")])
    nvd = FakeNvd([_record("CVE-1", None)])
    findings = {"CVE-1": ScannerFinding("CVE-1", "LOW", 8.2)}

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock", findings=findings, write=True
    )
    assert result.resolution.source == "scanner_cvss"
    assert paramify.patches == [("a", {"originalLevel": "HIGH"})]


def test_compares_against_original_level_not_level():
    """`level` carries any risk adjustment; `originalLevel` is the field asked for."""
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="CRITICAL", level="LOW")])
    nvd = FakeNvd([_record("CVE-1", 9.5)])

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock",
        findings={"CVE-1": ScannerFinding("CVE-1", "LOW", None)}, write=True,
    )

    assert result.current_level == "CRITICAL"
    assert result.applied == "noop"
    assert paramify.patches == []


# --- requirement: safe to run and rerun ----------------------------------


def test_dry_run_writes_nothing():
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="NOT_SET")])
    nvd = FakeNvd([_record("CVE-1", 9.5)])

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock",
        findings={"CVE-1": ScannerFinding("CVE-1", "LOW", None)}, write=False,
    )

    assert result.applied == "would-set"
    assert paramify.patches == []


def test_only_raise_blocks_the_downgrade():
    paramify = FakeParamify([_issue("a", ["CVE-1"], original="CRITICAL")])
    nvd = FakeNvd([_record("CVE-1", 2.0)])

    (result,) = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock",
        findings={"CVE-1": ScannerFinding("CVE-1", "LOW", None)},
        only_raise=True, write=True,
    )

    assert result.applied == "skip"
    assert result.plan.direction == "lower"
    assert paramify.patches == []


def test_one_failed_write_does_not_end_the_run():
    class Flaky(FakeParamify):
        def update_issue(self, issue_id, body):
            if issue_id == "a":
                raise RuntimeError("boom")
            return super().update_issue(issue_id, body)

    paramify = Flaky([_issue("a", ["CVE-1"]), _issue("b", ["CVE-2"])])
    nvd = FakeNvd([_record("CVE-1", 9.5), _record("CVE-2", 9.5)])
    findings = {
        "CVE-1": ScannerFinding("CVE-1", "LOW", None),
        "CVE-2": ScannerFinding("CVE-2", "LOW", None),
    }

    results = set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock", findings=findings, write=True
    )

    assert [r.applied for r in results] == ["error", "set"]
    assert "boom" in results[0].error


def test_nvd_is_fetched_once_for_the_whole_program():
    paramify = FakeParamify([_issue("a", ["CVE-1"]), _issue("b", ["CVE-1", "CVE-2"])])
    nvd = FakeNvd([_record("CVE-1", 5.0), _record("CVE-2", 5.0)])

    set_original_levels(
        paramify, nvd, SETTINGS, program_id="p", origin="Twistlock",
        findings={"CVE-1": ScannerFinding("CVE-1", "LOW", None)}, write=False,
    )
    assert len(nvd.calls) == 1


def test_empty_scope_returns_no_results():
    paramify = FakeParamify([_issue("a", ["CVE-1"], origin="Nessus")])
    assert (
        set_original_levels(
            paramify, FakeNvd([]), SETTINGS, program_id="p", origin="Twistlock"
        )
        == []
    )


# --- requirement: scope must be verifiable, not assumed -------------------


class FakeParamifyWithAssessments(FakeParamify):
    def __init__(self, issues, assessments):
        super().__init__(issues)
        self._assessments = assessments

    def list_assessments(self):
        return self._assessments


def _assessment(aid, name, mechanism):
    return {"id": aid, "name": name, "mechanism": {"name": mechanism}}


TWO_ON_ONE_MECHANISM = [
    _assessment("A1", "monthly-container-scan", "Twistlock"),
    _assessment("A2", "staging-container-scan", "Twistlock"),
]


def test_assessment_resolves_to_its_mechanism():
    paramify = FakeParamifyWithAssessments(
        [], [_assessment("A1", "monthly-container-scan", "Twistlock")]
    )

    assert resolve_scope(paramify, "monthly-container-scan").origin == "Twistlock"
    assert resolve_scope(paramify, "A1").origin == "Twistlock"
    assert resolve_scope(paramify, "MONTHLY-CONTAINER-SCAN").origin == "Twistlock"


def test_a_sole_assessment_on_a_mechanism_is_not_shared():
    paramify = FakeParamifyWithAssessments(
        [],
        [
            _assessment("A1", "monthly-host-scan", "Nessus"),
            _assessment("A2", "monthly-container-scan", "Twistlock"),
        ],
    )
    scope = resolve_scope(paramify, "monthly-container-scan")

    assert not scope.shared
    assert scope.sharing_names == []


def test_a_shared_mechanism_names_the_others():
    """The origin name cannot separate them, so the run must say what it assumes."""
    paramify = FakeParamifyWithAssessments([], TWO_ON_ONE_MECHANISM)
    scope = resolve_scope(paramify, "monthly-container-scan")

    assert scope.shared
    assert scope.name == "monthly-container-scan"
    assert scope.sharing_names == ["staging-container-scan"]


def test_no_assessment_is_an_error():
    paramify = FakeParamifyWithAssessments([], TWO_ON_ONE_MECHANISM)
    with pytest.raises(ScopeError, match="no assessment given"):
        resolve_scope(paramify, None)


def test_unknown_assessment_lists_what_is_available():
    paramify = FakeParamifyWithAssessments(
        [], [_assessment("A1", "monthly-container-scan", "Twistlock")]
    )
    with pytest.raises(ScopeError, match="monthly-container-scan"):
        resolve_scope(paramify, "nope")


def test_assessment_without_a_mechanism_is_an_error():
    paramify = FakeParamifyWithAssessments([], [{"id": "A1", "name": "bare", "mechanism": None}])
    with pytest.raises(ScopeError, match="no mechanism element"):
        resolve_scope(paramify, "bare")
