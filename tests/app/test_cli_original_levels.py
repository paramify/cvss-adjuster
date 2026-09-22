"""CLI wiring for `set-original-levels` — no network.

Exercises scope resolution, the scan-dir plumbing, the dry-run contract, and the
text/JSON output forms.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import cvss_adjuster.app.cli.main as main
from cvss_adjuster.app.services import ScopeError
from cvss_adjuster.app.settings import Settings

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

HEADER = "Registry,Repository,CVE ID,Severity,CVSS,Description\n"
SCAN_ROWS = "r,repo,CVE-1,high,0,d\nr,repo,CVE-2,critical,0,d\n"

SOLE = [{"id": "A1", "name": "monthly-container-scan", "mechanism": {"name": "Twistlock"}}]
SHARED = SOLE + [
    {"id": "A2", "name": "staging-container-scan", "mechanism": {"name": "Twistlock"}}
]


def _plain(text: str) -> str:
    return _ANSI.sub("", text)


class FakeParamify:
    def __init__(self, assessments=None):
        self.patches = []
        self._assessments = SOLE if assessments is None else assessments

    def list_assessments(self):
        return self._assessments

    def get_issues(self, **kwargs):
        return [
            {
                "id": "ISS-1", "poamId": "POAM-1", "title": "openssl",
                "cveIds": ["CVE-1"], "origin": {"name": "Twistlock"},
                "originalLevel": "NOT_SET", "level": "NOT_SET",
            },
            {
                "id": "ISS-2", "poamId": "POAM-2", "title": "nessus finding",
                "cveIds": ["CVE-2"], "origin": {"name": "Nessus"},
                "originalLevel": "NOT_SET", "level": "NOT_SET",
            },
        ]

    def update_issue(self, issue_id, body):
        self.patches.append((issue_id, body))
        return {"id": issue_id, **body}

    def close(self):
        pass


class FakeNvd:
    """No usable metric, so the ladder must fall through to scanner severity."""

    def fetch_cves(self, cve_ids):
        return [
            {"cve_id": c.upper(), "missing": False, "metrics": []}
            for c in dict.fromkeys(x.strip().upper() for x in cve_ids)
        ]


@pytest.fixture(autouse=True)
def _no_output_env(monkeypatch):
    monkeypatch.delenv("CVSS_ADJUST_JSON", raising=False)
    monkeypatch.delenv("CVSS_ADJUST_PLAIN", raising=False)


@pytest.fixture
def scans(tmp_path):
    (tmp_path / "scan.csv").write_text(HEADER + SCAN_ROWS, encoding="utf-8")
    return tmp_path


@pytest.fixture
def paramify():
    return FakeParamify()


def _ctx(monkeypatch, paramify):
    monkeypatch.setattr(
        main,
        "build_context",
        lambda: SimpleNamespace(
            # scan_dir/assessment pinned: Settings() otherwise reads the developer's
            # .env, and a local value would silently feed real data into these tests.
            settings=Settings(paramify_api_key="k", scan_dir=None, assessment=None),
            paramify=paramify,
            nvd=FakeNvd(),
            http=None,
            close=lambda: None,
        ),
    )


@pytest.fixture(autouse=True)
def _default_ctx(monkeypatch, paramify):
    _ctx(monkeypatch, paramify)


def _run(scans, *extra):
    return runner.invoke(
        main.app,
        ["set-original-levels", "--program-id", "P1", "--scan-dir", str(scans),
         "--assessment", "monthly-container-scan", *extra],
    )


# --- the dry-run contract -------------------------------------------------


def test_dry_run_reports_without_writing(scans, paramify):
    result = _run(scans)
    assert result.exit_code == 0
    assert paramify.patches == []
    assert "would-set" in _plain(result.output)
    assert "dry run" in _plain(result.output)


def test_apply_writes_original_level(scans, paramify):
    assert _run(scans, "--apply").exit_code == 0
    assert paramify.patches == [("ISS-1", {"originalLevel": "HIGH"})]


def test_dry_run_flag_overrides_apply(scans, paramify):
    _run(scans, "--apply", "--dry-run")
    assert paramify.patches == []


# --- scope ----------------------------------------------------------------


def test_scope_excludes_other_scanners(scans):
    rows = json.loads(_run(scans, "--json").output)
    assert [r["issue_id"] for r in rows] == ["ISS-1"]


def test_a_sole_assessment_reports_its_scope_without_a_warning(scans):
    out = _plain(_run(scans).output)
    assert "the only assessment on that mechanism" in out
    assert "Assuming" not in out


def test_a_shared_mechanism_states_what_is_assumed(monkeypatch, scans):
    shared = FakeParamify(assessments=SHARED)
    _ctx(monkeypatch, shared)
    out = _plain(_run(scans).output)

    assert "Assuming 'monthly-container-scan' is the only assessment" in out
    assert "staging-container-scan" in out


def test_the_assumption_survives_json_mode(monkeypatch, scans):
    """--json must not hide a safety statement; stdout stays clean JSON."""
    _ctx(monkeypatch, FakeParamify(assessments=SHARED))
    result = _run(scans, "--json")

    assert "Assuming 'monthly-container-scan'" in _plain(result.stderr)
    json.loads(result.stdout)


def test_naming_no_assessment_raises_a_scope_error(scans):
    result = runner.invoke(
        main.app, ["set-original-levels", "--program-id", "P1", "--scan-dir", str(scans)]
    )
    assert isinstance(result.exception, ScopeError)
    assert "no assessment given" in str(result.exception)


def test_a_scope_error_reaches_the_user_as_a_message_not_a_traceback(monkeypatch, capsys):
    """`run()` is the layer that turns a typed error into a clean exit."""

    def boom():
        raise ScopeError("no assessment given")

    monkeypatch.setattr(main, "build_context", boom)
    monkeypatch.setattr("sys.argv", ["cvss-adjust", "programs"])
    with pytest.raises(SystemExit) as exc:
        main.run()

    err = _plain(capsys.readouterr().err)
    assert exc.value.code == 1
    assert "Error:" in err
    assert "no assessment given" in err
    assert "Traceback" not in err


def test_unknown_assessment_lists_what_exists(scans):
    result = runner.invoke(
        main.app,
        ["set-original-levels", "--program-id", "P1", "--scan-dir", str(scans),
         "--assessment", "does-not-exist"],
    )
    assert isinstance(result.exception, ScopeError)
    assert "monthly-container-scan" in str(result.exception)


# --- output ---------------------------------------------------------------


def test_json_carries_the_resolution_provenance(scans):
    (row,) = json.loads(_run(scans, "--json").output)

    assert row["resolution"]["source"] == "scanner_severity"
    assert row["resolution"]["level"] == "HIGH"
    assert row["plan"]["action"] == "set"


def test_summary_reports_the_rung_that_resolved_each_issue(scans):
    out = _plain(_run(scans).output)
    assert "1 issues in scope" in out
    assert "scanner severity 1" in out


def test_missing_scan_dir_warns_that_the_ladder_is_nvd_only(scans):
    result = runner.invoke(
        main.app,
        ["set-original-levels", "--program-id", "P1", "--assessment", "monthly-container-scan"],
    )
    assert result.exit_code == 0
    assert "NVD-only" in _plain(result.output)


def test_bad_scan_dir_fails_loudly(tmp_path):
    result = runner.invoke(
        main.app,
        ["set-original-levels", "--program-id", "P1", "--assessment", "monthly-container-scan",
         "--scan-dir", str(tmp_path / "nope")],
    )
    assert result.exit_code != 0
