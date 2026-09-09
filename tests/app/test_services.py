"""Orchestration tests: the score -> plan -> apply loop, with fake clients.

No HTTP. These cover the parts that only exist once the two clients are composed:
issue filtering, the shared NVD fetch, and dry-run vs write.
"""

from cvss_adjuster.app.services import adjust_program, score_cves
from cvss_adjuster.app.settings import Settings

SETTINGS = Settings(
    paramify_api_key="k", deviation_type="RISK_ADJUSTMENT",
    deviation_method="EXAMINE", deviation_status="PENDING",
)


def _record(cve_id, score, *, version="cvssMetricV31", mtype="Primary"):
    return {
        "cve_id": cve_id,
        "missing": False,
        "metrics": [
            {
                "metric_key": version,
                "type": mtype,
                "source": "nvd@nist.gov",
                "vector": f"CVSS:3.1/{cve_id}",
                "base_score": score,
                "version": "3.1",
            }
        ],
    }


class FakeNvd:
    def __init__(self, records):
        self._records = {r["cve_id"]: r for r in records}
        self.calls = []

    def fetch_cves(self, cve_ids):
        self.calls.append(list(cve_ids))
        return [
            self._records.get(c.upper(), {"cve_id": c.upper(), "metrics": [], "missing": True})
            for c in dict.fromkeys(c.strip().upper() for c in cve_ids)
        ]


class FakeParamify:
    def __init__(self, issues):
        self._issues = issues
        self.created = []
        self.updated = []

    def get_issues(self, **kwargs):
        return self._issues

    def create_deviation(self, issue_id, body):
        self.created.append((issue_id, body))
        return {"id": "dev-new", **body}

    def update_deviation(self, issue_id, deviation_id, body):
        self.updated.append((issue_id, deviation_id, body))
        return {"id": deviation_id, **body}


def test_score_cves_takes_the_max_across_the_set():
    nvd = FakeNvd([_record("CVE-1", 5.0), _record("CVE-2", 9.1)])
    result = score_cves(nvd, ["CVE-1", "CVE-2"])
    assert result.nvd_score == 9.1
    assert result.winning_cve == "CVE-2"


def test_score_cves_warns_about_a_cve_missing_from_nvd():
    nvd = FakeNvd([_record("CVE-1", 5.0)])
    result = score_cves(nvd, ["CVE-1", "CVE-MISSING"])
    assert result.nvd_score == 5.0
    assert any("CVE-MISSING" in w for w in result.warnings)


def test_adjust_program_skips_issues_without_cves():
    paramify = FakeParamify([
        {"id": "ISS-1", "poamId": "P-1", "title": "Log4j", "cveIds": ["CVE-1"]},
        {"id": "ISS-2", "poamId": "P-2", "title": "No CVEs", "cveIds": []},
        {"id": "ISS-3", "poamId": "P-3", "title": "Null CVEs"},
    ])
    nvd = FakeNvd([_record("CVE-1", 7.5)])
    results = adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1")
    assert [r.issue_id for r in results] == ["ISS-1"]


def test_adjust_program_fetches_nvd_once_for_the_whole_program():
    paramify = FakeParamify([
        {"id": "ISS-1", "cveIds": ["CVE-1"]},
        {"id": "ISS-2", "cveIds": ["CVE-2"]},
    ])
    nvd = FakeNvd([_record("CVE-1", 7.5), _record("CVE-2", 4.2)])
    adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1")
    # One batched call for every CVE in the program, not one call per issue.
    assert nvd.calls == [["CVE-1", "CVE-2"]]


def test_adjust_program_defaults_to_a_dry_run():
    paramify = FakeParamify([{"id": "ISS-1", "poamId": "P-1", "cveIds": ["CVE-1"]}])
    nvd = FakeNvd([_record("CVE-1", 9.5)])
    results = adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1")
    assert results[0].deviation_action == "would-create"
    assert paramify.created == []


def test_adjust_program_writes_when_asked():
    paramify = FakeParamify([{"id": "ISS-1", "poamId": "P-1", "cveIds": ["CVE-1"]}])
    nvd = FakeNvd([_record("CVE-1", 9.5)])
    results = adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1", write=True)
    assert results[0].deviation_action == "created"
    assert len(paramify.created) == 1
    issue_id, body = paramify.created[0]
    assert issue_id == "ISS-1"
    assert body["deviationMetadata"]["adjustedLevel"] == "CRITICAL"


def test_adjust_program_reruns_as_unchanged():
    """The idempotency guarantee, end to end: a second run writes nothing."""
    paramify = FakeParamify([{"id": "ISS-1", "poamId": "P-1", "cveIds": ["CVE-1"]}])
    nvd = FakeNvd([_record("CVE-1", 9.5)])
    adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1", write=True)
    _, body = paramify.created[0]

    # Feed the just-created deviation back as the issue's inline deviation.
    paramify._issues[0]["deviations"] = [{"id": "dev-new", **body}]
    results = adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1", write=True)
    assert results[0].deviation_action == "unchanged"
    assert len(paramify.created) == 1  # still just the first one


def test_adjust_program_on_an_empty_program_returns_nothing():
    paramify = FakeParamify([])
    nvd = FakeNvd([])
    assert adjust_program(paramify, nvd, SETTINGS, program_id="PRJ-1") == []
