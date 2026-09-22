"""`score_cves`: pick the highest usable NVD base score across a CVE set."""

from cvss_adjuster.app.services import score_cves


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


def test_takes_the_max_across_the_set():
    nvd = FakeNvd([_record("CVE-1", 5.0), _record("CVE-2", 9.1)])
    result = score_cves(nvd, ["CVE-1", "CVE-2"])

    assert result.nvd_score == 9.1
    assert result.winning_cve == "CVE-2"


def test_warns_about_a_cve_missing_from_nvd():
    result = score_cves(FakeNvd([_record("CVE-1", 5.0)]), ["CVE-1", "CVE-404"])

    assert result.nvd_score == 5.0
    assert any("CVE-404" in w for w in result.warnings)


def test_a_record_with_no_usable_metric_yields_no_score():
    """The `Deferred`-with-metrics-stripped case: present, but nothing to use."""
    nvd = FakeNvd([{"cve_id": "CVE-1", "missing": False, "metrics": []}])
    result = score_cves(nvd, ["CVE-1"])

    assert result.nvd_score is None
    assert result.winning_cve is None
