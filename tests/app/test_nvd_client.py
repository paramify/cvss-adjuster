"""Transport-level guarantees for the NVD client.

The bug these pin caused the customer's run to die: the key was sent as a query
parameter (which NVD rejects), and the rejection was swallowed by a retry that
continued anonymously — so the run paced itself for 50 requests/30s while
actually being limited to 5, and throttled thousands of requests later.
"""

from __future__ import annotations

import httpx
import pytest

from cvss_adjuster.app.clients.nvd import (
    ANON_BATCH_PAUSE,
    KEYED_BATCH_PAUSE,
    NvdAuthError,
    NvdClient,
)
from cvss_adjuster.app.settings import Settings


def _vuln(cve_id: str, score: float | None = 7.5, *, status: str = "Analyzed") -> dict:
    metrics = (
        {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "baseScore": score,
                        "vectorString": "CVSS:3.1/AV:N",
                        "version": "3.1",
                    },
                }
            ]
        }
        if score is not None
        else {}
    )
    return {"cve": {"id": cve_id, "vulnStatus": status, "metrics": metrics}}


def _client(handler, *, api_key: str | None = None, batch_size: int = 100) -> NvdClient:
    settings = Settings(
        nvd_api_key=api_key, nvd_batch_size=batch_size, paramify_api_key="x"
    )
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return NvdClient(http, settings)


def test_api_key_is_sent_as_a_header_never_as_a_query_parameter():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json={"vulnerabilities": [_vuln("CVE-1")]})

    _client(handler, api_key="secret-key").fetch_cves(["CVE-1"])

    assert seen["headers"].get("apikey") == "secret-key"
    assert "apiKey" not in seen["params"]
    assert "apikey" not in {k.lower() for k in seen["params"]}


def test_no_api_key_sends_no_header():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = {k.lower() for k in request.headers}
        return httpx.Response(200, json={"vulnerabilities": []})

    _client(handler).fetch_cves(["CVE-1"])
    assert "apikey" not in seen["headers"]


def test_a_rejected_key_fails_loudly_instead_of_continuing_anonymously():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, headers={"message": "Invalid apiKey."})

    with pytest.raises(NvdAuthError, match="rejected the API key"):
        _client(handler, api_key="bad").fetch_cves(["CVE-1"])


def test_cves_are_batched_with_the_comma_joined_plural_parameter():
    """`cveIds` batches; the repeated `cveId=A&cveId=B` form silently drops extras."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        calls.append(params)
        ids = params["cveIds"].split(",")
        return httpx.Response(200, json={"vulnerabilities": [_vuln(i) for i in ids]})

    ids = [f"CVE-2026-{n:04d}" for n in range(250)]
    records = _client(handler, api_key="k", batch_size=100).fetch_cves(ids)

    assert len(calls) == 3  # 100 + 100 + 50
    assert [len(c["cveIds"].split(",")) for c in calls] == [100, 100, 50]
    assert "cveId" not in calls[0]
    assert len(records) == 250


def test_duplicate_cves_are_deduped_before_the_request():
    calls: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        ids = dict(request.url.params)["cveIds"].split(",")
        calls.append(ids)
        return httpx.Response(200, json={"vulnerabilities": [_vuln(i) for i in ids]})

    records = _client(handler, api_key="k").fetch_cves(
        ["CVE-1", "cve-1", " CVE-1 ", "CVE-2"]
    )
    assert calls == [["CVE-1", "CVE-2"]]
    assert len(records) == 2


def test_a_cve_absent_from_the_response_is_marked_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [_vuln("CVE-1")]})

    records = _client(handler, api_key="k").fetch_cves(["CVE-1", "CVE-2"])
    by_id = {r["cve_id"]: r for r in records}
    assert by_id["CVE-1"]["missing"] is False
    assert by_id["CVE-2"]["missing"] is True


def test_a_deferred_cve_with_no_metrics_parses_to_an_empty_metric_list():
    """Present in NVD, but nothing usable — the case that must fall through."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"vulnerabilities": [_vuln("CVE-1", None, status="Deferred")]}
        )

    (record,) = _client(handler, api_key="k").fetch_cves(["CVE-1"])
    assert record["missing"] is False
    assert record["metrics"] == []
    assert record["vuln_status"] == "Deferred"


def test_pacing_matches_whichever_rate_limit_applies():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    assert _client(handler, api_key="k").batch_pause == KEYED_BATCH_PAUSE
    assert _client(handler).batch_pause == ANON_BATCH_PAUSE
