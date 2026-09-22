"""NVD CVE client: fetch CVEs in batches and normalize their CVSS metrics.

Transport concerns only — batching, authentication, pacing, and shaping raw NVD
JSON into flat metric dicts. Metric *selection* lives in ``core``.

Two corrections over the original implementation, both confirmed against the
live API rather than the documentation:

* **The API key goes in a header, not the query string.** Sent as a query
  parameter NVD answers ``404 Invalid parameter: apiKey.``; sent as a header the
  same request is accepted. The previous version passed it as a parameter and,
  on the resulting 404, silently retried *without* it — so every caller ran
  unauthenticated at 5 requests/30s while pacing for the keyed 50/30s limit, and
  a program with a few thousand CVEs throttled and died mid-run.
* **A bad key now fails loudly.** Falling back to anonymous access turned a
  one-line configuration mistake into a rate-limit failure thousands of requests
  later, which is the hardest possible place to diagnose it.

``cveIds`` (plural, comma-joined) is a real NVD parameter and does batch — this
is not the repeated ``cveId=A&cveId=B`` form, which silently ignores everything
after the first value.
"""

from __future__ import annotations

import time
from typing import Any, cast

import httpx

from cvss_adjuster.app.settings import Settings

METRIC_KEYS = ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40")

# NVD's published limits: 5 requests / 30s anonymous, 50 / 30s with a key. The
# pauses sit just outside each, since tripping the limit costs far more than the
# wait. Anonymous runs are slow by design, not by accident.
KEYED_BATCH_PAUSE = 0.6
ANON_BATCH_PAUSE = 6.5


class NvdAuthError(RuntimeError):
    """The configured NVD API key was rejected."""


class NvdClient:
    def __init__(self, http: httpx.Client, settings: Settings) -> None:
        self._http = http
        self._url = settings.nvd_url
        self._api_key = settings.nvd_api_key
        self._batch_size = settings.nvd_batch_size

    @property
    def batch_pause(self) -> float:
        return KEYED_BATCH_PAUSE if self._api_key else ANON_BATCH_PAUSE

    def fetch_cves(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        """Return one record per CVE: ``cve_id``, ``vuln_status``, ``metrics[]``."""
        ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c and c.strip()))
        found: dict[str, dict[str, Any]] = {
            i: {"cve_id": i, "metrics": [], "missing": True} for i in ids
        }
        size = self._batch_size
        for start in range(0, len(ids), size):
            batch = ids[start : start + size]
            for vuln in self._fetch_batch(batch):
                parsed = _parse_vuln(vuln)
                if parsed["cve_id"] in found:
                    found[parsed["cve_id"]] = parsed
            if start + size < len(ids):
                time.sleep(self.batch_pause)
        return [found[i] for i in ids]

    def _fetch_batch(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        resp = self._http.get(
            self._url, params={"cveIds": ",".join(cve_ids)}, headers=headers
        )
        if resp.status_code == 404 and "apikey" in (
            resp.headers.get("message", "") or ""
        ).lower():
            raise NvdAuthError(
                "NVD rejected the API key (NVD_API_KEY). Fix or unset it — the "
                "previous behaviour of silently continuing unauthenticated caused "
                "rate-limit failures thousands of requests later."
            )
        resp.raise_for_status()
        return cast("list[dict[str, Any]]", resp.json().get("vulnerabilities", []))


def _parse_vuln(vulnerability: dict[str, Any]) -> dict[str, Any]:
    cve = vulnerability.get("cve", {})
    metrics: list[dict[str, Any]] = []
    for key in METRIC_KEYS:
        for block in (cve.get("metrics") or {}).get(key) or []:
            data = block.get("cvssData") or {}
            if data.get("baseScore") is None:
                continue
            metrics.append(
                {
                    "metric_key": key,
                    "type": block.get("type", "Secondary"),
                    "source": block.get("source", ""),
                    "vector": data.get("vectorString", ""),
                    "base_score": float(data["baseScore"]),
                    "version": str(data.get("version", "")),
                }
            )
    return {
        "cve_id": cve.get("id", "UNKNOWN"),
        "vuln_status": cve.get("vulnStatus"),
        "metrics": metrics,
        "missing": False,
    }
