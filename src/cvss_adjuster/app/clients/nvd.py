"""NVD CVE client: fetch CVEs in batches and normalize their CVSS metrics.

Transport concerns only — batching, the retry-without-apiKey dance, and shaping
raw NVD JSON into flat metric dicts. Metric *selection* lives in ``core``.
"""

from __future__ import annotations

import time
from typing import Any, cast

import httpx

from cvss_adjuster.app.settings import Settings

METRIC_KEYS = ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40")


class NvdClient:
    def __init__(self, http: httpx.Client, settings: Settings) -> None:
        self._http = http
        self._url = settings.nvd_url
        self._api_key = settings.nvd_api_key

    def fetch_cves(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        """Return one record per CVE: ``cve_id``, ``vuln_status``, ``metrics[]``."""
        ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids))
        found: dict[str, dict[str, Any]] = {
            i: {"cve_id": i, "metrics": [], "missing": True} for i in ids
        }
        for start in range(0, len(ids), 100):
            batch = ids[start : start + 100]
            for vuln in self._fetch_batch(batch):
                parsed = _parse_vuln(vuln)
                found[parsed["cve_id"]] = parsed
            if start + 100 < len(ids):
                time.sleep(0.6)
        return [found[i] for i in ids]

    def _fetch_batch(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        for use_key in (True, False):
            params: dict[str, str] = {"cveIds": ",".join(cve_ids)}
            if use_key and self._api_key:
                params["apiKey"] = self._api_key
            elif not use_key and not self._api_key:
                break
            resp = self._http.get(self._url, params=params)
            if resp.status_code == 404 and use_key and self._api_key:
                continue
            resp.raise_for_status()
            return cast("list[dict[str, Any]]", resp.json().get("vulnerabilities", []))
        return []


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
