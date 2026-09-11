"""Paramify API client — the four endpoints this tool needs, and nothing else.

Deliberately first-party rather than a shared SDK dependency: this repo is meant
to be cloned and built by anyone, and a private git dependency cannot be resolved
on a machine without access to it (``pip install`` fails during resolution, before
any of this code runs). Four endpoints of plain ``httpx`` is a small price for a
repo that installs anywhere and can be read end-to-end by whoever runs it.

    GET    projects                                  -> list_programs
    GET    issues?projectId=…                        -> get_issues
    POST   issues/{id}/deviations                    -> create_deviation
    PATCH  issues/{id}/deviations/{deviationId}      -> update_deviation

Verified against the Paramify OpenAPI spec v0.9.0: paths, query-parameter names,
response envelope keys, and the deviation request body (required fields plus the
``method`` / ``type`` / ``status`` / ``adjustedLevel`` enums).

Responses come back as plain ``dict``s. The API returns camelCase keys and adds
fields over time; passing them through untouched means a new field arrives
automatically, and keeps API shapes out of the pure ``core`` logic.
"""

from __future__ import annotations

from typing import Any

import httpx

from cvss_adjuster.app.clients.errors import (
    ParamifyAPIError,
    ParamifyAuthError,
    ParamifyConfigError,
    ParamifyNotFoundError,
)
from cvss_adjuster.app.settings import Settings


def build_http_client(
    settings: Settings, *, transport: httpx.BaseTransport | None = None
) -> httpx.Client:
    """One pooled client carrying base URL, auth, timeout, and retry policy.

    ``transport`` exists so tests can inject an ``httpx.MockTransport`` and
    exercise the real construction path without touching the network.
    """
    headers = {"Accept": "application/json"}
    if settings.paramify_api_key:
        headers["Authorization"] = f"Bearer {settings.paramify_api_key}"

    # Normalize to exactly one trailing slash. httpx joins base_url + a relative
    # path by stripping the path's leading "/" and appending, so the base_url
    # *must* end in "/" or the segments run together ("/api/v0" + "issues").
    base_url = settings.paramify_url.rstrip("/") + "/"

    return httpx.Client(
        base_url=base_url,
        headers=headers,
        timeout=settings.paramify_timeout,
        transport=transport or httpx.HTTPTransport(retries=2),
    )


class ParamifyClient:
    """Client for the handful of Paramify endpoints the adjuster uses."""

    def __init__(
        self, settings: Settings, *, http: httpx.Client | None = None
    ) -> None:
        self._settings = settings
        self._owns_http = http is None  # only close what we built
        self._http = http if http is not None else build_http_client(settings)

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> ParamifyClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- transport --------------------------------------------------------

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Call an endpoint and return parsed JSON (``None`` for an empty body)."""
        if not self._settings.paramify_api_key:
            raise ParamifyConfigError(
                "PARAMIFY_API_KEY is not set — export it or put it in a .env file"
            )
        resp = self._http.request(method, path, **kwargs)
        if resp.status_code >= 400:
            _raise_for_status(resp, method, path)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- endpoints --------------------------------------------------------

    def list_programs(self) -> list[dict[str, Any]]:
        """GET /projects — the Paramify UI labels these "programs".

        Also the cheapest authenticated call, so it doubles as the auth smoke test.
        """
        data = self.request("GET", "projects")
        return list(_unwrap(data, "projects"))

    def get_issues(
        self,
        *,
        project_id: str | None = None,
        issue_ids: list[str] | None = None,
        poam_ids: list[str] | None = None,
        cve_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """GET /issues — each issue carries its deviations inline.

        That inline ``deviations`` array is what makes the sync a single read:
        planning never has to fetch a deviation separately. Requires a scope so we
        never accidentally ask the API for every issue in the account.
        """
        params: dict[str, Any] = {}
        if project_id:
            params["projectId"] = project_id
        if issue_ids:
            params["id"] = issue_ids
        if poam_ids:
            params["poamId"] = poam_ids
        if cve_ids:
            params["cveId"] = cve_ids
        if not any(k in params for k in ("projectId", "id", "poamId")):
            raise ParamifyConfigError(
                "get_issues requires a scope: program_id, issue_ids, or poam_ids"
            )
        data = self.request("GET", "issues", params=params)
        return list(_unwrap(data, "issues"))

    def create_deviation(self, issue_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /issues/{issueId}/deviations

        ``body`` carries ``description``, ``method``, ``type``, and
        ``deviationMetadata`` — the four fields the spec requires, all built by
        ``core.vuln.deviation``.

        Note: the API appends a trailing newline to ``description`` when it stores
        one, on create as well as update. ``plan_deviation`` compares stripped
        descriptions because of it — without that, a rerun never reaches "noop".
        """
        data = self.request("POST", f"issues/{issue_id}/deviations", json=body)
        return dict(data or {})

    def update_deviation(
        self, issue_id: str, deviation_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """PATCH /issues/{issueId}/deviations/{deviationId} — partial update."""
        data = self.request(
            "PATCH", f"issues/{issue_id}/deviations/{deviation_id}", json=body
        )
        return dict(data or {})


def _unwrap(data: Any, key: str) -> Any:
    """List endpoints return ``{"<key>": [...]}``; tolerate a bare list too."""
    if isinstance(data, dict):
        return data.get(key, data)
    return data or []


def _raise_for_status(resp: httpx.Response, method: str, path: str) -> None:
    """Map an HTTP error response onto the right typed exception."""
    try:
        body: Any = resp.json()
    except ValueError:
        body = resp.text
    if resp.status_code in (401, 403):
        raise ParamifyAuthError(resp.status_code, method, path, body)
    if resp.status_code == 404:
        raise ParamifyNotFoundError(resp.status_code, method, path, body)
    raise ParamifyAPIError(resp.status_code, method, path, body)
