"""Tests for the hand-rolled Paramify client.

This is the one piece with no upstream to inherit correctness from, so it gets
real coverage: URL joining, the auth header, envelope unwrapping, the scope guard,
and the status -> typed-exception mapping. ``httpx.MockTransport`` exercises the
real construction path without touching the network.
"""

import httpx
import pytest

from cvss_adjuster.app.clients.errors import (
    ParamifyAPIError,
    ParamifyAuthError,
    ParamifyConfigError,
    ParamifyNotFoundError,
)
from cvss_adjuster.app.clients.paramify import ParamifyClient, build_http_client
from cvss_adjuster.app.settings import Settings

SETTINGS = Settings(paramify_api_key="k-123", paramify_url="https://app.paramify.com/api/v0")


def _client(handler) -> ParamifyClient:
    http = build_http_client(SETTINGS, transport=httpx.MockTransport(handler))
    return ParamifyClient(SETTINGS, http=http)


def test_base_url_joins_without_swallowing_the_api_prefix():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"projects": []})

    _client(handler).list_programs()
    # The classic bug this guards: "/api/v0" + "projects" -> "/api/v0projects".
    assert seen["url"] == "https://app.paramify.com/api/v0/projects"


def test_bearer_token_is_sent():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"projects": []})

    _client(handler).list_programs()
    assert seen["auth"] == "Bearer k-123"


def test_list_endpoints_unwrap_their_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"projects": [{"id": "P1"}, {"id": "P2"}]})

    assert [p["id"] for p in _client(handler).list_programs()] == ["P1", "P2"]


def test_list_endpoints_tolerate_a_bare_list():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": "P1"}])

    assert [p["id"] for p in _client(handler).list_programs()] == ["P1"]


def test_get_issues_sends_the_project_scope():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"issues": [{"id": "ISS-1"}]})

    issues = _client(handler).get_issues(project_id="PRJ-1")
    assert "projectId=PRJ-1" in seen["url"]
    assert issues[0]["id"] == "ISS-1"


def test_get_issues_without_a_scope_is_refused_before_any_request():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("should never be called")

    with pytest.raises(ParamifyConfigError, match="requires a scope"):
        _client(handler).get_issues(cve_ids=["CVE-2021-44228"])


def test_missing_api_key_is_caught_before_any_request():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("should never be called")

    settings = Settings(paramify_api_key=None)
    http = build_http_client(settings, transport=httpx.MockTransport(handler))
    with pytest.raises(ParamifyConfigError, match="PARAMIFY_API_KEY"):
        ParamifyClient(settings, http=http).list_programs()


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, ParamifyAuthError),
        (403, ParamifyAuthError),
        (404, ParamifyNotFoundError),
        (500, ParamifyAPIError),
    ],
)
def test_status_codes_map_to_typed_errors(status, expected):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": "nope", "requestId": "req-7"})

    with pytest.raises(expected) as excinfo:
        _client(handler).list_programs()
    assert excinfo.value.status_code == status
    assert excinfo.value.request_id == "req-7"
    assert "nope" in str(excinfo.value)


def test_non_json_error_body_still_raises_cleanly():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>bad gateway</html>")

    with pytest.raises(ParamifyAPIError, match="bad gateway"):
        _client(handler).list_programs()


def test_nested_error_message_is_surfaced_not_the_raw_object():
    """Regression, captured from a live stage 401.

    The API nests the readable text inside `error`, so reaching only for
    body["error"] returns a dict and prints timestamps and paths at the user.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "requestId": "0b7b8609-c7c6-4e9b-bb0b-6c439f8d510f",
                "statusMessage": "Unauthorized",
                "error": {
                    "message": "The credentials used are invalid.",
                    "path": "/api/v0/projects",
                    "timestamp": "2026-09-10T17:14:32.533Z",
                },
            },
        )

    with pytest.raises(ParamifyAuthError) as excinfo:
        _client(handler).list_programs()
    message = str(excinfo.value)
    assert message == "GET /projects -> 401: The credentials used are invalid."
    assert "timestamp" not in message
    assert excinfo.value.request_id == "0b7b8609-c7c6-4e9b-bb0b-6c439f8d510f"


def test_flat_error_string_still_works():
    """A flat string `error` is the other shape seen in the wild."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom", "requestId": "req-7"})

    with pytest.raises(ParamifyAPIError, match="boom"):
        _client(handler).list_programs()
