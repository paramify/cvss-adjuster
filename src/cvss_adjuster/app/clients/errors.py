"""Typed exceptions for the Paramify client.

A single catch-all error forces callers to string-match on messages. Typed
subclasses let the CLI react to *kinds* of failure (``except ParamifyAuthError``
to print the stage-vs-prod hint) while still catching everything with
``except ParamifyError``.

Paramify's error responses share a shape — ``{requestId, statusMessage, error}``
— so ``ParamifyAPIError`` surfaces a friendly message and keeps ``request_id``
for support, while retaining the full ``body``.
"""

from __future__ import annotations

from typing import Any


class ParamifyError(Exception):
    """Base class for every error raised by the Paramify client."""


class ParamifyConfigError(ParamifyError):
    """Misconfiguration caught before any request is sent (e.g. missing API key)."""


class ParamifyAPIError(ParamifyError):
    """The API returned a non-2xx response.

    Carries the status code, the request method/path, and the parsed (or raw)
    response body, so a caller can inspect *what* went wrong, not just a string.
    """

    def __init__(self, status_code: int, method: str, path: str, body: Any = None) -> None:
        self.status_code = status_code
        self.method = method
        self.path = path
        self.body = body
        self.request_id: str | None = None

        detail: Any = body
        if isinstance(body, dict):
            self.request_id = body.get("requestId")
            detail = _detail(body)
        super().__init__(f"{method} /{path} -> {status_code}: {detail}")


def _detail(body: dict[str, Any]) -> Any:
    """Pull the human-readable message out of an API error body.

    The shape is ``{requestId, statusMessage, error: {message, path, timestamp}}``
    — the readable text is nested one level down inside ``error``, so reaching only
    for ``body["error"]`` yields a dict and prints timestamps and paths at the
    user. Flat shapes (a string ``error``, a top-level ``message``) are handled too,
    since this is the kind of response that changes without warning.
    """
    error = body.get("error")
    if isinstance(error, dict):
        return error.get("message") or error.get("statusMessage") or error
    return error or body.get("message") or body.get("statusMessage") or body


class ParamifyAuthError(ParamifyAPIError):
    """401 / 403 — missing, expired, or insufficient credentials."""


class ParamifyNotFoundError(ParamifyAPIError):
    """404 — the requested resource does not exist."""
