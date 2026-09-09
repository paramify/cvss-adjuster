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
            detail = body.get("error") or body.get("statusMessage") or body
        super().__init__(f"{method} /{path} -> {status_code}: {detail}")


class ParamifyAuthError(ParamifyAPIError):
    """401 / 403 — missing, expired, or insufficient credentials."""


class ParamifyNotFoundError(ParamifyAPIError):
    """404 — the requested resource does not exist."""
