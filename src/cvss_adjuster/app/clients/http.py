"""Shared HTTP client factory (NVD only).

One pooled ``httpx.Client`` per invocation, so connections are reused and the
timeout/retry policy lives in one place. Paramify is deliberately *not* built
here — it needs a base URL and a bearer auth header, and mixing the two pools
risks sending the Paramify token to NVD. See ``clients/paramify.py``.
"""

from __future__ import annotations

import httpx


def make_client(timeout: float = 60.0) -> httpx.Client:
    transport = httpx.HTTPTransport(retries=2)
    return httpx.Client(timeout=timeout, transport=transport)
