"""Per-invocation context: resolved settings + the two clients.

Built once in the Typer root callback and stashed on ``ctx.obj``, so every command
receives the same constructed clients (the dependency-injection seam). This is the
only place that wires concrete clients to concrete settings — which is what lets
tests swap in fakes by monkeypatching ``build_context``.

Two separate HTTP pools on purpose: the Paramify client carries a bearer token on
every request, and NVD must never receive it.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from cvss_adjuster.app.clients.http import make_client
from cvss_adjuster.app.clients.nvd import NvdClient
from cvss_adjuster.app.clients.paramify import ParamifyClient
from cvss_adjuster.app.settings import Settings


@dataclass
class Context:
    settings: Settings
    http: httpx.Client
    nvd: NvdClient
    paramify: ParamifyClient

    def close(self) -> None:
        self.http.close()  # NVD's unauthenticated session
        self.paramify.close()  # the authenticated Paramify pool


def build_context() -> Context:
    settings = Settings()
    http = make_client()
    return Context(
        settings=settings,
        http=http,
        nvd=NvdClient(http, settings),
        paramify=ParamifyClient(settings),
    )
