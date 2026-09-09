"""CVSS vector -> base score.

SWAP SEAM. The only place that knows how a vector string becomes a number.
Callers depend only on ``recompute_from_vector``, so the engine can be replaced
(drop in the official ``cvss`` package, or an in-house port) without touching
services or the CLI. Until one is wired, it returns ``None`` and the pipeline
still runs end-to-end (the recomputed score shows as n/a).
"""

from __future__ import annotations


class CvssVectorError(ValueError):
    pass


def score_from_vector(vector: str) -> float:
    raise NotImplementedError(
        "scoring engine not wired yet — plug in the official `cvss` library "
        "or an in-house port here."
    )


def recompute_from_vector(vector: str | None) -> float | None:
    """Best-effort recompute; ``None`` when unavailable or unparseable."""
    if not vector:
        return None
    try:
        return score_from_vector(vector)
    except (CvssVectorError, NotImplementedError):
        return None
