"""Pure CVSS metric selection and severity mapping (no I/O)."""

from __future__ import annotations

from typing import Any

# Preference order: use CVSS 4.0 when present, otherwise fall back to 3.1.
DEFAULT_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31")


def cvss_score_to_level(score: float) -> str:
    """Map an NVD base score to a Paramify ``adjustedLevel``."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0:
        return "LOW"
    return "CHILL"


def pick_metric(
    metrics: list[dict[str, Any]],
    metric_keys: tuple[str, ...] = DEFAULT_METRIC_KEYS,
) -> dict[str, Any] | None:
    """Pick the best metric: first available version, Primary over Secondary, max score."""
    for metric_key in metric_keys:
        candidates = [m for m in metrics if m["metric_key"] == metric_key]
        if not candidates:
            continue
        for metric_type in ("Primary", "Secondary"):
            typed = [m for m in candidates if m["type"] == metric_type]
            if typed:
                return max(typed, key=lambda m: m["base_score"])
    return None
