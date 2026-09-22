"""Planning the ``originalLevel`` write. Pure; no I/O.

The customer asked for the *original risk rating* specifically — "not
necessarily from a risk adjustment perspective, but from an original risk
rating" — which is ``PATCH /issues/{issueId}`` with ``originalLevel``, not the
deviation/``adjustedLevel`` row the tool wrote previously.

Planning is separated from writing so a rerun is a no-op and so the whole plan
can be reviewed before a single request is sent. Direction is tracked because a
plan that *lowers* a level on a live FedRAMP POA&M deserves a human's eye:
``only_raise`` exists for the run where that is not acceptable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cvss_adjuster.core.vuln.scanner import LEVEL_RANK

Action = Literal["set", "noop", "skip"]
Direction = Literal["raise", "lower", "same", "unset"]


@dataclass(frozen=True)
class LevelPlan:
    action: Action
    issue_id: str
    current_level: str | None
    target_level: str | None
    direction: Direction
    reason: str = ""

    @property
    def body(self) -> dict[str, str]:
        """The PATCH payload. Only meaningful for ``action == "set"``."""
        return {"originalLevel": self.target_level or ""}


def direction_of(current: str | None, target: str | None) -> Direction:
    if target is None:
        return "unset"
    if current is None or current == "NOT_SET":
        return "unset"
    if current == target:
        return "same"
    return "raise" if LEVEL_RANK.get(target, -1) > LEVEL_RANK.get(current, -1) else "lower"


def plan_original_level(
    issue_id: str,
    *,
    current_level: str | None,
    target_level: str | None,
    only_raise: bool = False,
) -> LevelPlan:
    """Decide whether this issue's ``originalLevel`` should change.

    ``skip`` means deliberately left alone (nothing resolved, or a downgrade the
    run was told not to make); ``noop`` means already correct.
    """
    direction = direction_of(current_level, target_level)

    if target_level is None:
        return LevelPlan(
            "skip", issue_id, current_level, None, direction,
            "no level resolved from NVD, scanner CVSS, or scanner severity",
        )

    if current_level == target_level:
        return LevelPlan(
            "noop", issue_id, current_level, target_level, direction,
            "already at the resolved level",
        )

    if only_raise and direction == "lower":
        return LevelPlan(
            "skip", issue_id, current_level, target_level, direction,
            f"would lower {current_level} -> {target_level}; --only-raise is set",
        )

    return LevelPlan(
        "set", issue_id, current_level, target_level, direction,
        f"{current_level or 'NOT_SET'} -> {target_level}",
    )
