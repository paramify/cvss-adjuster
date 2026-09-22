"""The customer's acceptance criteria, one test per stated requirement.

Each test names the requirement it pins and, where the number matters, the
observation from the real exports that makes it load-bearing. These are the
tests to read first if the ladder ever needs to change.
"""

from __future__ import annotations

import pytest

from cvss_adjuster.core.vuln.original_level import direction_of, plan_original_level
from cvss_adjuster.core.vuln.resolution import (
    SOURCE_NVD,
    SOURCE_SCANNER_CVSS,
    SOURCE_SCANNER_SEVERITY,
    SOURCE_UNRESOLVED,
    resolve_level,
)
from cvss_adjuster.core.vuln.scanner import (
    ScannerFinding,
    UnknownSeverityError,
    higher_level,
    merge_rows,
    normalize_severity,
    parse_cvss,
)

# --- requirement: scanner severity maps onto Paramify's enum ---------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("medium", "MODERATE"),  # the mapping that matters: 22% of observed rows
        ("low", "LOW"),
        ("CRITICAL", "CRITICAL"),  # case-insensitive
        ("  High  ", "HIGH"),  # whitespace-tolerant
        ("", None),
        (None, None),
    ],
)
def test_severity_mapping(raw, expected):
    assert normalize_severity(raw) == expected


def test_unknown_severity_raises_rather_than_defaulting():
    """A new severity word must never silently score as the lowest level."""
    with pytest.raises(UnknownSeverityError):
        normalize_severity("spicy")


# --- requirement: a CVSS of 0 means absent, not harmless -------------------


@pytest.mark.parametrize("raw", ["0", "0.0", 0, 0.0, "", "  ", None, "n/a", "-1"])
def test_zero_and_junk_cvss_are_absent(raw):
    assert parse_cvss(raw) is None


@pytest.mark.parametrize(("raw", "expected"), [("7.5", 7.5), (9.8, 9.8), (" 4.3 ", 4.3)])
def test_real_cvss_survives(raw, expected):
    assert parse_cvss(raw) == expected


def test_zero_cvss_does_not_beat_a_high_severity():
    """The headline case: a CVSS-0 row whose scanner severity says high."""
    resolution = resolve_level(
        nvd_score=None,
        finding=ScannerFinding("CVE-1", normalize_severity("high"), parse_cvss("0")),
    )
    assert resolution.level == "HIGH"
    assert resolution.source == SOURCE_SCANNER_SEVERITY


# --- requirement: the higher bar wins when rows disagree -------------------


def test_merge_takes_highest_severity_and_highest_cvss():
    """A CVE can appear at different severities in different images."""
    merged = merge_rows(
        [("CVE-1", "LOW", 3.1), ("CVE-1", "HIGH", None), ("CVE-1", "MODERATE", 5.5)]
    )["CVE-1"]
    assert merged.severity_level == "HIGH"
    assert merged.cvss == 5.5
    assert merged.row_count == 3
    assert merged.has_conflict
    assert merged.severities_seen == ("HIGH", "LOW", "MODERATE")


def test_higher_level_handles_missing_sides():
    assert higher_level(None, "LOW") == "LOW"
    assert higher_level("HIGH", None) == "HIGH"
    assert higher_level(None, None) is None
    assert higher_level("CRITICAL", "HIGH") == "CRITICAL"


# --- requirement: NVD first, scanner CVSS second, category third -----------


def test_rung_one_nvd_wins_even_when_lower_than_the_scanner():
    """A priority ladder, not a max: NVD wins when it has a usable score."""
    resolution = resolve_level(
        nvd_score=4.0,
        nvd_cve_id="CVE-1",
        finding=ScannerFinding("CVE-1", "CRITICAL", 9.9),
    )
    assert (resolution.level, resolution.source) == ("MODERATE", SOURCE_NVD)


def test_rung_two_scanner_cvss_when_nvd_has_nothing():
    resolution = resolve_level(
        nvd_score=None, finding=ScannerFinding("CVE-1", "LOW", 8.1)
    )
    assert (resolution.level, resolution.source) == ("HIGH", SOURCE_SCANNER_CVSS)


def test_rung_three_scanner_severity_when_neither_score_is_usable():
    resolution = resolve_level(
        nvd_score=None, finding=ScannerFinding("CVE-1", "MODERATE", None)
    )
    assert (resolution.level, resolution.source) == ("MODERATE", SOURCE_SCANNER_SEVERITY)


def test_unresolved_when_no_rung_has_anything():
    resolution = resolve_level(nvd_score=None, finding=None)
    assert resolution.level is None
    assert resolution.source == SOURCE_UNRESOLVED
    assert not resolution.resolved


def test_nvd_score_of_zero_falls_through():
    """NVD encodes 'no opinion' as 0 too, so the same rule applies to rung one."""
    resolution = resolve_level(
        nvd_score=0.0, finding=ScannerFinding("CVE-1", "HIGH", None)
    )
    assert (resolution.level, resolution.source) == ("HIGH", SOURCE_SCANNER_SEVERITY)


def test_missing_nvd_metric_falls_through_instead_of_skipping():
    """The previous implementation skipped these entirely.

    Presence in NVD is not a usable score: sampled CVEs came back present but
    `Deferred` with their metrics stripped. `nvd_score=None` is what metric
    selection yields for those, and the ladder must carry on rather than leave
    the issue unrated.
    """
    resolution = resolve_level(
        nvd_score=None, nvd_cve_id="CVE-1", finding=ScannerFinding("CVE-1", "CRITICAL", None)
    )
    assert resolution.level == "CRITICAL"
    assert resolution.resolved


def test_conflicting_severities_are_reported_in_the_detail():
    resolution = resolve_level(
        nvd_score=None,
        finding=ScannerFinding("CVE-1", "HIGH", None, 2, ("HIGH", "LOW")),
    )
    assert "HIGH/LOW" in resolution.detail


# --- requirement: write the original risk rating, idempotently -------------


def test_plan_sets_when_the_level_moves():
    plan = plan_original_level("i1", current_level="NOT_SET", target_level="HIGH")
    assert plan.action == "set"
    assert plan.body == {"originalLevel": "HIGH"}


def test_plan_is_a_noop_on_rerun():
    plan = plan_original_level("i1", current_level="HIGH", target_level="HIGH")
    assert plan.action == "noop"


def test_plan_skips_when_nothing_resolved():
    plan = plan_original_level("i1", current_level="HIGH", target_level=None)
    assert plan.action == "skip"


def test_only_raise_blocks_a_downgrade_but_allows_an_upgrade():
    blocked = plan_original_level(
        "i1", current_level="HIGH", target_level="LOW", only_raise=True
    )
    assert blocked.action == "skip"
    assert blocked.direction == "lower"

    allowed = plan_original_level(
        "i1", current_level="LOW", target_level="CRITICAL", only_raise=True
    )
    assert allowed.action == "set"
    assert allowed.direction == "raise"


def test_downgrades_are_allowed_by_default_but_labelled():
    plan = plan_original_level("i1", current_level="HIGH", target_level="LOW")
    assert plan.action == "set"
    assert plan.direction == "lower"


@pytest.mark.parametrize(
    ("current", "target", "expected"),
    [
        ("LOW", "HIGH", "raise"),
        ("HIGH", "LOW", "lower"),
        ("HIGH", "HIGH", "same"),
        ("NOT_SET", "HIGH", "unset"),
        (None, "HIGH", "unset"),
    ],
)
def test_direction(current, target, expected):
    assert direction_of(current, target) == expected
