"""Pure normalization of scanner (Twistlock) findings. No I/O.

The scanner's own ``CVSS`` and ``Severity`` columns are the second and third
rungs of the fallback ladder, and they exist *only* in the scan export: the
Paramify API surfaces neither (the 0.9.2 spec contains no cvss/severity/score/
vector field anywhere). Reading, merging and validating them is therefore a
first-class concern rather than a detail of the CSV loader.

Two rules drive everything here, both taken from the customer's own framing:

* **A CVSS of 0 means "absent", never "harmless."** A large share of scan rows
  carry 0 while the scanner's own severity says ``high`` or ``critical``.
  Treating 0 as a real score would silently bury them.
* **When one CVE appears at several severities, the highest wins** — "it of
  course makes sense to take the higher bar over just like a zero."
"""

from __future__ import annotations

from dataclasses import dataclass

# Paramify's enum, ordered. Index doubles as the comparison rank, so "highest
# severity wins" is a plain max() rather than a bespoke comparator.
LEVEL_ORDER: tuple[str, ...] = ("CHILL", "LOW", "MODERATE", "HIGH", "CRITICAL")
LEVEL_RANK: dict[str, int] = {name: i for i, name in enumerate(LEVEL_ORDER)}

# Scanner severity vocabulary -> Paramify level.
#
# ``medium`` -> ``MODERATE`` is the one that matters in practice: Twistlock says
# "medium", Paramify's enum says "MODERATE", and a missed mapping here would
# drop 22% of rows on the floor. The rest of the vocabulary is mapped defensively
# because scanner exports drift between versions; anything unrecognized raises
# rather than defaulting, so a new severity word can never be silently scored low.
SEVERITY_ALIASES: dict[str, str] = {
    "critical": "CRITICAL",
    "important": "CRITICAL",
    "high": "HIGH",
    "medium": "MODERATE",
    "moderate": "MODERATE",
    "low": "LOW",
    "minor": "LOW",
    "negligible": "CHILL",
    "unimportant": "CHILL",
    "none": "CHILL",
    "informational": "CHILL",
    "info": "CHILL",
}


class UnknownSeverityError(ValueError):
    """A severity string the mapping does not cover.

    Deliberately fatal rather than a silent default: an unmapped word means the
    scanner changed its vocabulary, and guessing would quietly misscore findings.
    """


@dataclass(frozen=True)
class ScannerFinding:
    """One CVE's merged scanner evidence across every row that mentioned it."""

    cve_id: str
    severity_level: str | None  # Paramify level from the Severity column
    cvss: float | None  # scanner's numeric CVSS; None when absent or 0
    row_count: int = 0
    severities_seen: tuple[str, ...] = ()

    @property
    def has_conflict(self) -> bool:
        return len(self.severities_seen) > 1


def normalize_severity(raw: str | None) -> str | None:
    """Map a scanner severity word onto a Paramify level.

    ``None`` for a blank cell; raises ``UnknownSeverityError`` for a non-empty
    value that is not in the mapping.
    """
    if raw is None:
        return None
    text = raw.strip().lower()
    if not text:
        return None
    try:
        return SEVERITY_ALIASES[text]
    except KeyError:
        raise UnknownSeverityError(
            f"unmapped scanner severity {raw!r} — add it to SEVERITY_ALIASES "
            "rather than letting it score as low"
        ) from None


def parse_cvss(raw: str | float | None) -> float | None:
    """Parse the scanner's CVSS cell, treating 0 and unparseable text as absent.

    Zero is the whole reason the fallback ladder exists, so it is folded into
    "absent" at the boundary and never reaches the resolver as a real 0.0.
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    else:
        text = str(raw).strip()
        if not text:
            return None
        try:
            value = float(text)
        except ValueError:
            return None
    if value <= 0:
        return None
    return value


def higher_level(left: str | None, right: str | None) -> str | None:
    """The more severe of two levels; tolerates ``None`` on either side."""
    if left is None:
        return right
    if right is None:
        return left
    return left if LEVEL_RANK.get(left, -1) >= LEVEL_RANK.get(right, -1) else right


def merge_rows(rows: list[tuple[str, str | None, float | None]]) -> dict[str, ScannerFinding]:
    """Collapse ``(cve_id, severity_level, cvss)`` rows into one finding per CVE.

    Both dimensions take the maximum: the highest severity seen and the highest
    non-zero CVSS seen. A CVE routinely carries conflicting severities across
    rows (``high`` in one image and ``low`` in another), and the higher bar is
    what should survive the merge.
    """
    merged: dict[str, ScannerFinding] = {}
    seen: dict[str, set[str]] = {}
    for cve_id, level, cvss in rows:
        key = cve_id.strip().upper()
        if not key:
            continue
        if level is not None:
            seen.setdefault(key, set()).add(level)
        prior = merged.get(key)
        if prior is None:
            merged[key] = ScannerFinding(key, level, cvss, 1, ())
            continue
        merged[key] = ScannerFinding(
            key,
            higher_level(prior.severity_level, level),
            _max_optional(prior.cvss, cvss),
            prior.row_count + 1,
            (),
        )
    return {
        key: ScannerFinding(
            f.cve_id,
            f.severity_level,
            f.cvss,
            f.row_count,
            tuple(sorted(seen.get(key, set()))),
        )
        for key, f in merged.items()
    }


def _max_optional(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)
