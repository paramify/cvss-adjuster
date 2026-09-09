from cvss_adjuster.core.vuln.selection import cvss_score_to_level, pick_metric


def test_levels():
    assert cvss_score_to_level(9.5) == "CRITICAL"
    assert cvss_score_to_level(7.0) == "HIGH"
    assert cvss_score_to_level(4.0) == "MODERATE"
    assert cvss_score_to_level(0.1) == "LOW"
    assert cvss_score_to_level(0) == "CHILL"


def test_pick_metric_prefers_v40_then_primary_then_max():
    metrics = [
        {"metric_key": "cvssMetricV31", "type": "Primary", "base_score": 9.9},
        {"metric_key": "cvssMetricV40", "type": "Secondary", "base_score": 5.0},
        {"metric_key": "cvssMetricV40", "type": "Primary", "base_score": 7.1},
        {"metric_key": "cvssMetricV40", "type": "Primary", "base_score": 8.2},
    ]
    m = pick_metric(metrics)
    assert m is not None
    assert m["metric_key"] == "cvssMetricV40"
    assert m["type"] == "Primary"
    assert m["base_score"] == 8.2


def test_pick_metric_none_when_no_preferred_version():
    only_v2 = [{"metric_key": "cvssMetricV2", "type": "Primary", "base_score": 5.0}]
    assert pick_metric(only_v2) is None
