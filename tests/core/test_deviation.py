from cvss_adjuster.core.vuln.deviation import build_description, plan_deviation

KW = dict(deviation_type="RISK_ADJUSTMENT", method="EXAMINE", default_status="PENDING")


def _existing(desc, *, level="HIGH", status="PENDING", method="EXAMINE", id="dev-9"):
    return {
        "id": id,
        "description": desc,
        "method": method,
        "type": "RISK_ADJUSTMENT",
        "deviationMetadata": {"status": status, "adjustedLevel": level},
    }


def test_create_when_none_exists():
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector="CVSS:3.1/AV:N",
        existing_deviations=[],
        **KW,
    )
    assert plan.action == "create"
    assert "vector CVSS:3.1/AV:N" in plan.body["description"]
    assert plan.body["deviationMetadata"]["adjustedLevel"] == "HIGH"


def test_noop_when_identical():
    desc = build_description(7.5, "CVE-1", ["CVE-1"], "iss-1", "CVSS:3.1/AV:N")
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector="CVSS:3.1/AV:N",
        existing_deviations=[_existing(desc, level="HIGH")],
        **KW,
    )
    assert plan.action == "noop"
    assert plan.deviation_id == "dev-9"


def test_update_when_score_changed_preserves_status():
    stale = build_description(9.8, "CVE-1", ["CVE-1"], "iss-1", "CVSS:3.1/OLD")
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector="CVSS:3.1/NEW",
        existing_deviations=[_existing(stale, level="CRITICAL", status="ACCEPTED")],
        **KW,
    )
    assert plan.action == "update"
    assert plan.deviation_id == "dev-9"
    assert plan.body["deviationMetadata"]["adjustedLevel"] == "HIGH"
    # human-set status must be preserved, not reverted to PENDING
    assert plan.body["deviationMetadata"]["status"] == "ACCEPTED"


def test_human_authored_deviation_is_not_matched():
    human = {"type": "RISK_ADJUSTMENT", "description": "analyst note, no signature"}
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector=None,
        existing_deviations=[human],
        **KW,
    )
    assert plan.action == "create"  # ours is missing; we don't touch theirs


def test_duplicates_emit_warning():
    stale = build_description(9.8, "CVE-1", ["CVE-1"], "iss-1")
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector=None,
        existing_deviations=[_existing(stale), _existing(stale)],
        **KW,
    )
    assert plan.warnings and "2 tool-created" in plan.warnings[0]


def test_noop_when_the_api_appended_a_trailing_newline():
    """Regression: Paramify stores the description with a trailing newline.

    A byte-exact comparison made every rerun plan an update of a row that was
    already correct, so the tool never reached a steady state. Caught against the
    live stage API, not by the fakes — they echoed back exactly what was sent.
    """
    desc = build_description(7.5, "CVE-1", ["CVE-1"], "iss-1", "CVSS:3.1/AV:N")
    plan = plan_deviation(
        "iss-1",
        nvd_score=7.5,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector="CVSS:3.1/AV:N",
        existing_deviations=[_existing(desc + "\n", level="HIGH")],
        **KW,
    )
    assert plan.action == "noop"


def test_still_updates_when_the_score_really_moved():
    """The strip() must not make it blind to a real change."""
    stale = build_description(4.0, "CVE-1", ["CVE-1"], "iss-1", "CVSS:3.1/AV:N")
    plan = plan_deviation(
        "iss-1",
        nvd_score=9.9,
        winning_cve="CVE-1",
        cve_ids=["CVE-1"],
        vector="CVSS:3.1/AV:N",
        existing_deviations=[_existing(stale + "\n", level="MODERATE")],
        **KW,
    )
    assert plan.action == "update"
    assert plan.body["deviationMetadata"]["adjustedLevel"] == "CRITICAL"
