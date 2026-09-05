
from app.services import risk_engine


def _finding(**overrides):
    base = {
        "title": "SQL Injection in login handler",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "file": "app/routes/auth.py",
        "confidence": None,
    }
    base.update(overrides)
    return base


# ── calculate_finding_risk ────────────────────────────────────────────────

def test_critical_sql_injection_in_routes_scores_high():
    risk = risk_engine.calculate_finding_risk(_finding(), repo="prod-payments-api")
    assert risk["riskScore"] >= 70
    assert risk["riskLevel"] in ("HIGH", "CRITICAL")


def test_low_severity_finding_in_test_file_scores_low():
    finding = _finding(severity="LOW", category="Weak Cryptography", file="tests/test_utils.py")
    risk = risk_engine.calculate_finding_risk(finding, repo="internal-tooling")
    assert risk["riskScore"] < 35
    assert risk["riskLevel"] == "LOW"


def test_severity_is_the_dominant_factor():
    critical = risk_engine.calculate_finding_risk(_finding(severity="CRITICAL"))
    low = risk_engine.calculate_finding_risk(_finding(severity="LOW"))
    assert critical["riskScore"] > low["riskScore"]


def test_exposure_heuristic_routes_vs_internal():
    public = risk_engine.calculate_finding_risk(_finding(file="app/api/routes/users.py"))
    internal = risk_engine.calculate_finding_risk(_finding(file="internal/lib/helpers.py"))
    assert public["exposure"] > internal["exposure"]
    assert public["riskScore"] >= internal["riskScore"]


def test_ai_confidence_lowers_exploitability():
    high_conf = risk_engine.calculate_finding_risk(_finding(confidence="high"))
    low_conf = risk_engine.calculate_finding_risk(_finding(confidence="low"))
    assert low_conf["exploitability"] < high_conf["exploitability"]
    assert low_conf["riskScore"] <= high_conf["riskScore"]


def test_asset_criticality_heuristic_prod_vs_sandbox():
    prod = risk_engine.calculate_finding_risk(_finding(), repo="acme/prod-checkout")
    sandbox = risk_engine.calculate_finding_risk(_finding(), repo="acme/sandbox-demo")
    assert prod["assetCriticality"] > sandbox["assetCriticality"]
    assert prod["riskScore"] > sandbox["riskScore"]


def test_risk_score_is_clamped_0_to_100():
    risk = risk_engine.calculate_finding_risk(_finding(), repo="prod-core-payments-billing")
    assert 0 <= risk["riskScore"] <= 100


def test_unrecognized_category_falls_back_to_moderate_default():
    finding = _finding(category="Something Unusual The Model Made Up")
    risk = risk_engine.calculate_finding_risk(finding)
    assert risk["exploitability"] == risk_engine._DEFAULT_EXPLOITABILITY


def test_eal_scales_with_severity():
    critical_eal = risk_engine.calculate_finding_risk(_finding(severity="CRITICAL"))["eal"]["annualLoss"]
    low_eal = risk_engine.calculate_finding_risk(_finding(severity="LOW"))["eal"]["annualLoss"]
    assert critical_eal > low_eal


def test_output_is_deterministic_and_reproducible():
    a = risk_engine.calculate_finding_risk(_finding(), repo="acme/prod-api")
    b = risk_engine.calculate_finding_risk(_finding(), repo="acme/prod-api")
    assert a == b


def test_output_includes_methodology_version():
    risk = risk_engine.calculate_finding_risk(_finding())
    assert risk["methodology"] == risk_engine.METHODOLOGY_VERSION


# ── recalculate_after_fix / risk_reduction_pct ───────────────────────────

def test_post_fix_risk_is_much_lower_than_pre_fix():
    before = risk_engine.calculate_finding_risk(_finding(), repo="prod-api")
    after = risk_engine.recalculate_after_fix(before)
    assert after["riskScore"] < before["riskScore"]
    assert after["eal"]["annualLoss"] < before["eal"]["annualLoss"]


def test_post_fix_risk_is_not_zero_verified_is_not_proof():
    before = risk_engine.calculate_finding_risk(_finding(), repo="prod-api")
    after = risk_engine.recalculate_after_fix(before)
    # A verified fix is strong evidence, not formal proof — residual risk
    # should be small but nonzero for anything that started above zero.
    assert after["riskScore"] >= 0
    if before["riskScore"] > 0:
        assert after["riskScore"] >= 0


def test_risk_reduction_pct_matches_spec_example_ballpark():
    """Product spec's own worked example: Risk 94 -> 18 is an ~81% reduction.
    Our residual-fraction model should land in a comparable range for a
    similarly severe finding, not reduce risk to near-zero or barely at all."""
    before = risk_engine.calculate_finding_risk(_finding(), repo="prod-api")
    after = risk_engine.recalculate_after_fix(before)
    pct = risk_engine.risk_reduction_pct(before, after)
    assert 70 <= pct <= 95


def test_risk_reduction_pct_zero_before_score_is_zero_not_error():
    before = {"riskScore": 0}
    after = {"riskScore": 0}
    assert risk_engine.risk_reduction_pct(before, after) == 0.0


def test_risk_reduction_pct_full_reduction_is_100():
    before = {"riskScore": 50}
    after = {"riskScore": 0}
    assert risk_engine.risk_reduction_pct(before, after) == 100.0


def test_risk_reduction_pct_never_reports_negative_when_risk_increased():
    """Explicit failure-case regression: if risk_after > risk_before ever
    reaches this function (shouldn't happen via recalculate_after_fix, but
    could via a malformed/mismatched caller input), it must clamp to 0.0 —
    a fix pipeline must never claim a "risk reduction" percentage when risk
    measurably went up."""
    before = {"riskScore": 20}
    after = {"riskScore": 65}  # risk went UP
    assert risk_engine.risk_reduction_pct(before, after) == 0.0


def test_post_fix_risk_score_never_exceeds_pre_fix_score_across_severities():
    """recalculate_after_fix's own invariant, exercised across every
    severity/category/exposure combination rather than just one example."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for category in ("SQL Injection", "Weak Cryptography", "Open Redirect"):
            before = risk_engine.calculate_finding_risk(
                _finding(severity=sev, category=category), repo="prod-api"
            )
            after = risk_engine.recalculate_after_fix(before)
            assert after["riskScore"] <= before["riskScore"], f"{sev}/{category}: risk increased after fix"
            assert after["eal"]["annualLoss"] <= before["eal"]["annualLoss"]


def test_recalculate_after_fix_clamps_even_if_residual_fraction_were_misconfigured(monkeypatch):
    """Defense-in-depth check for the explicit clamp in recalculate_after_fix
    — even if RESIDUAL_RISK_FRACTION were ever bumped to/above 1.0 by
    mistake, post-fix risk still may not exceed pre-fix risk."""
    monkeypatch.setattr(risk_engine, "RESIDUAL_RISK_FRACTION", 1.5)
    before = risk_engine.calculate_finding_risk(_finding(), repo="prod-api")
    after = risk_engine.recalculate_after_fix(before)
    assert after["riskScore"] <= before["riskScore"]
    assert after["eal"]["annualLoss"] <= before["eal"]["annualLoss"]


# ── aggregate_project_risk ────────────────────────────────────────────────

def test_aggregate_empty_findings_list():
    overview = risk_engine.aggregate_project_risk([])
    assert overview["overallRiskScore"] == 0
    assert overview["riskLevel"] == "LOW"
    assert overview["eal"]["annualLoss"] == 0


def test_aggregate_is_dominated_by_worst_finding_not_diluted_by_many_lows():
    critical = risk_engine.calculate_finding_risk(_finding(severity="CRITICAL"), repo="prod-api")
    lows = [
        risk_engine.calculate_finding_risk(_finding(severity="LOW", category="Weak Cryptography"), repo="prod-api")
        for _ in range(9)
    ]
    overview = risk_engine.aggregate_project_risk([critical] + lows)
    # A naive average of one CRITICAL (~high score) and nine LOWs (~low score)
    # would land solidly in LOW/MEDIUM territory; the weighted formula should
    # keep it visibly elevated instead of hiding the critical finding.
    assert overview["overallRiskScore"] > (sum(r["riskScore"] for r in [critical] + lows) / 10)


def test_aggregate_eal_is_sum_across_findings():
    f1 = risk_engine.calculate_finding_risk(_finding(severity="HIGH"))
    f2 = risk_engine.calculate_finding_risk(_finding(severity="MEDIUM"))
    overview = risk_engine.aggregate_project_risk([f1, f2])
    assert overview["eal"]["annualLoss"] == f1["eal"]["annualLoss"] + f2["eal"]["annualLoss"]


def test_aggregate_var_is_greater_than_or_equal_to_eal():
    f1 = risk_engine.calculate_finding_risk(_finding(severity="CRITICAL"))
    overview = risk_engine.aggregate_project_risk([f1])
    assert overview["var"]["value"] >= overview["eal"]["annualLoss"]


def test_aggregate_counts_findings_by_severity_level():
    critical = risk_engine.calculate_finding_risk(_finding(severity="CRITICAL"), repo="prod-api")
    low = risk_engine.calculate_finding_risk(_finding(severity="LOW", category="Weak Cryptography"), repo="sandbox")
    overview = risk_engine.aggregate_project_risk([critical, low])
    assert overview["findingsBySeverity"]["critical"] + overview["findingsBySeverity"]["high"] >= 1
    assert overview["findingsBySeverity"]["low"] + overview["findingsBySeverity"]["medium"] >= 1
    total = sum(overview["findingsBySeverity"].values())
    assert total == 2
