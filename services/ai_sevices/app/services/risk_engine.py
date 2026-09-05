"""
Risk Engine — deterministic risk quantification.

PatchLine's architecture requires risk calculation to be deterministic,
explainable, versioned, reproducible, and auditable — an LLM must never be
the one inventing the numerical risk score (models can explain WHY risk
changed; they don't get to decide the number). This module is the "Risk
Engine" component: it owns Risk Score, Risk Level, Exploitability, Exposure,
Asset Criticality, Expected Annual Loss (EAL), and a simplified Value-at-Risk
estimate, and it recalculates a finding's risk after a verified fix so the
dashboard can show measurable risk reduction rather than just "N found, M
fixed."

It is NOT a replacement for Elasticsearch (which stores/serves the
calculated numbers for search/dashboards) and it does not talk to Chroma,
Mongo, or any AI provider directly — callers (routers/scanner.py) compute a
risk snapshot and persist/index it themselves. This keeps the engine a pure,
synchronous, fully unit-testable function of its inputs.

── Methodology (documented, versioned — see METHODOLOGY_VERSION) ──────────

riskScore (0-100) = severityBase
                     * exploitabilityMultiplier(0.4-1.0)
                     * exposureMultiplier(0.5-1.0)
                     * assetCriticalityMultiplier(0.5-1.0)

  severityBase: CRITICAL=90, HIGH=70, MEDIUM=45, LOW=20 — the finding's
    already-normalized severity (app/services/severity.py) sets the ceiling;
    everything else scales it down, never up.

  exploitability (0-10): a per-category baseline (e.g. SQL injection and
    command injection score high — direct, well-understood attack paths;
    weak crypto/insecure defaults score lower — real but harder to weaponize
    without another bug alongside it), nudged by the finding's own
    confidence (AI-sourced findings only — "low" confidence pulls
    exploitability down, since an uncertain finding is a less certain attack
    path; deterministic findings have no confidence gradient, matching
    severity.py's own reasoning for why AI/deterministic findings aren't
    scored identically elsewhere in the pipeline either).

  exposure (0.0-1.0): a heuristic from the file's path — code under a
    routes/api/controllers/handlers-style path is treated as more likely
    internet-facing than code under internal/lib/utils/test paths. This is
    a heuristic, not a real asset inventory (PatchLine doesn't have one) —
    documented as such rather than presented as ground truth.

  assetCriticality (0.5-1.0): a coarse heuristic from the repo name (a repo
    whose name suggests it's a production/customer-facing service scores
    higher than one that looks like tooling/infra/test) — same "documented
    heuristic, not a real asset registry" caveat as exposure.

riskLevel: CRITICAL >=80, HIGH >=60, MEDIUM >=35, else LOW (same 4-tier
  scale as severity.py, so the two stay comparable on a dashboard).

EAL (Expected Annual Loss) = probabilityOfExploitation * financialImpact
  probabilityOfExploitation = exploitability/10 * exposure, clamped [0,1]
  financialImpact: a per-severity base ($ figure), scaled by exposure —
    an explicitly simplified placeholder methodology (PatchLine has no real
    business-impact data source), same spirit as the product spec's own EAL
    example ("$62,000/year") — a documented number, not an arbitrary one.

VaR (simplified): PatchLine's spec calls for confidence level + time
  horizon + a loss-distribution methodology. Without real loss-distribution
  data this module uses an explicitly-labeled simplified heuristic — treat
  annual loss as approximately normal with stddev = 0.6 * mean, VaR_95% =
  EAL + 1.645 * 0.6 * EAL (the one-tailed 95th-percentile z-score). This is
  NOT a substitute for a real actuarial model; it exists so the dashboard
  has a defensible, reproducible number rather than none at all, and is
  clearly labeled `"methodology": "simplified"` in its output so nothing
  downstream can mistake it for one.
"""

from __future__ import annotations

import re
from typing import Optional

from app.services import severity as severity_module

METHODOLOGY_VERSION = "risk-engine-v1"

# ── severity -> base score ──────────────────────────────────────────────
_SEVERITY_BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}

# ── category -> baseline exploitability (0-10) ──────────────────────────
# Deliberately coarse-grained: keyed on substrings found in the category
# label deterministic/AI findings actually use (see
# deterministic_scanner.py / regex_rules.py category strings), not on a
# closed enum, since AI-sourced findings' category text isn't as tightly
# controlled as the deterministic rule set's.
_EXPLOITABILITY_KEYWORDS: list[tuple[str, float]] = [
    ("sql injection", 9.5),
    ("command injection", 9.5),
    ("remote code execution", 9.8),
    ("rce", 9.8),
    ("deserialization", 8.5),
    ("path traversal", 8.0),
    ("xss", 7.5),
    ("cross-site scripting", 7.5),
    ("ssrf", 8.0),
    ("authentication", 8.0),
    ("auth bypass", 8.5),
    ("hardcoded secret", 7.0),
    ("secret", 6.5),
    ("idor", 7.5),
    ("csrf", 6.0),
    ("weak cryptography", 5.0),
    ("crypto", 5.0),
    ("insecure random", 4.5),
    ("weak hash", 5.0),
    ("open redirect", 4.0),
    ("information disclosure", 4.5),
    ("misconfiguration", 4.0),
    ("dependency", 5.5),
    ("outdated", 4.5),
]
_DEFAULT_EXPLOITABILITY = 5.0  # unrecognized category — assume moderate, not extreme

_CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.85, "low": 0.65}

# ── exposure heuristic: file path -> internet-facing likelihood ─────────
_HIGH_EXPOSURE_PATH_RE = re.compile(
    r"(^|/)(routes?|api|controllers?|handlers?|endpoints?|views?|public|www|server)(/|$)", re.IGNORECASE
)
_LOW_EXPOSURE_PATH_RE = re.compile(
    r"(^|/)(test|tests|__tests__|spec|specs|internal|lib|utils?|scripts?|migrations?|docs?)(/|$)", re.IGNORECASE
)
_DEFAULT_EXPOSURE = 0.7

# ── asset-criticality heuristic: repo name -> business criticality ──────
_HIGH_CRITICALITY_REPO_RE = re.compile(r"(prod|production|core|payment|billing|auth|checkout)", re.IGNORECASE)
_LOW_CRITICALITY_REPO_RE = re.compile(r"(sandbox|test|demo|sample|poc|playground|infra|tooling)", re.IGNORECASE)
_DEFAULT_ASSET_CRITICALITY = 0.75

# ── EAL: per-severity base financial impact (USD/year) ───────────────────
# Documented placeholder methodology (see module docstring) — PatchLine has
# no real business-impact data source to draw from.
_FINANCIAL_IMPACT_BASE = {"CRITICAL": 220_000, "HIGH": 95_000, "MEDIUM": 30_000, "LOW": 6_000}

# ── post-fix residual risk ───────────────────────────────────────────────
# A verified fix isn't formal proof of absence of risk (Codex + the
# deterministic scanner both passing is strong evidence, not a guarantee),
# so post-fix risk is modeled as a small residual fraction of the original
# rather than zero. 0.12 -> ~88% typical reduction, in the same ballpark as
# the product spec's own worked example (94 -> 18, an 81% reduction).
RESIDUAL_RISK_FRACTION = 0.12


def _severity_base(sev: str) -> int:
    return _SEVERITY_BASE.get(severity_module.normalize(sev), _SEVERITY_BASE["MEDIUM"])


def _exploitability(category: Optional[str], confidence: Optional[str]) -> float:
    cat = (category or "").strip().lower()
    score = _DEFAULT_EXPLOITABILITY
    for keyword, value in _EXPLOITABILITY_KEYWORDS:
        if keyword in cat:
            score = value
            break
    if confidence:
        score *= _CONFIDENCE_MULTIPLIER.get(str(confidence).strip().lower(), 1.0)
    return round(max(0.0, min(10.0, score)), 2)


def _exposure(file_path: Optional[str]) -> float:
    path = file_path or ""
    if _HIGH_EXPOSURE_PATH_RE.search(path):
        return 1.0
    if _LOW_EXPOSURE_PATH_RE.search(path):
        return 0.35
    return _DEFAULT_EXPOSURE


def _asset_criticality(repo: Optional[str]) -> float:
    name = repo or ""
    if _HIGH_CRITICALITY_REPO_RE.search(name):
        return 1.0
    if _LOW_CRITICALITY_REPO_RE.search(name):
        return 0.5
    return _DEFAULT_ASSET_CRITICALITY


def _risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def calculate_finding_risk(finding: dict, repo: Optional[str] = None) -> dict:
    """Deterministic risk snapshot for one finding. Pure function of its
    inputs — same finding + repo always produces the same output, which is
    what "reproducible/auditable" (PatchLine architecture rule) requires."""
    sev = severity_module.normalize(finding.get("severity"))
    base = _severity_base(sev)
    exploitability = _exploitability(finding.get("category"), finding.get("confidence"))
    exposure = _exposure(finding.get("file"))
    asset_criticality = _asset_criticality(repo)

    exploitability_multiplier = 0.4 + 0.6 * (exploitability / 10.0)
    exposure_multiplier = 0.5 + 0.5 * exposure
    risk_score = round(base * exploitability_multiplier * exposure_multiplier * asset_criticality)
    risk_score = max(0, min(100, risk_score))

    probability_of_exploitation = round(max(0.0, min(1.0, (exploitability / 10.0) * exposure)), 4)
    financial_impact = round(_FINANCIAL_IMPACT_BASE.get(sev, _FINANCIAL_IMPACT_BASE["MEDIUM"]) * exposure)
    eal = round(probability_of_exploitation * financial_impact)

    return {
        "riskScore": risk_score,
        "riskLevel": _risk_level(risk_score),
        "severity": sev,
        "exploitability": exploitability,
        "exposure": round(exposure, 2),
        "assetCriticality": round(asset_criticality, 2),
        "probabilityOfExploitation": probability_of_exploitation,
        "financialImpact": financial_impact,
        "eal": {"annualLoss": eal, "currency": "USD"},
        "methodology": METHODOLOGY_VERSION,
    }


def recalculate_after_fix(risk_before: dict) -> dict:
    """Post-fix risk snapshot, derived from the pre-fix snapshot rather than
    recomputed from scratch — a verified fix drives risk down to a small
    residual fraction of what it was (see RESIDUAL_RISK_FRACTION), it
    doesn't reset the finding's inherent category/exposure/criticality
    profile, which haven't changed.

    Invariant: post-fix risk must never exceed pre-fix risk — a verified fix
    claiming risk went UP would be actively misleading (see
    risk_reduction_pct's matching clamp). Structurally guaranteed here since
    RESIDUAL_RISK_FRACTION < 1, but clamped explicitly anyway as defense in
    depth against that constant ever being misconfigured above 1."""
    risk_score_after = min(round(risk_before["riskScore"] * RESIDUAL_RISK_FRACTION), risk_before["riskScore"])
    eal_before = risk_before["eal"]["annualLoss"]
    eal_after = min(round(eal_before * RESIDUAL_RISK_FRACTION), eal_before)
    return {
        "riskScore": risk_score_after,
        "riskLevel": _risk_level(risk_score_after),
        "severity": risk_before.get("severity"),
        "exploitability": round(risk_before["exploitability"] * RESIDUAL_RISK_FRACTION, 2),
        "exposure": risk_before.get("exposure"),
        "assetCriticality": risk_before.get("assetCriticality"),
        "probabilityOfExploitation": round(
            risk_before["probabilityOfExploitation"] * RESIDUAL_RISK_FRACTION, 4
        ),
        "financialImpact": risk_before.get("financialImpact"),
        "eal": {"annualLoss": eal_after, "currency": "USD"},
        "methodology": METHODOLOGY_VERSION,
    }


def risk_reduction_pct(risk_before: dict, risk_after: dict) -> float:
    """Percentage drop in riskScore, 0-100. Two things this deliberately
    does NOT do:
      - Report a negative number when risk_after > risk_before (clamped to
        0.0) — a fix pipeline must never claim "risk reduced" when risk
        measurably went up, whatever produced that input.
      - Treat risk_before's score being 0 as an error — 0.0 (nothing to
        reduce) is the correct answer, not an exception.
    Callers that need to know risk actually INCREASED (as opposed to just
    "0% reduction") should compare risk_after['riskScore'] >
    risk_before['riskScore'] directly rather than inferring it from this
    function returning 0.0, since that return value is intentionally
    ambiguous between "no change" and "got worse"."""
    before = risk_before.get("riskScore", 0)
    if not before:
        return 0.0
    after = risk_after.get("riskScore", 0)
    return round(max(0.0, (before - after) / before * 100), 1)


# ── project/scan-level aggregation ───────────────────────────────────────
# Powers the dashboard's "Executive Metrics" (Risk Score, EAL, VaR) —
# PatchLine architecture rule: this is the Risk Engine's calculation,
# Elasticsearch/the frontend only display it, never recompute it.

# Simplified VaR heuristic (see module docstring): treat annual loss as
# approximately normal with stddev = _VAR_STDDEV_FRACTION * mean, and use
# the one-tailed z-score for _VAR_CONFIDENCE.
_VAR_CONFIDENCE = 0.95
_VAR_HORIZON_DAYS = 365
_VAR_STDDEV_FRACTION = 0.6
_VAR_Z_SCORE_95 = 1.645


def aggregate_project_risk(finding_risks: list[dict]) -> dict:
    """Roll many findings' individual risk snapshots up into one
    project/scan-level overview. Deliberately NOT a plain average — a
    portfolio with one CRITICAL and nine LOW findings is meaningfully
    riskier than "average of ten mostly-low scores" would suggest, so the
    overall score is dominated by the worst finding and moderated by the
    mean (documented weighting, not an unexplained magic number)."""
    if not finding_risks:
        return {
            "overallRiskScore": 0,
            "riskLevel": "LOW",
            "eal": {"annualLoss": 0, "currency": "USD"},
            "var": {"value": 0, "currency": "USD", "confidence": _VAR_CONFIDENCE, "horizonDays": _VAR_HORIZON_DAYS},
            "findingsBySeverity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "methodology": METHODOLOGY_VERSION,
        }

    scores = [r["riskScore"] for r in finding_risks]
    overall = round(0.6 * max(scores) + 0.4 * (sum(scores) / len(scores)))
    overall = max(0, min(100, overall))

    eal_total = sum(r["eal"]["annualLoss"] for r in finding_risks)
    var_value = round(eal_total + _VAR_Z_SCORE_95 * _VAR_STDDEV_FRACTION * eal_total)

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in finding_risks:
        level = r.get("riskLevel", "LOW").lower()
        if level in by_severity:
            by_severity[level] += 1

    return {
        "overallRiskScore": overall,
        "riskLevel": _risk_level(overall),
        "eal": {"annualLoss": eal_total, "currency": "USD"},
        "var": {
            "value": var_value,
            "currency": "USD",
            "confidence": _VAR_CONFIDENCE,
            "horizonDays": _VAR_HORIZON_DAYS,
            "methodology": "simplified",
        },
        "findingsBySeverity": by_severity,
        "methodology": METHODOLOGY_VERSION,
    }
