"""
Shared severity scale for the whole scan pipeline.

Before this module existed, the deterministic engines (semgrep_engine._severity_for)
and the AI supplemental layer (routers/scanner.py's _ai_supplemental_scan) each
normalized severity independently. The deterministic side was already strict —
always one of CANONICAL below — but the AI side just did
`item.get("severity", "INFO").upper()` with no whitelist, so a model could return
a 5th value ("INFO", not in the deterministic scale) or literally any string.
That surfaced as a real, visible bug: the frontend's per-severity summary badges
(app/scanner/page.tsx) only iterate CRITICAL/HIGH/MEDIUM/LOW, silently excluding
INFO findings from that count, while the pie chart on the same page included
INFO — two different totals for the same dataset on the same screen.

Fix is structural, not a frontend patch: normalize every finding, regardless of
source, onto ONE 4-level scale before it ever reaches a response or the
frontend. `normalize()` is the single choke point both layers call through.
"""

from typing import Optional

# The canonical scale. Every finding the API returns — deterministic or AI —
# has severity in this set. Nothing downstream needs to handle a 5th value.
CANONICAL = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Aliases a model (or a future engine) might reasonably return that map onto
# the canonical scale. INFO collapses into LOW rather than getting its own
# tier — same choice semgrep_engine.py already made for semgrep's own INFO
# level (_SEMGREP_TO_INTERNAL_SEVERITY), so this keeps AI findings on the
# same footing instead of introducing a scale deterministic findings don't have.
_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
    "INFORMATIONAL": "LOW",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
}

DEFAULT = "MEDIUM"  # unrecognized/missing severity — err toward a human looking at it


def normalize(raw: Optional[str]) -> str:
    """Map any severity string (or None) onto CANONICAL. Never raises, never
    returns a value outside CANONICAL — callers can rely on that unconditionally."""
    if not raw:
        return DEFAULT
    return _ALIASES.get(str(raw).strip().upper(), DEFAULT)
