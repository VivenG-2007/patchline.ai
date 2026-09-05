"""
Explicit state machine for a finding's remediation lifecycle.

This is the ai-storage-service's own copy of the same machine enforced in
main-service/src/services/findingState.js. It exists here too as a defense-in-depth
check: main-service's /approve-fix is the only place a human can move a finding
out of AWAITING_APPROVAL, but generate_and_verify_fix() is a real HTTP endpoint —
if it only trusted the caller, a bug (or a duplicate/racing job) could
re-generate a fix for a finding that's already FIX_VERIFIED, or that has already
exhausted its bounded retry budget. Both services must agree on the same
transitions and MAX_FIX_ATTEMPTS; if you change one, change the other.
"""

from __future__ import annotations

from typing import Optional

MAX_FIX_ATTEMPTS = 3

TRANSITIONS: dict[str, list[str]] = {
    # Two allowed destinations from AWAITING_APPROVAL:
    #  - FIX_QUEUED: the textbook path, if this service's own Mongo copy
    #    already has a fix record for this finding.
    #  - FIX_PROCESSING: the path that actually happens in production. The
    #    real human-approval gate lives in main-service, backed by Redis
    #    (scanStore.transitionFix), NOT in this service's Mongo scan_history
    #    doc — main-service's AWAITING_APPROVAL -> FIX_QUEUED write never
    #    reaches Mongo. So by the time the worker calls this endpoint with
    #    FIX_PROCESSING, Mongo still reads AWAITING_APPROVAL (no fix record
    #    yet) even though the finding really was approved. That's expected,
    #    not a skipped step: this whole router requires
    #    require_internal_service_token (see router() above), so only
    #    main-service's already-gated worker can ever reach here — nothing
    #    external can use this to bypass approval.
    "AWAITING_APPROVAL": ["FIX_QUEUED", "FIX_PROCESSING"],
    "FIX_QUEUED": ["FIX_PROCESSING", "FIX_FAILED"],
    # Self-loop for the same reason as the JS version: a retried job re-enters
    # FIX_PROCESSING before redoing the work. FIX_UNRESOLVED is the terminal
    # "no valid fix / human review required" state — reached directly from
    # FIX_PROCESSING (not via FIX_NEEDS_REVIEW/FIX_FAILED) because the
    # decision that this was the LAST bounded attempt is made in the same
    # request that just finished verifying it; see generate_and_verify_fix's
    # Step 5 terminal-state comment.
    "FIX_PROCESSING": ["FIX_PROCESSING", "FIX_VERIFIED", "FIX_NEEDS_REVIEW", "FIX_FAILED", "FIX_UNRESOLVED"],
    "FIX_NEEDS_REVIEW": ["FIX_QUEUED", "FIX_PROCESSING"],
    "FIX_FAILED": ["FIX_QUEUED", "FIX_PROCESSING"],
    "FIX_VERIFIED": [],
    # Terminal, like FIX_VERIFIED — no outgoing transitions. Reached when a
    # finding has exhausted MAX_FIX_ATTEMPTS bounded remediation attempts
    # without producing a verified fix (PatchLine architecture: "If all
    # viable strategies fail, mark the finding UNRESOLVED" /
    # "manualInterventionRequired = true"). Distinct from FIX_NEEDS_REVIEW
    # (which IS retryable) specifically so a finding stuck here reads as
    # "needs a human to intervene directly", not "try again" — a UI or
    # ticketing integration can filter on this status (+ the
    # reasonCode="NO_VALID_FIX" / manualInterventionRequired=true fields
    # generate_and_verify_fix also writes) without having to separately
    # cross-reference the attempts counter.
    "FIX_UNRESOLVED": [],
}

_RETRY_SOURCES = {"FIX_NEEDS_REVIEW", "FIX_FAILED"}


class InvalidTransitionError(Exception):
    def __init__(self, message: str, *, from_status: str, to_status: str, code: str = "INVALID_TRANSITION"):
        super().__init__(message)
        self.from_status = from_status
        self.to_status = to_status
        self.code = code


def current_status(scan_doc: Optional[dict], finding_id: str) -> str:
    fixes = (scan_doc or {}).get("fixes") or {}
    return (fixes.get(finding_id) or {}).get("status") or "AWAITING_APPROVAL"


def attempts_so_far(scan_doc: Optional[dict], finding_id: str) -> int:
    fixes = (scan_doc or {}).get("fixes") or {}
    return (fixes.get(finding_id) or {}).get("attempts") or 0


def assert_transition(scan_doc: Optional[dict], finding_id: str, to_status: str) -> str:
    """Raises InvalidTransitionError if `to_status` isn't reachable from the
    finding's current status, or if a retry would exceed MAX_FIX_ATTEMPTS.
    Returns the current ("from") status on success."""
    from_status = current_status(scan_doc, finding_id)
    allowed = TRANSITIONS.get(from_status)
    if allowed is None:
        raise InvalidTransitionError(
            f"Unknown finding status '{from_status}'", from_status=from_status, to_status=to_status, code="UNKNOWN_STATUS"
        )
    if to_status not in allowed:
        raise InvalidTransitionError(
            f"Cannot move finding {finding_id} from {from_status} to {to_status}",
            from_status=from_status, to_status=to_status,
        )
    if to_status in ("FIX_QUEUED", "FIX_PROCESSING") and from_status in _RETRY_SOURCES:
        attempts = attempts_so_far(scan_doc, finding_id)
        if attempts >= MAX_FIX_ATTEMPTS:
            raise InvalidTransitionError(
                f"Finding {finding_id} has exhausted its {MAX_FIX_ATTEMPTS} bounded fix attempts",
                from_status=from_status, to_status=to_status, code="FIX_ATTEMPTS_EXHAUSTED",
            )
    return from_status