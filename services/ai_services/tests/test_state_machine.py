# Pure unit tests for app/services/state_machine.py. Deliberately imported
# directly (not through app.main) so this suite has no FastAPI/Mongo
# dependency and can run in isolation.

import pytest

from app.services.state_machine import (
    MAX_FIX_ATTEMPTS,
    InvalidTransitionError,
    assert_transition,
    attempts_so_far,
    current_status,
)


def _doc(finding_id, status, attempts=0):
    return {"fixes": {finding_id: {"status": status, "attempts": attempts}}}


def test_current_status_defaults_to_awaiting_approval():
    assert current_status(None, "f1") == "AWAITING_APPROVAL"
    assert current_status({}, "f1") == "AWAITING_APPROVAL"
    assert current_status({"fixes": {}}, "f1") == "AWAITING_APPROVAL"


def test_attempts_so_far_defaults_to_zero():
    assert attempts_so_far(None, "f1") == 0
    assert attempts_so_far(_doc("f1", "FIX_FAILED", 2), "f1") == 2


def test_happy_path_full_lifecycle():
    doc = {}
    assert assert_transition(doc, "f1", "FIX_QUEUED") == "AWAITING_APPROVAL"

    doc = _doc("f1", "FIX_QUEUED")
    assert assert_transition(doc, "f1", "FIX_PROCESSING") == "FIX_QUEUED"

    doc = _doc("f1", "FIX_PROCESSING")
    assert assert_transition(doc, "f1", "FIX_VERIFIED") == "FIX_PROCESSING"


def test_awaiting_approval_can_also_jump_straight_to_fix_processing():
    # Documented divergence from the JS version: main-service's Redis-backed
    # AWAITING_APPROVAL -> FIX_QUEUED write never reaches this service's Mongo
    # doc, so the worker's FIX_PROCESSING call legitimately arrives while this
    # copy still reads AWAITING_APPROVAL.
    doc = {}
    assert assert_transition(doc, "f1", "FIX_PROCESSING") == "AWAITING_APPROVAL"


def test_fix_processing_self_loop_allowed():
    doc = _doc("f1", "FIX_PROCESSING")
    assert assert_transition(doc, "f1", "FIX_PROCESSING") == "FIX_PROCESSING"


def test_fix_verified_is_terminal():
    doc = _doc("f1", "FIX_VERIFIED")
    for to_status in ["FIX_QUEUED", "FIX_PROCESSING", "FIX_VERIFIED", "FIX_NEEDS_REVIEW", "FIX_FAILED"]:
        with pytest.raises(InvalidTransitionError):
            assert_transition(doc, "f1", to_status)


def test_cannot_double_approve_a_verified_finding():
    doc = _doc("f1", "FIX_VERIFIED")
    with pytest.raises(InvalidTransitionError):
        assert_transition(doc, "f1", "FIX_QUEUED")


def test_needs_review_and_failed_can_retry_to_queued():
    assert assert_transition(_doc("f1", "FIX_NEEDS_REVIEW", 1), "f1", "FIX_QUEUED") == "FIX_NEEDS_REVIEW"
    assert assert_transition(_doc("f1", "FIX_FAILED", 1), "f1", "FIX_QUEUED") == "FIX_FAILED"


def test_needs_review_and_failed_can_retry_directly_to_processing():
    assert assert_transition(_doc("f1", "FIX_NEEDS_REVIEW", 1), "f1", "FIX_PROCESSING") == "FIX_NEEDS_REVIEW"
    assert assert_transition(_doc("f1", "FIX_FAILED", 1), "f1", "FIX_PROCESSING") == "FIX_FAILED"


def test_retry_blocked_once_max_attempts_reached():
    doc = _doc("f1", "FIX_FAILED", MAX_FIX_ATTEMPTS)
    with pytest.raises(InvalidTransitionError) as exc_info:
        assert_transition(doc, "f1", "FIX_QUEUED")
    assert exc_info.value.code == "FIX_ATTEMPTS_EXHAUSTED"

    with pytest.raises(InvalidTransitionError) as exc_info_proc:
        assert_transition(doc, "f1", "FIX_PROCESSING")
    assert exc_info_proc.value.code == "FIX_ATTEMPTS_EXHAUSTED"


def test_retry_allowed_one_attempt_below_cap():
    doc = _doc("f1", "FIX_FAILED", MAX_FIX_ATTEMPTS - 1)
    assert assert_transition(doc, "f1", "FIX_QUEUED") == "FIX_FAILED"


def test_fix_queued_can_fail_before_processing():
    doc = _doc("f1", "FIX_QUEUED")
    assert assert_transition(doc, "f1", "FIX_FAILED") == "FIX_QUEUED"


def test_unknown_status_rejected():
    doc = _doc("f1", "SOME_MADE_UP_STATUS")
    with pytest.raises(InvalidTransitionError) as exc_info:
        assert_transition(doc, "f1", "FIX_QUEUED")
    assert exc_info.value.code == "UNKNOWN_STATUS"


def test_two_findings_tracked_independently():
    doc = {
        "fixes": {
            "f1": {"status": "FIX_VERIFIED", "attempts": 1},
            "f2": {"status": "AWAITING_APPROVAL", "attempts": 0},
        }
    }
    with pytest.raises(InvalidTransitionError):
        assert_transition(doc, "f1", "FIX_QUEUED")
    assert assert_transition(doc, "f2", "FIX_QUEUED") == "AWAITING_APPROVAL"


# ── FIX_UNRESOLVED (terminal "no valid fix / human review required" state) ──

def test_fix_processing_can_move_directly_to_unresolved():
    doc = _doc("f1", "FIX_PROCESSING", MAX_FIX_ATTEMPTS)
    assert assert_transition(doc, "f1", "FIX_UNRESOLVED") == "FIX_PROCESSING"


def test_fix_unresolved_is_terminal():
    doc = _doc("f1", "FIX_UNRESOLVED")
    for to_status in ["FIX_QUEUED", "FIX_PROCESSING", "FIX_VERIFIED", "FIX_NEEDS_REVIEW", "FIX_FAILED", "FIX_UNRESOLVED"]:
        with pytest.raises(InvalidTransitionError):
            assert_transition(doc, "f1", to_status)


def test_fix_unresolved_is_not_a_retry_source():
    # Unlike FIX_NEEDS_REVIEW/FIX_FAILED, FIX_UNRESOLVED must not accept a
    # retry — it's the terminal "exhausted, needs a human" state, not a
    # bounded-retry source.
    doc = _doc("f1", "FIX_UNRESOLVED", MAX_FIX_ATTEMPTS)
    with pytest.raises(InvalidTransitionError):
        assert_transition(doc, "f1", "FIX_QUEUED")
