import datetime

from app.services.reconciliation import _is_stale


def _iso(minutes_ago: float) -> str:
    ts = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes_ago)
    return ts.isoformat() + "Z"


def test_missing_timestamp_is_treated_as_stale():
    assert _is_stale(None, threshold_minutes=30) is True
    assert _is_stale("", threshold_minutes=30) is True


def test_recent_timestamp_is_not_stale():
    assert _is_stale(_iso(5), threshold_minutes=30) is False


def test_old_timestamp_is_stale():
    assert _is_stale(_iso(45), threshold_minutes=30) is True


def test_boundary_just_under_threshold_is_not_stale():
    assert _is_stale(_iso(29), threshold_minutes=30) is False


def test_unparseable_timestamp_is_treated_as_stale():
    assert _is_stale("not-a-real-timestamp", threshold_minutes=30) is True
