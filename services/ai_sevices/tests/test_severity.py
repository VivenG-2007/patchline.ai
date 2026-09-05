# Unit tests for app/services/severity.py — the shared normalization choke
# point both the deterministic engines and the AI supplemental layer route
# through (see that module's docstring for the bug this closes: AI findings
# used to be a bare `.upper()` with no whitelist, so a 5th "INFO" value or an
# arbitrary model-returned string could reach the frontend uncaught).

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

from app.services import severity


def test_canonical_values_pass_through_unchanged():
    for value in severity.CANONICAL:
        assert severity.normalize(value) == value


def test_lowercase_and_mixed_case_normalized():
    assert severity.normalize("critical") == "CRITICAL"
    assert severity.normalize("High") == "HIGH"
    assert severity.normalize("mEdIuM") == "MEDIUM"


def test_info_collapses_to_low():
    # Same choice semgrep_engine.py already made for semgrep's own INFO level —
    # AI findings shouldn't get a 5th tier deterministic findings don't have.
    assert severity.normalize("INFO") == "LOW"
    assert severity.normalize("informational") == "LOW"


def test_semgrep_style_aliases_map_onto_canonical_scale():
    assert severity.normalize("ERROR") == "HIGH"
    assert severity.normalize("WARNING") == "MEDIUM"


def test_unrecognized_string_falls_back_to_default():
    assert severity.normalize("severe") == severity.DEFAULT
    assert severity.normalize("banana") == severity.DEFAULT
    assert severity.normalize("") == severity.DEFAULT


def test_none_and_missing_fall_back_to_default():
    assert severity.normalize(None) == severity.DEFAULT


def test_whitespace_is_tolerated():
    assert severity.normalize("  high  ") == "HIGH"


def test_result_is_always_in_canonical_set():
    # Property-style check: nothing this function returns can ever be a 5th
    # value — the specific bug that motivated this module.
    for candidate in ("INFO", "critical", "whatever", None, "", "warning", "MODERATE"):
        assert severity.normalize(candidate) in severity.CANONICAL
