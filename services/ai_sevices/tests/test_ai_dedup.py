# Unit tests for the AI-vs-deterministic and AI-vs-AI dedup logic in
# app/routers/scanner.py. Covers the specific gaps called out in review:
#   - off-by-one line numbers should still be caught (line-window, not
#     exact-line-only)
#   - a deterministic category outside the 5 hardcoded keyword sets should
#     still be caught via title-similarity, not silently pass through
#   - a distinct concern on the same/nearby line must NOT be dropped
#   - two AI findings describing the same issue (e.g. from different
#     batches) should collapse to one — there was previously no dedup
#     among AI findings at all

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

from app.routers.scanner import (
    _dedupe_ai_findings,
    _duplicates_deterministic_finding,
    _title_similarity,
)


# ──────────────────────── _title_similarity ────────────────────────

def test_identical_titles_are_fully_similar():
    assert _title_similarity("SQL Injection in login", "SQL Injection in login") == 1.0


def test_unrelated_titles_are_not_similar():
    assert _title_similarity("Missing CSRF token on logout", "Weak MD5 hash for passwords") < 0.3


def test_empty_title_never_matches():
    assert _title_similarity("", "SQL Injection") == 0.0
    assert _title_similarity("SQL Injection", "") == 0.0


def test_paraphrased_titles_still_overlap_enough():
    a = "Insecure Direct Object Reference on invoice endpoint"
    b = "IDOR vulnerability allows access to invoice by id"
    # Won't be 1.0 (different wording) but should clear the dedup threshold
    # on shared meaningful tokens ("invoice").
    assert _title_similarity(a, b) > 0.0


# ──────────────────────── _duplicates_deterministic_finding ────────────────────────

def _det(file="app.py", line=10, category="SQL Injection", title="SQL injection via string concat"):
    return {"file": file, "line": line, "category": category, "title": title}


def test_exact_line_and_keyword_match_is_a_duplicate():
    det_by_file = {"app.py": [_det()]}
    item = {"file": "app.py", "line": 10, "title": "SQL Injection risk", "description": ""}
    assert _duplicates_deterministic_finding(item, det_by_file) is True


def test_off_by_one_line_still_caught_via_title_similarity():
    # The AI's own line guess is often off by one before _locate_line
    # resolves it — this must not let an obvious duplicate through just
    # because it landed one line away from the deterministic finding.
    det_by_file = {"app.py": [_det(line=10, category="Insecure Deserialization",
                                    title="Insecure deserialization of user input")]}
    item = {
        "file": "app.py", "line": 11,
        "title": "Insecure deserialization of untrusted user input",
        "description": "",
    }
    assert _duplicates_deterministic_finding(item, det_by_file) is True


def test_category_outside_hardcoded_keyword_sets_still_caught():
    # "Insecure Deserialization" has no entry in _COVERED_CATEGORY_KEYWORDS —
    # this only survives via the title-similarity fallback, which is the
    # gap the keyword-only version of this check used to have.
    det_by_file = {"app.py": [_det(line=20, category="Insecure Deserialization",
                                    title="Unsafe pickle.loads on request body")]}
    item = {
        "file": "app.py", "line": 20,
        "title": "Unsafe pickle.loads call on request body",
        "description": "",
    }
    assert _duplicates_deterministic_finding(item, det_by_file) is True


def test_distinct_concern_on_same_line_is_not_dropped():
    # An IDOR finding sharing a line with a SQLi finding is a different,
    # additive issue and must survive — low title overlap, no keyword match.
    det_by_file = {"app.py": [_det(line=10, category="SQL Injection",
                                    title="SQL injection via string concat")]}
    item = {
        "file": "app.py", "line": 10,
        "title": "Missing authorization check allows accessing other users' records",
        "description": "",
    }
    assert _duplicates_deterministic_finding(item, det_by_file) is False


def test_no_deterministic_findings_in_file_is_never_a_duplicate():
    assert _duplicates_deterministic_finding({"file": "other.py", "line": 1, "title": "x"}, {}) is False


# ──────────────────────── _dedupe_ai_findings ────────────────────────

def test_dedupe_ai_findings_collapses_near_duplicate_across_batches():
    items = [
        {"file": "auth.py", "line": 40, "title": "Race condition in token refresh"},
        {"file": "auth.py", "line": 41, "title": "Race condition in token refresh logic"},
    ]
    result = _dedupe_ai_findings(items)
    assert len(result) == 1
    assert result[0]["line"] == 40  # first occurrence wins


def test_dedupe_ai_findings_keeps_distinct_findings():
    items = [
        {"file": "auth.py", "line": 40, "title": "Race condition in token refresh"},
        {"file": "auth.py", "line": 200, "title": "Missing rate limit on password reset"},
        {"file": "billing.py", "line": 40, "title": "SSRF via webhook URL"},
    ]
    result = _dedupe_ai_findings(items)
    assert len(result) == 3


def test_dedupe_ai_findings_empty_input():
    assert _dedupe_ai_findings([]) == []
