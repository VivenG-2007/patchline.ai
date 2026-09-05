from app.core.fingerprint import (
    find_duplicate_strategy,
    normalize_strategy_text,
    strategy_fingerprint,
    strategy_similarity,
)


# ── normalize_strategy_text ──────────────────────────────────────────────

def test_normalize_lowercases_and_strips_punctuation():
    assert normalize_strategy_text("Parameterize the SQL Query!") == "parameterize sql query"


def test_normalize_strips_stopwords_but_preserves_alphanumeric_tokens():
    # "12" (a pure-digit token) is dropped, but "md5" (digits embedded in an
    # alphanumeric token) must survive intact — mangling it to "md" would
    # silently change what the strategy actually says.
    assert normalize_strategy_text("Use bcrypt with 12 rounds instead of MD5") == "bcrypt rounds md5"


def test_normalize_empty_input():
    assert normalize_strategy_text("") == ""
    assert normalize_strategy_text(None) == ""


# ── strategy_fingerprint ─────────────────────────────────────────────────

def test_fingerprint_is_order_independent():
    fp1 = strategy_fingerprint("Parameterized the query and removed string concatenation", "injection", "app.py")
    fp2 = strategy_fingerprint("Removed string concatenation, parameterized the query", "injection", "app.py")
    assert fp1 == fp2


def test_fingerprint_differs_by_scope():
    fp1 = strategy_fingerprint("parameterized the query", "injection", "app.py")
    fp2 = strategy_fingerprint("parameterized the query", "injection", "other.py")
    assert fp1 != fp2


def test_fingerprint_differs_for_different_strategies():
    fp1 = strategy_fingerprint("parameterized the SQL query", "injection", "app.py")
    fp2 = strategy_fingerprint("added input length validation", "injection", "app.py")
    assert fp1 != fp2


def test_fingerprint_is_deterministic():
    a = strategy_fingerprint("switched to bcrypt", "crypto", "hash.py")
    b = strategy_fingerprint("switched to bcrypt", "crypto", "hash.py")
    assert a == b
    assert len(a) == 16


# ── strategy_similarity ──────────────────────────────────────────────────

def test_similarity_identical_text_is_one():
    assert strategy_similarity("parameterized the query", "parameterized the query") == 1.0


def test_similarity_paraphrase_is_high():
    a = "Parameterized the SQL query to prevent injection"
    b = "Used a parameterized query instead of string concatenation to prevent SQL injection"
    sim = strategy_similarity(a, b)
    assert sim > 0.3  # meaningful overlap even though wording differs


def test_similarity_unrelated_strategies_is_low():
    a = "Parameterized the SQL query"
    b = "Rotated the API key and moved it to a secrets manager"
    assert strategy_similarity(a, b) < 0.2


def test_similarity_empty_input_is_zero():
    assert strategy_similarity("", "parameterized the query") == 0.0
    assert strategy_similarity("parameterized the query", "") == 0.0
    assert strategy_similarity(None, None) == 0.0


# ── find_duplicate_strategy ──────────────────────────────────────────────

def test_find_duplicate_strategy_detects_near_exact_repeat():
    prior = ["Parameterized the SQL query to remove string concatenation"]
    candidate = "Parameterize the SQL query and remove the string concatenation"
    assert find_duplicate_strategy(candidate, prior) == prior[0]


def test_find_duplicate_strategy_allows_genuinely_different_approach():
    prior = ["Parameterized the SQL query to remove string concatenation"]
    candidate = "Switched to an ORM with built-in query escaping and added an allowlist for sortable columns"
    assert find_duplicate_strategy(candidate, prior) is None


def test_find_duplicate_strategy_no_prior_history():
    assert find_duplicate_strategy("Parameterized the query", []) is None


def test_find_duplicate_strategy_empty_candidate():
    assert find_duplicate_strategy("", ["some prior strategy"]) is None


def test_find_duplicate_strategy_checks_against_multiple_priors():
    prior = [
        "Rotated the hardcoded API key",
        "Parameterized the SQL query to remove string concatenation",
    ]
    candidate = "Use parameterized queries instead of concatenating the SQL string"
    assert find_duplicate_strategy(candidate, prior) == prior[1]
