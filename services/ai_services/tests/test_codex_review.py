# Unit tests for the independent Codex review step in app/routers/scanner.py:
#   _unified_diff        — the diff artifact given to the reviewer
#   _codex_review_fix     — GPT-5.3 Codex's independent, adversarial review of
#                           the GPT-5.2 patch (never the same call as generation)
#
# Verifies:
#   - the reviewer sees the actual diff of the change, not just the raw files
#   - a clean, well-formed PASS response is honored
#   - an internally inconsistent response (verified: true alongside a bypass,
#     or a HIGH regression risk) is NOT trusted at face value — re-derived
#     server-side instead
#   - provider errors and unparseable output are reported as `callFailed`,
#     never silently treated as a passing review
#   - malformed regressionRisk values fail closed to HIGH

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import pytest

from app.routers import scanner


def _finding(**overrides):
    base = {
        "id": "f1",
        "title": "SQL Injection in login handler",
        "category": "injection",
        "severity": "HIGH",
        "file": "app/routes/auth.py",
        "description": "User input is concatenated directly into a SQL query.",
        "ruleKey": "sql-injection-concat",
    }
    base.update(overrides)
    return base


class _FakeProvider:
    """Stand-in for app.services.ai_providers.get_provider() — captures the
    exact messages it was called with so tests can assert on prompt content,
    and returns a scripted response."""

    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise_exc = raise_exc
        self.calls = []

    async def chat(self, messages, model=None):
        self.calls.append({"messages": messages, "model": model})
        if self._raise_exc:
            raise self._raise_exc
        return self._response


# ── _unified_diff ────────────────────────────────────────────────────────

def test_unified_diff_shows_the_actual_change():
    original = "def query(user_input):\n    return f\"SELECT * FROM users WHERE id={user_input}\"\n"
    fixed = "def query(user_input):\n    return \"SELECT * FROM users WHERE id=%s\", (user_input,)\n"
    diff = scanner._unified_diff(original, fixed, "app/db.py")
    assert "-" in diff and "+" in diff
    assert "a/app/db.py" in diff
    assert "b/app/db.py" in diff
    assert "%s" in diff


def test_unified_diff_no_change_returns_placeholder():
    same = "identical content\n"
    diff = scanner._unified_diff(same, same, "app/db.py")
    assert "no textual diff" in diff.lower()


# ── _codex_review_fix ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_codex_review_sends_diff_not_just_raw_files(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": true, '
            '"bypasses": [], "regressionRisk": "LOW", "issues": [], "confidence": 0.95, '
            '"notes": "Parameterized query, looks solid."}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)

    original = "query = \"SELECT * FROM users WHERE id=\" + user_input\n"
    fixed = "query = \"SELECT * FROM users WHERE id=%s\"\ncursor.execute(query, (user_input,))\n"
    result = await scanner._codex_review_fix(_finding(), original, fixed, "org/repo")

    assert result["callFailed"] is False
    assert result["verified"] is True
    user_msg = fake.calls[0]["messages"][1]["content"]
    assert "PATCH (unified diff" in user_msg
    assert "+" in user_msg and "-" in user_msg
    # System prompt should be the adversarial reviewer persona, not the
    # original weaker "double-checking" prompt.
    system_msg = fake.calls[0]["messages"][0]["content"]
    assert "ADVERSARIAL" in system_msg
    assert "bypasses" in system_msg


@pytest.mark.asyncio
async def test_codex_review_honors_clean_pass(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": true, '
            '"bypasses": [], "regressionRisk": "LOW", "issues": [], "confidence": 0.9, '
            '"notes": "Looks good."}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["verified"] is True
    assert result["regressionRisk"] == "LOW"
    assert result["bypasses"] == []


@pytest.mark.asyncio
async def test_codex_review_does_not_trust_verified_true_alongside_a_bypass(monkeypatch):
    """An internally inconsistent model response (says verified but also
    lists a bypass) must not be forwarded as a PASS."""
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": false, '
            '"bypasses": ["/admin/export endpoint still concatenates raw input"], '
            '"regressionRisk": "LOW", "issues": [], "confidence": 0.8, "notes": "Mostly fixed."}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["verified"] is False
    assert result["bypasses"]


@pytest.mark.asyncio
async def test_codex_review_does_not_trust_verified_true_with_high_regression_risk(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": true, '
            '"bypasses": [], "regressionRisk": "HIGH", "issues": [], "confidence": 0.7, "notes": "Risky."}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["verified"] is False
    assert result["regressionRisk"] == "HIGH"


@pytest.mark.asyncio
async def test_codex_review_rejects_when_vulnerability_not_resolved(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": false, "vulnerabilityResolved": false, "rootCauseFixed": false, '
            '"bypasses": [], "regressionRisk": "LOW", "issues": ["fix only handles one code path"], '
            '"confidence": 0.85, "notes": "Sibling query still vulnerable."}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["verified"] is False
    assert result["issues"]


@pytest.mark.asyncio
async def test_codex_review_provider_error_marks_call_failed_not_verified(monkeypatch):
    fake = _FakeProvider(raise_exc=RuntimeError("provider timeout"))
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["callFailed"] is True
    assert result["verified"] is False


@pytest.mark.asyncio
async def test_codex_review_unparseable_output_marks_call_failed_not_verified(monkeypatch):
    fake = _FakeProvider(response={"content": "I think this patch looks fine, sure!"})
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["callFailed"] is True
    assert result["verified"] is False


@pytest.mark.asyncio
async def test_codex_review_malformed_regression_risk_fails_closed_to_high(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": true, '
            '"bypasses": [], "regressionRisk": "who knows", "issues": [], "confidence": 0.5, "notes": ""}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["regressionRisk"] == "HIGH"
    assert result["verified"] is False  # HIGH regression risk forces verified=False


@pytest.mark.asyncio
async def test_codex_review_non_list_bypasses_and_issues_are_coerced_to_list(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": false, "vulnerabilityResolved": false, "rootCauseFixed": false, '
            '"bypasses": "still exploitable via header injection", '
            '"regressionRisk": "MEDIUM", "issues": "unrelated formatting changes", '
            '"confidence": 0.6, "notes": ""}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert isinstance(result["bypasses"], list) and len(result["bypasses"]) == 1
    assert isinstance(result["issues"], list) and len(result["issues"]) == 1


@pytest.mark.asyncio
async def test_codex_review_confidence_is_clamped_to_0_1(monkeypatch):
    fake = _FakeProvider(response={
        "content": (
            '{"verified": true, "vulnerabilityResolved": true, "rootCauseFixed": true, '
            '"bypasses": [], "regressionRisk": "LOW", "issues": [], "confidence": 5.0, "notes": ""}'
        )
    })
    monkeypatch.setattr(scanner, "get_provider", lambda: fake)
    result = await scanner._codex_review_fix(_finding(), "old", "new", "org/repo")
    assert result["confidence"] == 1.0
