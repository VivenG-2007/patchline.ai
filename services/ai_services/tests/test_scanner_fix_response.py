# Regression test for a NameError that used to crash generate_and_verify_fix.
#
# The old code built the `aiVerification` block of FixResponse inline, and
# one branch referenced a bare `settings` name that was never assigned
# anywhere in generate_and_verify_fix's own scope (it only exists inside
# _codex_review_fix's/_generate_fix's separate local scopes). Every real
# Codex response already carries a "model" key (model_router.chat_for_task
# always injects one — see test_model_router.py), so this branch is
# unreachable in normal operation and every existing test happened to avoid
# it. It only fires when a caller hands `_build_ai_verification_payload` a
# codex dict that is missing "model" — which is exactly what this test does.
#
# The fix (see app/routers/scanner.py) pulls that dict construction into its
# own top-level function, `_build_ai_verification_payload`, that always
# resolves a fresh `get_settings()` rather than depending on whatever
# variable name a caller's local scope happens to use.

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

from app.routers import scanner


def test_verify_model_never_raises_nameerror_when_codex_response_lacks_model():
    """The exact regression scenario: Codex 'succeeded' (verified=True) but
    its result dict has no 'model' key at all. Building the aiVerification
    payload from this must not raise — it must fall back to the configured
    verify-tier model."""
    codex_without_model = {
        "verified": True,
        "vulnerabilityResolved": True,
        "rootCauseFixed": True,
        "bypasses": [],
        "regressionRisk": "LOW",
        "issues": [],
        "confidence": 0.9,
        "notes": "Looks solid.",
        "provider": "featherless",
        "callFailed": False,
        # deliberately no "model" key
    }

    # This is the call that used to raise NameError: name 'settings' is not defined.
    payload = scanner._build_ai_verification_payload(codex_without_model)

    assert payload is not None
    assert payload["status"] == "PASSED"
    assert payload["model"], "must fall back to the configured verify model, not None/blank"
    assert isinstance(payload["model"], str)


def test_verify_model_fallback_is_the_configured_verify_deployment(monkeypatch):
    """When Codex's own result has no model, the fallback must be
    _verify_model()'s resolution (verify deployment, else the shared
    default deployment) — not some other tier's model."""
    settings = scanner.get_settings()
    monkeypatch.setattr(settings, "azure_openai_deployment_verify", "codex-5.3-test-deployment")

    codex_without_model = {
        "verified": False,
        "vulnerabilityResolved": False,
        "rootCauseFixed": False,
        "bypasses": [],
        "regressionRisk": "HIGH",
        "issues": ["still exploitable"],
        "confidence": 0.4,
        "notes": "Rejected.",
        "provider": "azure_openai",
        "callFailed": False,
    }

    payload = scanner._build_ai_verification_payload(codex_without_model)
    assert payload["model"] == "codex-5.3-test-deployment"
    assert payload["status"] == "FAILED"


def test_verify_model_uses_codex_own_model_when_present():
    """The normal path: Codex's result already names its own model, so no
    fallback resolution should be needed at all."""
    codex = {
        "verified": True,
        "vulnerabilityResolved": True,
        "rootCauseFixed": True,
        "bypasses": [],
        "regressionRisk": "LOW",
        "issues": [],
        "confidence": 0.95,
        "notes": "",
        "model": "deepseek-v4-pro",
        "provider": "featherless",
        "callFailed": False,
    }
    payload = scanner._build_ai_verification_payload(codex)
    assert payload["model"] == "deepseek-v4-pro"


def test_ai_verification_payload_is_none_when_verification_never_ran():
    """Duplicate-strategy hard block skips Codex entirely — codex is None,
    and the payload must be None too (never a dict full of fallback/zero
    values that would misleadingly look like a real, completed review)."""
    assert scanner._build_ai_verification_payload(None) is None
