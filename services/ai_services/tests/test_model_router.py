import os

os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import pytest

from app.config import get_settings
from app.services import model_router


class _FakeProvider:
    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise_exc = raise_exc
        self.calls = []

    async def chat(self, messages, model=None):
        self.calls.append({"messages": messages, "model": model})
        if self._raise_exc:
            raise self._raise_exc
        return self._response


@pytest.fixture(autouse=True)
def _reset_featherless_settings():
    """Featherless settings are process-global (pydantic-settings singleton
    via get_settings()) — reset before AND after each test so one test
    enabling Featherless can't leak into the next."""
    settings = get_settings()
    original = (
        settings.featherless_enabled,
        settings.featherless_api_key,
    )
    yield
    settings.featherless_enabled, settings.featherless_api_key = original


def _enable_featherless(monkeypatch, key="fake-key"):
    settings = get_settings()
    settings.featherless_enabled = True
    settings.featherless_api_key = key


# ── Featherless disabled (default) — pure passthrough to the fallback ──

@pytest.mark.asyncio
async def test_featherless_disabled_goes_straight_to_fallback():
    settings = get_settings()
    settings.featherless_enabled = False
    fallback = _FakeProvider(response={"content": "fallback answer", "usage": {}})

    result = await model_router.chat_for_task("fix", [{"role": "user", "content": "hi"}], fallback, "some-model")

    assert result["content"] == "fallback answer"
    assert result["model"] == "some-model"
    assert len(fallback.calls) == 1


@pytest.mark.asyncio
async def test_featherless_disabled_never_touches_featherless_provider(monkeypatch):
    """Regression guard: with Featherless off, get_provider_by_name('featherless')
    must never even be called — this is what guarantees zero behavior change
    for every deployment that hasn't set FEATHERLESS_API_KEY."""
    settings = get_settings()
    settings.featherless_enabled = False

    def _boom(name):
        raise AssertionError(f"get_provider_by_name('{name}') should not be called when Featherless is disabled")

    monkeypatch.setattr(model_router, "get_provider_by_name", _boom)
    fallback = _FakeProvider(response={"content": "ok", "usage": {}})
    result = await model_router.chat_for_task("analysis", [{"role": "user", "content": "hi"}], fallback, "m")
    assert result["content"] == "ok"


# ── Featherless enabled: primary success ─────────────────────────────────

@pytest.mark.asyncio
async def test_featherless_success_never_calls_fallback(monkeypatch):
    _enable_featherless(monkeypatch)
    featherless = _FakeProvider(response={"content": "featherless answer", "usage": {}})
    monkeypatch.setattr(model_router, "get_provider_by_name", lambda name: featherless)

    fallback = _FakeProvider(response={"content": "should not be used", "usage": {}})
    result = await model_router.chat_for_task("verify", [{"role": "user", "content": "hi"}], fallback, "fallback-model")

    assert result["content"] == "featherless answer"
    assert result["provider"] == "featherless"
    assert len(fallback.calls) == 0


@pytest.mark.asyncio
async def test_featherless_uses_the_correct_per_task_model(monkeypatch):
    _enable_featherless(monkeypatch)
    settings = get_settings()
    featherless = _FakeProvider(response={"content": "ok", "usage": {}})
    monkeypatch.setattr(model_router, "get_provider_by_name", lambda name: featherless)
    fallback = _FakeProvider(response={"content": "x", "usage": {}})

    result = await model_router.chat_for_task("fix", [{"role": "user", "content": "hi"}], fallback, "irrelevant")
    assert result["model"] == settings.featherless_model_fix

    result = await model_router.chat_for_task("verify", [{"role": "user", "content": "hi"}], fallback, "irrelevant")
    assert result["model"] == settings.featherless_model_verify


# ── Featherless enabled: primary fails, fallback is used ─────────────────

@pytest.mark.asyncio
async def test_featherless_failure_falls_back_transparently(monkeypatch):
    _enable_featherless(monkeypatch)
    featherless = _FakeProvider(raise_exc=RuntimeError("timeout"))
    monkeypatch.setattr(model_router, "get_provider_by_name", lambda name: featherless)
    fallback = _FakeProvider(response={"content": "fallback saved us", "usage": {}})

    result = await model_router.chat_for_task("fix", [{"role": "user", "content": "hi"}], fallback, "fallback-model")

    assert result["content"] == "fallback saved us"
    assert result["model"] == "fallback-model"
    assert len(featherless.calls) == 1
    assert len(fallback.calls) == 1


@pytest.mark.asyncio
async def test_both_providers_failing_raises_ai_router_error(monkeypatch):
    _enable_featherless(monkeypatch)
    featherless = _FakeProvider(raise_exc=RuntimeError("featherless down"))
    monkeypatch.setattr(model_router, "get_provider_by_name", lambda name: featherless)
    fallback = _FakeProvider(raise_exc=RuntimeError("fallback also down"))

    with pytest.raises(model_router.AIRouterError):
        await model_router.chat_for_task("verify", [{"role": "user", "content": "hi"}], fallback, "m")


@pytest.mark.asyncio
async def test_featherless_enabled_but_no_fallback_supplied_raises_cleanly(monkeypatch):
    _enable_featherless(monkeypatch)
    featherless = _FakeProvider(raise_exc=RuntimeError("down"))
    monkeypatch.setattr(model_router, "get_provider_by_name", lambda name: featherless)

    with pytest.raises(model_router.AIRouterError):
        await model_router.chat_for_task("fix", [{"role": "user", "content": "hi"}], None, None)


# ── Misc ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unknown_task_raises_value_error():
    fallback = _FakeProvider(response={"content": "x", "usage": {}})
    with pytest.raises(ValueError):
        await model_router.chat_for_task("not_a_real_task", [], fallback, "m")
