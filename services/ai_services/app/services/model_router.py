"""
AI Router — Featherless (primary) -> fallback provider, per pipeline task.

PatchLine's model-routing table assigns each pipeline task its own primary
(Featherless) and fallback (OpenAI/Azure OpenAI) model:

    task           primary (Featherless)         fallback
    analysis       Qwen3-Coder-30B-A3B            gpt-4.1-mini
    rag_ranking    DeepSeek-V3-0324               gpt-5.2      (not wired — see below)
    fix            Qwen3-Coder-480B-A35B          gpt-5.2
    verify         DeepSeek-V3-0324               gpt-5.3-codex

This module is the ONLY place that decision gets made — callers never pick
a provider/model themselves for a routed task, they call `chat_for_task`
and get back whichever provider actually answered plus which one it was
(for the structured logging PatchLine's observability rules require).

Design choices, and why:

  - Fallback isn't a second copy of the routing logic — the CALLER supplies
    the fallback provider + model it would have used before this router
    existed (scanner.py's existing _scan_model/_fix_model/_verify_model
    functions, and its existing `get_provider()` call). That means when
    Featherless is disabled (FEATHERLESS_ENABLED unset/false, the default)
    or its call fails, behavior is byte-for-byte identical to the
    pre-router code path — every existing deployment and every existing
    test (which monkeypatches `get_provider()` directly) keeps working
    with zero changes required on their end.

  - Only a PROVIDER-LEVEL failure triggers fallback (an exception from the
    HTTP call itself — timeout, connection error, non-2xx status). A
    successful-but-low-quality response from Featherless is NOT treated as
    a failure here; content-level rejection (Codex saying a patch is bad,
    JSON that fails to parse) is each call site's own business, same as it
    was before Featherless existed, and retrying content-level problems
    against a totally different model would silently change what "retry"
    means throughout the pipeline.

  - "rag_ranking" is defined in Settings and in this module's per-task
    tables for completeness, but nothing in the pipeline currently calls
    `chat_for_task("rag_ranking", ...)` — RAG candidate ranking
    (app/core/memory_store.py's composite scorer) is intentionally
    deterministic, the same "don't let an LLM invent the number" principle
    the Risk Engine follows. The config exists so a future LLM-assisted
    tie-break has somewhere to plug in without a config migration.
"""

from __future__ import annotations

from typing import Optional

from app.config import get_settings
from app.core.logging import get_logger
from app.services.ai_providers import get_provider_by_name

logger = get_logger()

RoutedTask = str  # "analysis" | "rag_ranking" | "fix" | "verify"

_FEATHERLESS_MODEL_BY_TASK = {
    "analysis": lambda s: s.featherless_model_analysis,
    "rag_ranking": lambda s: s.featherless_model_rag_ranking,
    "fix": lambda s: s.featherless_model_fix,
    "verify": lambda s: s.featherless_model_verify,
}

_runtime_provider_health = {
    "featherless": {"status": "available", "last_error": None, "calls": 0, "failures": 0},
    "fallback": {"status": "available", "last_error": None, "calls": 0, "failures": 0},
}


class AIRouterError(Exception):
    """Both the primary (if attempted) and the fallback provider failed for
    this task. Callers treat this exactly like any other provider exception
    they'd have gotten pre-router — it does not introduce a new failure mode,
    just a clearer message about which providers were tried."""


def _featherless_available(settings) -> bool:
    return bool(settings.featherless_enabled and settings.featherless_api_key)


def get_provider_runtime_status() -> dict:
    """Returns dynamic backend health and runtime provider information for the UI."""
    settings = get_settings()
    is_f_configured = _featherless_available(settings)
    f_health = _runtime_provider_health["featherless"]
    fb_health = _runtime_provider_health["fallback"]

    # Determine status of Featherless AI
    if not is_f_configured:
        f_status = "disabled"
    elif f_health["status"] == "failed":
        f_status = "failed"
    elif f_health["calls"] > 0 and f_health["status"] == "working":
        f_status = "working"
    else:
        f_status = "available"

    # Fallback provider name (usually azure_openai or openai)
    fb_name = (settings.fallback_provider or settings.ai_provider or "azure_openai").lower()
    fb_display_name = "Azure OpenAI" if "azure" in fb_name else ("OpenAI" if "openai" in fb_name else fb_name.capitalize())
    
    if fb_health["status"] == "failed":
        fb_status = "failed"
    elif fb_health["calls"] > 0 and fb_health["status"] == "working":
        fb_status = "working"
    else:
        fb_status = "available"

    # Current active provider determination
    if f_status == "working":
        current_provider = "Featherless AI"
        current_model = settings.featherless_model_fix
        verifier_provider = "Featherless AI"
        verifier_model = settings.featherless_model_verify
    elif f_status == "available" and is_f_configured:
        current_provider = "Featherless AI"
        current_model = settings.featherless_model_fix
        verifier_provider = "Featherless AI"
        verifier_model = settings.featherless_model_verify
    else:
        # Featherless disabled or failed -> fallback is active
        current_provider = fb_display_name
        current_model = settings.fallback_model_fix or settings.azure_openai_deployment_fix or settings.ai_model
        verifier_provider = fb_display_name
        verifier_model = settings.fallback_model_verify or settings.azure_openai_deployment_verify or settings.ai_model

    return {
        "currentProvider": current_provider,
        "currentModel": current_model,
        "verifierProvider": verifier_provider,
        "verifierModel": verifier_model,
        "providers": {
            "featherless": {
                "name": "Featherless AI",
                "status": f_status,
                "isCurrent": current_provider == "Featherless AI",
                "model": settings.featherless_model_fix,
                "verifierModel": settings.featherless_model_verify,
                "lastError": f_health["last_error"],
            },
            "azure_openai": {
                "name": fb_display_name,
                "status": fb_status,
                "isCurrent": current_provider != "Featherless AI",
                "model": settings.fallback_model_fix or settings.azure_openai_deployment_fix or settings.ai_model,
                "verifierModel": settings.fallback_model_verify or settings.azure_openai_deployment_verify or settings.ai_model,
                "lastError": fb_health["last_error"],
            },
        },
    }


async def chat_for_task(
    task: RoutedTask,
    messages: list[dict],
    fallback_provider,
    fallback_model: Optional[str],
    *,
    log_context: Optional[dict] = None,
) -> dict:
    """Route one chat call through Featherless (if configured) with
    automatic fallback. `fallback_provider` is a provider module (whatever
    the caller's own `get_provider()` already resolved) and `fallback_model`
    is whatever model string the caller would have used anyway — see module
    docstring for why the fallback path is caller-supplied rather than
    re-derived here.

    Returns the provider's normal {content, usage} dict plus `provider` and
    `model`, so every call site can log exactly which model answered.
    """
    settings = get_settings()
    ctx = log_context or {}

    if task not in _FEATHERLESS_MODEL_BY_TASK:
        raise ValueError(f"Unknown routed task '{task}'. Known tasks: {', '.join(_FEATHERLESS_MODEL_BY_TASK)}")

    used_fallback = False
    if _featherless_available(settings):
        model = _FEATHERLESS_MODEL_BY_TASK[task](settings)
        try:
            featherless = get_provider_by_name("featherless")
            result = await featherless.chat(messages, model=model)
            _runtime_provider_health["featherless"]["status"] = "working"
            _runtime_provider_health["featherless"]["last_error"] = None
            _runtime_provider_health["featherless"]["calls"] += 1
            logger.info("ai_router_call", task=task, provider="featherless", model=model, fallback_used=False, **ctx)
            return {**result, "provider": "featherless", "model": model}
        except Exception as exc:  # noqa: BLE001 — provider failure, not a bug; falling back deliberately
            used_fallback = True
            _runtime_provider_health["featherless"]["status"] = "failed"
            _runtime_provider_health["featherless"]["last_error"] = str(exc)
            _runtime_provider_health["featherless"]["failures"] += 1
            logger.warning(
                "ai_router_primary_failed_falling_back",
                task=task, provider="featherless", model=model, error=str(exc), **ctx,
            )

    if fallback_provider is None or not fallback_model:
        raise AIRouterError(
            f"No usable provider for task '{task}': Featherless "
            f"{'failed' if used_fallback else 'not configured'} and no fallback provider/model was supplied."
        )

    try:
        result = await fallback_provider.chat(messages, model=fallback_model)
        _runtime_provider_health["fallback"]["status"] = "working"
        _runtime_provider_health["fallback"]["last_error"] = None
        _runtime_provider_health["fallback"]["calls"] += 1
    except Exception as exc:
        _runtime_provider_health["fallback"]["status"] = "failed"
        _runtime_provider_health["fallback"]["last_error"] = str(exc)
        _runtime_provider_health["fallback"]["failures"] += 1
        logger.error(
            "ai_router_all_providers_failed",
            task=task, fallback_model=fallback_model, error=str(exc), **ctx,
        )
        raise AIRouterError(f"All AI providers failed for task '{task}': {exc}") from exc

    fb_provider_name = (
        getattr(fallback_provider, "PROVIDER_NAME", None)
        or getattr(fallback_provider, "__name__", "fallback").rsplit(".", 1)[-1]
    )
    logger.info(
        "ai_router_call",
        task=task,
        provider=fb_provider_name,
        model=fallback_model,
        fallback_used=used_fallback,
        **ctx,
    )
    return {**result, "provider": fb_provider_name, "model": fallback_model}

