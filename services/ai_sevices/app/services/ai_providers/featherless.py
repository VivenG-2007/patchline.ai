"""Featherless AI provider. OpenAI-compatible /v1/chat/completions surface,
so this mirrors app/services/ai_providers/openai.py almost exactly — the
only differences are the base URL and which env vars back the API key.

This module is a plain provider (same `chat(messages, model)` shape every
other provider in this package exports) and knows nothing about fallback —
routing/fallback logic lives in app/services/model_router.py, which is what
actually decides whether to call this module or fall back to another
provider. Keeping that decision out of here means this file stays a pure,
easily-testable HTTP client.
"""

import httpx
from fastapi import HTTPException

from app.config import get_settings


async def chat(messages: list[dict], model: str | None = None) -> dict:
    settings = get_settings()
    if not settings.featherless_api_key:
        raise HTTPException(status_code=500, detail="FEATHERLESS_API_KEY not configured")
    if not model:
        raise HTTPException(status_code=500, detail="No model specified for Featherless request")

    base = settings.featherless_base_url.rstrip("/")
    url = f"{base}/chat/completions"

    async with httpx.AsyncClient(timeout=settings.featherless_timeout_seconds) as client:
        response = await client.post(
            url,
            headers={"authorization": f"Bearer {settings.featherless_api_key}"},
            json={"model": model, "messages": messages},
        )
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Featherless API error {response.status_code}: {response.text}")

    data = response.json()
    choice = (data.get("choices") or [{}])[0]
    return {"content": choice.get("message", {}).get("content", ""), "usage": data.get("usage", {})}
