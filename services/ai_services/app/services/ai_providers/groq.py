import httpx

from app.config import get_settings
from fastapi import HTTPException


# Groq exposes an OpenAI-compatible chat completions endpoint.
async def chat(messages: list[dict], model: str | None = None) -> dict:
    settings = get_settings()
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"authorization": f"Bearer {settings.ai_api_key}"},
            json={"model": model or settings.ai_model, "messages": messages},
        )
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Groq API error: {response.text}")
    data = response.json()
    choice = (data.get("choices") or [{}])[0]
    return {"content": choice.get("message", {}).get("content", ""), "usage": data.get("usage", {})}
