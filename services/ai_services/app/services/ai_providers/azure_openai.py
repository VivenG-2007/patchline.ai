"""Azure OpenAI provider.

Supports two endpoint styles:
  1. Azure AI Foundry - Responses API  (/openai/v1/responses)
  2. Azure OpenAI Service - Chat Completions (/openai/deployments/{name}/chat/completions)

Tries Responses API first. If a body-level error is returned (e.g. "model
output error: model output must contain either output text or tool calls"),
falls back to Chat Completions transparently.
"""

import httpx

from app.config import get_settings
from fastapi import HTTPException

_TEXT_OUTPUT_TYPES = {"output_text", "reasoning_summary_text", "text"}


async def chat(messages: list[dict], model: str | None = None) -> dict:
    settings = get_settings()
    api_key = settings.azure_openai_api_key or settings.ai_api_key
    deployment = (
        model
        or settings.azure_openai_deployment_name
        or settings.azure_openai_deployment
        or settings.ai_model
    )
    if not settings.azure_openai_endpoint:
        raise HTTPException(status_code=500, detail="AZURE_OPENAI_ENDPOINT not configured")
    if not api_key:
        raise HTTPException(status_code=500, detail="AZURE_OPENAI_API_KEY not configured")
    if not deployment:
        raise HTTPException(status_code=500, detail="AZURE_OPENAI_DEPLOYMENT_NAME not configured")

    api_version = settings.azure_openai_api_version or "2024-12-01-preview"
    base = settings.azure_openai_endpoint.rstrip("/")
    for suffix in ("/openai/v1/responses", "/openai/v1", "/models/chat/completions", "/openai/deployments"):
        if base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    from app.core.logging import get_logger
    logger = get_logger()

    system_content = ""
    turns: list[dict] = []
    for msg in messages:
        if msg.get("role") == "system":
            system_content = msg.get("content", "")
        else:
            turns.append({"role": msg["role"], "content": msg.get("content", "")})

    # Attempt 1: Azure AI Foundry Responses API
    responses_url = f"{base}/openai/v1/responses"
    responses_body: dict = {"model": deployment, "input": turns}
    if system_content:
        responses_body["instructions"] = system_content

    logger.info("azure_openai_request", url=responses_url, deployment=deployment, endpoint_style="responses_api")

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(responses_url, headers=headers, json=responses_body)

    if resp.status_code < 400:
        data = resp.json()
        body_error = data.get("error")
        if body_error:
            err_msg = body_error.get("message", str(body_error)) if isinstance(body_error, dict) else str(body_error)
            logger.warning("azure_openai_responses_api_body_error", deployment=deployment, error=err_msg, fallback="chat_completions")
            # Fall through to chat completions
        else:
            content = _extract_responses_api_text(data)
            if content:
                return {"content": content, "usage": data.get("usage", {})}
            logger.warning("azure_openai_responses_api_empty_content", deployment=deployment, fallback="chat_completions", raw_output=str(data.get("output", ""))[:500])
    else:
        logger.warning("azure_openai_responses_api_http_error", deployment=deployment, status=resp.status_code, fallback="chat_completions")

    # Attempt 2: Classic Chat Completions endpoint
    completions_url = f"{base}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    logger.info("azure_openai_request", url=completions_url, deployment=deployment, endpoint_style="chat_completions")

    async with httpx.AsyncClient(timeout=120) as client:
        resp2 = await client.post(completions_url, headers=headers, json={"model": deployment, "messages": messages})

    if resp2.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Azure OpenAI error {resp2.status_code}: {resp2.text}")

    data2 = resp2.json()
    choice = (data2.get("choices") or [{}])[0]
    content2 = (choice.get("message") or {}).get("content") or ""
    if not content2:
        raise HTTPException(status_code=502, detail="Azure OpenAI returned empty content from both Responses API and Chat Completions. Raw: " + str(data2)[:400])

    return {"content": content2, "usage": data2.get("usage", {})}


def _extract_responses_api_text(data: dict) -> str:
    """Extract text from a Responses API response body.
    Handles output_text, reasoning_summary_text, and text part types.
    """
    try:
        for item in data.get("output") or []:
            if item.get("type") != "message":
                continue
            for part in item.get("content") or []:
                if part.get("type") in _TEXT_OUTPUT_TYPES:
                    text = part.get("text", "")
                    if text:
                        return text
    except Exception:
        pass
    return ""
