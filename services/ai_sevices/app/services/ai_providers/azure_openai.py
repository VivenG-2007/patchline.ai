import httpx

from app.config import get_settings
from fastapi import HTTPException


async def chat(messages: list[dict], model: str | None = None) -> dict:
    settings = get_settings()

    # Resolve API key (AZURE_OPENAI_API_KEY preferred, falls back to AI_API_KEY)
    api_key = settings.azure_openai_api_key or settings.ai_api_key

    # Resolve deployment/model name
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

    # NOTE: computed but not currently passed into the request below (no
    # `api-version` query param is added anywhere in this function) — flagging
    # rather than silently deleting or guessing the fix, since this may be a
    # real bug (Azure OpenAI's REST API normally requires api-version) outside
    # the scope of the CI/lint pass that surfaced it. Suppressing the lint
    # warning here rather than papering over it.
    api_version = settings.azure_openai_api_version or "2024-12-01-preview"  # noqa: F841

    # ── Build the base URL ──────────────────────────────────────────────────
    # Strip any trailing path from whatever the user pasted into AZURE_OPENAI_ENDPOINT
    # so we can compose the final path cleanly ourselves.
    base = settings.azure_openai_endpoint.rstrip("/")
    for suffix in (
        "/openai/v1/responses",
        "/openai/v1",
        "/models/chat/completions",
        "/openai/deployments",
    ):
        if base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break

    # Azure AI Foundry uses the Responses API:
    # POST {base}/openai/v1/responses
    # Body: {"model": "<deployment>", "input": [...], "instructions": "..."}
    url = f"{base}/openai/v1/responses"

    # ── Convert messages → Responses API format ────────────────────────────
    # The Responses API takes:
    #   instructions – the system prompt (separate top-level field)
    #   input        – array of user/assistant turns, OR a plain string
    system_content = ""
    turns: list[dict] = []
    for msg in messages:
        if msg.get("role") == "system":
            system_content = msg.get("content", "")
        else:
            turns.append({"role": msg["role"], "content": msg.get("content", "")})

    body: dict = {"model": deployment, "input": turns}
    if system_content:
        body["instructions"] = system_content

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    from app.core.logging import get_logger
    get_logger().info(
        "azure_openai_request",
        url=url,
        deployment=deployment,
    )

    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(url, headers=headers, json=body)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Azure OpenAI error {response.status_code}: {response.text}",
        )

    data = response.json()

    # ── Parse Responses API output ─────────────────────────────────────────
    # Response shape:
    # { "output": [{ "type": "message", "content": [{"type": "output_text", "text": "..."}] }] }
    content = ""
    try:
        output_items = data.get("output") or []
        for item in output_items:
            if item.get("type") == "message":
                for part in item.get("content") or []:
                    if part.get("type") == "output_text":
                        content = part.get("text", "")
                        break
                if content:
                    break
    except Exception:
        pass

    return {
        "content": content,
        "usage": data.get("usage", {}),
    }
