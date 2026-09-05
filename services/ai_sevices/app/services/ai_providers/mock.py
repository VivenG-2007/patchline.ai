# Zero-dependency provider used by default so the template runs out of the
# box with no API key. Swap AI_PROVIDER in .env once you have real creds.
async def chat(messages: list[dict], model: str | None = None) -> dict:
    last_user = next((m for m in reversed(messages) if m["role"] == "user"), None)
    preview = (last_user["content"][:200] if last_user else "")
    return {
        "content": f'[mock provider] I received: "{preview}". Set AI_PROVIDER + AI_API_KEY in .env to use a real model.',
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }
