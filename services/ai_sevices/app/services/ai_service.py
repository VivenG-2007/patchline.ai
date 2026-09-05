import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId

from app.config import get_settings
from app.core.db import get_db
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.services.ai_providers import get_provider

logger = get_logger()


def _cache_key(messages: list[dict], model: str) -> str:
    digest = hashlib.sha256(json.dumps({"messages": messages, "model": model}, sort_keys=True).encode()).hexdigest()
    return f"ai:cache:{digest}"


# Generic entry point behind /api/ai/chat, /api/ai/generate, /api/ai/analyze.
# All three ultimately call the same pluggable provider — kept as separate
# endpoints so each can diverge later (different max_tokens, structured
# output parsing for `analyze`, etc.) without branching provider logic.
async def run_chat(
    owner_id: Optional[str],
    messages: list[dict],
    model: Optional[str] = None,
    conversation_id: Optional[str] = None,
    use_cache: bool = True,
) -> dict:
    settings = get_settings()
    provider = get_provider()
    resolved_model = model or settings.ai_model
    cache_key = _cache_key(messages, resolved_model)

    if use_cache:
        try:
            cached = await get_redis().get(cache_key)
            if cached:
                result = json.loads(cached)
                result["cached"] = True
                return result
        except Exception as exc:
            logger.warning("ai_cache_read_failed", error=str(exc))

    result = await provider.chat(messages, resolved_model)

    if use_cache:
        try:
            await get_redis().set(cache_key, json.dumps(result), ex=300)
        except Exception as exc:
            logger.warning("ai_cache_write_failed", error=str(exc))

    if owner_id:
        try:
            db = get_db()
            now = datetime.now(timezone.utc)
            assistant_message = {"role": "assistant", "content": result["content"]}
            if conversation_id:
                await db.conversations.update_one(
                    {"_id": ObjectId(conversation_id), "owner_id": owner_id},
                    {"$push": {"messages": {"$each": [messages[-1], assistant_message]}}, "$set": {"updated_at": now}},
                )
            else:
                await db.conversations.insert_one(
                    {
                        "owner_id": owner_id,
                        "provider": settings.ai_provider,
                        "model": resolved_model,
                        "messages": messages + [assistant_message],
                        "created_at": now,
                        "updated_at": now,
                    }
                )
        except Exception as exc:
            logger.warning("conversation_persist_failed", error=str(exc))

    result["cached"] = False
    return result
