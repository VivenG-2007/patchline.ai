from redis import asyncio as aioredis

from app.config import get_settings

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    settings = get_settings()
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True, socket_timeout=3)
    return _redis


async def ping() -> bool:
    try:
        return await get_redis().ping()
    except Exception:
        return False
