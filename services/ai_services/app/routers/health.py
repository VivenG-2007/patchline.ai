import os
import time

from fastapi import APIRouter

from app.config import get_settings
from app.core import db as db_module
from app.core import redis_client

router = APIRouter()
_start_time = time.time()


@router.get("/")
@router.head("/")
@router.get("/health")
@router.head("/health")
async def health():
    settings = get_settings()
    return {"status": "ok", "service": settings.service_name}


@router.get("/ready")
async def ready():
    settings = get_settings()
    mongo_ok = await db_module.ping()
    # Redis now backs the rate limiter (app/core/rate_limit.py) on every
    # /api/ai/* and /api/files/* route, not just cached/queued state — so
    # it belongs in readiness the same way mongo does, not just "nice to
    # report on."
    redis_ok = await redis_client.ping()
    ready = mongo_ok and redis_ok
    return {
        "ready": ready,
        "service": settings.service_name,
        "dependencies": {"mongodb": mongo_ok, "redis": redis_ok},
    }


@router.get("/metrics")
async def metrics():
    settings = get_settings()
    # RSS via /proc — avoids adding psutil just for one number.
    rss_mb = None
    try:
        with open(f"/proc/{os.getpid()}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_mb = round(int(line.split()[1]) / 1024, 1)
                    break
    except FileNotFoundError:
        pass
    return {
        "service": settings.service_name,
        "uptimeSeconds": round(time.time() - _start_time, 1),
        "aiProvider": settings.ai_provider,
        "memory": {"rssMB": rss_mb},
    }
