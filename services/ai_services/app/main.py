import asyncio
import uuid
from contextlib import asynccontextmanager

from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.core import es_client, github_http, redis_client
from app.core.blob_storage import ensure_container
from app.core.db import ensure_indexes
from app.core.logging import configure_logging, get_logger
from app.core.rate_limit import limiter
from app.errors import http_exception_handler, unhandled_exception_handler, validation_exception_handler
from app.routers import ai, dashboard, files, health, notifications, scanner, search
from app.services.reconciliation import run_reconciliation_loop

settings = get_settings()
configure_logging()
logger = get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Redis now backs the rate limiter on every /api/ai/* and /api/files/*
    # route (app/core/rate_limit.py), so — unlike the Mongo/Blob checks
    # below, which degrade gracefully — an unreachable Redis here means
    # every rate-limited request would start throwing at request time
    # instead of failing loudly at boot. Fail fast instead, same as
    # main-service does for the same reason (its Redis backs BullMQ + its
    # own rate limiter).
    if not await redis_client.ping():
        logger.error("redis_unreachable_at_startup — ai-storage-service cannot run without it")
        raise RuntimeError("Redis unreachable at startup (REDIS_URL)")
    logger.info("redis_reachable")

    try:
        await ensure_indexes()
        logger.info("mongodb_indexes_ready")
    except Exception as exc:
        logger.warning("mongodb_index_setup_skipped", error=str(exc))
    try:
        await ensure_container()
        logger.info("azure_blob_container_ready", container=settings.azure_storage_container)
    except Exception as exc:
        logger.warning("azure_blob_setup_skipped", error=str(exc))

    if es_client.is_configured():
        try:
            await es_client.ensure_index()
            logger.info("elasticsearch_ready")
        except Exception as exc:
            logger.warning("elasticsearch_setup_skipped", error=str(exc))
    else:
        logger.info("elasticsearch_not_configured — search will use the Mongo fallback")

    # Chroma Cloud backs the RAG "Remember" step — verify it's reachable at
    # startup so a misconfigured API key surfaces immediately (as a warning,
    # not a crash — RAG is best-effort and index_finding never blocks a scan).
    from app.core import memory_store as _mem
    if _mem.is_enabled():
        try:
            from app.core import chroma_client as _cc
            await _cc.get_collection()
            logger.info("chroma_ready", collection=settings.chroma_collection)
        except Exception as exc:
            logger.warning(
                "chroma_unreachable_at_startup — RAG memory will be silently "
                "skipped until resolved. Check CHROMA_API_KEY / CHROMA_HOST.",
                error=str(exc),
            )
    else:
        logger.info("rag_memory_disabled — set RAG_MEMORY_ENABLED=true to enable")

    # Periodic sweep for findings stuck in FIX_PROCESSING after a hard crash
    # (see app/services/reconciliation.py). Best-effort: if Mongo isn't
    # configured the loop's own db calls will just log and retry next
    # interval, same tolerance as the rest of this service's Mongo usage.
    reconciliation_task = asyncio.create_task(run_reconciliation_loop())

    logger.info("ai_storage_service_started", port=settings.port, provider=settings.ai_provider)
    yield
    reconciliation_task.cancel()
    try:
        await reconciliation_task
    except asyncio.CancelledError:
        pass
    await es_client.close()
    await github_http.close()
    logger.info("ai_storage_service_shutdown")


app = FastAPI(
    title="ai-storage-service",
    description="Patchline AI scanning + storage service — pluggable AI provider, MongoDB, Redis, Azure Blob.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

app.add_middleware(CorrelationIdMiddleware, header_name="x-request-id", generator=lambda: str(uuid.uuid4()))
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_request_id_state(request: Request, call_next):
    # asgi_correlation_id already sets the x-request-id response header;
    # mirror it onto request.state so our error handlers can read it uniformly.
    request.state.request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    response = await call_next(request)
    return response


app.include_router(health.router)
app.include_router(ai.router)
app.include_router(files.router)
app.include_router(scanner.router)
app.include_router(dashboard.router)
app.include_router(search.router)
app.include_router(notifications.router)

