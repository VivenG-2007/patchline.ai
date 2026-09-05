from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import get_settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    settings = get_settings()
    if _client is None:
        if not settings.mongodb_uri:
            raise RuntimeError("MONGODB_URI is not configured")
        _client = AsyncIOMotorClient(settings.mongodb_uri, maxPoolSize=20, serverSelectionTimeoutMS=10000)
    return _client


def get_db() -> AsyncIOMotorDatabase:
    global _db
    settings = get_settings()
    if _db is None:
        _db = get_client()[settings.mongodb_database]
    return _db


async def ping() -> bool:
    try:
        await get_client().admin.command("ping")
        return True
    except Exception:
        return False


async def ensure_indexes() -> None:
    db = get_db()
    await db.file_assets.create_index("owner_id")
    await db.file_assets.create_index("blob_name", unique=True)
    await db.conversations.create_index("owner_id")
    # Scanner history indexes
    await db.scan_history.create_index("scanId", unique=True)
    await db.scan_history.create_index("repo")
    # Every user-scoped scan_history read (dashboard stats, scan history list —
    # see routers/dashboard.py and routers/scanner.py) filters by ownerId and
    # sorts by scannedAt. Without an index on ownerId, both were doing a full
    # collection scan across every user's scans on every request. This
    # compound index serves the filter and the sort together; the older
    # scannedAt-only index below is kept for any query that sorts without an
    # ownerId filter.
    await db.scan_history.create_index([("ownerId", 1), ("scannedAt", -1)])
    await db.scan_history.create_index([("scannedAt", -1)])
    # Note: RAG memory (app/core/memory_store.py) no longer stores anything
    # in MongoDB — finding embeddings + metadata live in a Chroma Cloud
    # collection (app/core/chroma_client.py), so there's no finding_memory
    # index to maintain here.

