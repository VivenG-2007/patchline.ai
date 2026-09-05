import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bson import ObjectId
from fastapi import HTTPException, UploadFile

from app.config import get_settings
from app.core.blob_storage import get_container_client
from app.core.db import get_db

_SAFE_CHARS = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_filename(name: str) -> str:
    return _SAFE_CHARS.sub("_", name)[-150:]


# Streams the upload straight to Blob Storage in chunks rather than buffering
# the whole file in memory — important once someone uploads a large video.
async def upload_file(owner_id: str, file: UploadFile) -> dict:
    settings = get_settings()
    client = get_container_client()
    if client is None:
        raise HTTPException(status_code=503, detail="Azure Blob Storage not configured")

    safe_name = _sanitize_filename(file.filename or "upload")
    blob_name = f"{owner_id}/{uuid.uuid4()}{Path(safe_name).suffix}"
    blob_client = client.get_blob_client(blob_name)

    size = 0
    max_bytes = settings.max_upload_bytes

    async def stream():
        nonlocal size
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(status_code=413, detail=f"File exceeds max upload size ({max_bytes} bytes)")
            yield chunk

    await blob_client.upload_blob(stream(), overwrite=True, content_type=file.content_type)

    db = get_db()
    now = datetime.now(timezone.utc)
    doc = {
        "owner_id": owner_id,
        "blob_name": blob_name,
        "original_name": safe_name,
        "mime_type": file.content_type or "application/octet-stream",
        "size_bytes": size,
        "container": settings.azure_storage_container,
        "metadata": {},
        "created_at": now,
    }
    result = await db.file_assets.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def get_download_stream(owner_id: str, file_id: str):
    db = get_db()
    doc = await db.file_assets.find_one({"_id": ObjectId(file_id), "owner_id": owner_id})
    if not doc:
        return None
    client = get_container_client()
    if client is None:
        raise HTTPException(status_code=503, detail="Azure Blob Storage not configured")
    blob_client = client.get_blob_client(doc["blob_name"])
    downloader = await blob_client.download_blob()
    return doc, downloader


async def delete_file(owner_id: str, file_id: str) -> bool:
    db = get_db()
    doc = await db.file_assets.find_one({"_id": ObjectId(file_id), "owner_id": owner_id})
    if not doc:
        return False
    client = get_container_client()
    if client is not None:
        await client.get_blob_client(doc["blob_name"]).delete_blob(delete_snapshots="include")
    await db.file_assets.delete_one({"_id": doc["_id"]})
    return True


async def list_files(owner_id: str, limit: int = 100) -> list[dict]:
    db = get_db()
    cursor = db.file_assets.find({"owner_id": owner_id}).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]
