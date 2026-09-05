from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.core.rate_limit import limiter
from app.core.security import CurrentUser, require_auth
from app.services import storage_service

router = APIRouter(prefix="/api/files", tags=["files"])

_ALLOWED_PREFIXES = ("image/", "video/", "audio/", "application/pdf", "text/", "application/json")


def _serialize(doc: dict) -> dict:
    return {
        "id": str(doc["_id"]),
        "ownerId": doc["owner_id"],
        "blobName": doc["blob_name"],
        "originalName": doc["original_name"],
        "mimeType": doc["mime_type"],
        "sizeBytes": doc["size_bytes"],
        "container": doc["container"],
        "metadata": doc.get("metadata", {}),
        "createdAt": doc["created_at"].isoformat(),
    }


@router.get("")
async def list_files(user: CurrentUser = Depends(require_auth)):
    docs = await storage_service.list_files(user.id)
    return {"files": [_serialize(d) for d in docs]}


@router.post("/upload", status_code=201)
@limiter.limit("30/minute")
async def upload(request: Request, file: UploadFile, user: CurrentUser = Depends(require_auth)):
    if not file:
        raise HTTPException(status_code=400, detail='No file provided (field name: "file")')
    if file.content_type and not file.content_type.startswith(_ALLOWED_PREFIXES):
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {file.content_type}")
    doc = await storage_service.upload_file(user.id, file)
    return {"file": _serialize(doc)}


@router.get("/{file_id}")
async def download(file_id: str, user: CurrentUser = Depends(require_auth)):
    result = await storage_service.get_download_stream(user.id, file_id)
    if result is None:
        raise HTTPException(status_code=404, detail="File not found")
    doc, downloader = result

    async def iterator():
        async for chunk in downloader.chunks():
            yield chunk

    return StreamingResponse(
        iterator(),
        media_type=doc["mime_type"],
        headers={"content-disposition": f'attachment; filename="{doc["original_name"]}"'},
    )


@router.delete("/{file_id}", status_code=204)
async def remove(file_id: str, user: CurrentUser = Depends(require_auth)):
    ok = await storage_service.delete_file(user.id, file_id)
    if not ok:
        raise HTTPException(status_code=404, detail="File not found")
    return None
