"""
GET  /api/v1/notifications        — recent events for this user, derived live
                                     from scan_history (no separate table to
                                     keep in sync, no mocked/hardcoded items).
POST /api/v1/notifications/read   — mark everything up to a given id as read.

"Read" state is a single Redis string per user (the id of the newest
notification they've seen), not a table — cheap and there's nothing to
migrate if the notification list logic changes later.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.db import get_db
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.core.security import CurrentUser, require_auth

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])
logger = get_logger()

_READ_KEY = "notifications:last_read:{user_id}"


def _finding_status(scan_doc: dict, finding_id: str) -> str:
    return ((scan_doc.get("fixes") or {}).get(finding_id) or {}).get("status") or "AWAITING_APPROVAL"


async def _build_notifications(user_id: str, limit: int) -> list[dict]:
    db = get_db()
    cursor = db.scan_history.find({"ownerId": user_id}, {"_id": 0}).sort("scannedAt", -1).limit(50)
    scans = [doc async for doc in cursor]

    items: list[dict] = []
    for scan in scans:
        items.append(
            {
                "id": f"scan-{scan.get('scanId')}",
                "type": "info",
                "title": "Scan completed",
                "message": f"{scan.get('repo')} — {scan.get('findingsCount', 0)} findings",
                "timestamp": scan.get("scannedAt"),
            }
        )
        for f in scan.get("findings") or []:
            if (f.get("severity") or "").upper() == "CRITICAL":
                items.append(
                    {
                        "id": f"crit-{scan.get('scanId')}-{f.get('id')}",
                        "type": "critical",
                        "title": "Critical vulnerability detected",
                        "message": f"{f.get('title')} — {scan.get('repo')}",
                        "timestamp": scan.get("scannedAt"),
                    }
                )
        for finding_id, fix in (scan.get("fixes") or {}).items():
            if fix.get("status") == "FIX_VERIFIED":
                items.append(
                    {
                        "id": f"fix-{scan.get('scanId')}-{finding_id}",
                        "type": "success",
                        "title": "AI fix verified",
                        "message": f"{scan.get('repo')} — fix passed all checks",
                        "timestamp": fix.get("verifiedAt") or scan.get("scannedAt"),
                    }
                )

    items.sort(key=lambda n: n.get("timestamp") or "", reverse=True)
    return items[:limit]


class MarkReadRequest(BaseModel):
    lastReadId: Optional[str] = None


@router.get("")
async def list_notifications(user: CurrentUser = Depends(require_auth)) -> dict[str, Any]:
    items = await _build_notifications(user.id, limit=30)
    redis = get_redis()
    try:
        last_read = await redis.get(_READ_KEY.format(user_id=user.id))
    except Exception:
        last_read = None

    if last_read:
        read_index = next((i for i, n in enumerate(items) if n["id"] == last_read), None)
        unread_count = read_index if read_index is not None else len(items)
    else:
        unread_count = len(items)

    return {"notifications": items, "unreadCount": unread_count}


@router.post("/read")
async def mark_read(payload: MarkReadRequest, user: CurrentUser = Depends(require_auth)) -> dict[str, Any]:
    if payload.lastReadId:
        redis = get_redis()
        try:
            await redis.set(_READ_KEY.format(user_id=user.id), payload.lastReadId, ex=60 * 60 * 24 * 30)
        except Exception as exc:  # noqa: BLE001
            logger.warning("notifications_mark_read_failed", error=str(exc))
    return {"ok": True}
