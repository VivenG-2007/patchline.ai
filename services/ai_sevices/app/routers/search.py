"""
GET /api/v1/search — powers the command-K search bar in the frontend.

Backed by Elasticsearch when configured (app/core/es_client.py); falls back
to a Mongo regex scan over this user's own scan_history when ES is
unreachable or not configured, so search keeps working (just without
fuzzy/relevance ranking) even without the ES dependency running.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from app.core import es_client
from app.core.db import get_db
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_auth

router = APIRouter(prefix="/api/v1/search", tags=["search"])
logger = get_logger()


async def _mongo_fallback_search(owner_id: str, q: str, severity: Optional[str], repo: Optional[str], size: int) -> list[dict]:
    db = get_db()
    mongo_filter: dict[str, Any] = {"ownerId": owner_id}
    if repo:
        mongo_filter["repo"] = repo
    cursor = db.scan_history.find(mongo_filter, {"_id": 0}).sort("scannedAt", -1).limit(200)
    pattern = re.compile(re.escape(q), re.IGNORECASE) if q else None

    results: list[dict] = []
    async for scan in cursor:
        for f in scan.get("findings") or []:
            if severity and (f.get("severity") or "").upper() != severity.upper():
                continue
            haystack = f"{f.get('title', '')} {f.get('description', '')} {f.get('file', '')}"
            if pattern and not pattern.search(haystack):
                continue
            status = ((scan.get("fixes") or {}).get(f.get("id")) or {}).get("status") or "AWAITING_APPROVAL"
            results.append(
                {
                    "scanId": scan.get("scanId"),
                    "findingId": f.get("id"),
                    "repo": scan.get("repo"),
                    "branch": scan.get("branch"),
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "severity": (f.get("severity") or "").upper(),
                    "status": status,
                    "scannedAt": scan.get("scannedAt"),
                }
            )
            if len(results) >= size:
                return results
    return results


@router.get("")
async def search(
    q: str = Query("", description="Free-text query over finding title/description/file"),
    severity: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(require_auth),
) -> dict[str, Any]:
    es_results = await es_client.search_findings(
        owner_id=user.id, query=q, severity=severity, repo=repo, status=status, size=limit
    )
    if es_results is not None:
        return {"results": es_results, "source": "elasticsearch", "total": len(es_results)}

    fallback = await _mongo_fallback_search(user.id, q, severity, repo, limit)
    return {"results": fallback, "source": "mongo_fallback", "total": len(fallback)}
