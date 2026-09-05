"""
Elasticsearch integration for full-text search over scan findings.

Design goals:
  - Optional at runtime. If ES_URL (or ES_CLOUD_ID) isn't set, every function
    here becomes a safe no-op / returns an empty result instead of raising —
    search degrades to "unavailable", it never takes the scanner down.
  - Indexing happens best-effort, right after a scan is persisted to Mongo.
    Mongo (scan_history) stays the source of truth; ES is a derived, rebuildable
    search index. If ES indexing fails, the scan result to the caller is
    unaffected — we only log a warning.
  - One document per finding (not per scan), so search can filter/sort at the
    finding level (severity, repo, status) the way the UI's search bar needs.

Index name: `patchline_findings`
Document id: `{scanId}:{findingId}` (deterministic — re-indexing a scan
overwrites the same docs instead of duplicating them).
"""

from __future__ import annotations

from typing import Any, Optional

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger()

FINDINGS_INDEX = "patchline_findings_v2"

_client: Optional[AsyncElasticsearch] = None
_checked_unavailable = False



def _build_client() -> Optional[AsyncElasticsearch]:
    settings = get_settings()
    endpoint = settings.es_endpoint or settings.es_url
    if endpoint:
        kwargs: dict[str, Any] = {"hosts": [endpoint]}
        if settings.es_api_key:
            kwargs["api_key"] = settings.es_api_key
        elif settings.es_username and settings.es_password:
            kwargs["basic_auth"] = (settings.es_username, settings.es_password)
        return AsyncElasticsearch(**kwargs)
    if settings.es_cloud_id and settings.es_api_key:
        return AsyncElasticsearch(cloud_id=settings.es_cloud_id, api_key=settings.es_api_key)
    return None


def get_client() -> Optional[AsyncElasticsearch]:
    global _client
    if _client is None:
        _client = _build_client()
    return _client


def is_configured() -> bool:
    return get_client() is not None


async def ping() -> bool:
    client = get_client()
    if client is None:
        return False
    try:
        return bool(await client.ping())
    except Exception as exc:  # noqa: BLE001 — any transport error just means "not reachable"
        logger.warning("elasticsearch_ping_failed", error=str(exc))
        return False


FINDINGS_MAPPINGS = {
    "properties": {
        "ownerId": {"type": "keyword"},
        "scanId": {"type": "keyword"},
        "findingId": {"type": "keyword"},
        "repo": {"type": "keyword"},
        "branch": {"type": "keyword"},
        "title": {"type": "text"},
        "description": {"type": "text"},
        "file": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "line": {"type": "integer"},
        "severity": {"type": "keyword"},
        "category": {"type": "keyword"},
        "source": {"type": "keyword"},
        "status": {"type": "keyword"},
        "scannedAt": {"type": "date"},
        "riskScore": {"type": "integer"},
        "riskLevel": {"type": "keyword"},
        "eal": {"type": "integer"},
        "riskReductionPct": {"type": "float"},
        "fixModel": {"type": "keyword"},
        "fixProvider": {"type": "keyword"},
        "codexModel": {"type": "keyword"},
        "codexProvider": {"type": "keyword"},
    }
}


async def ensure_index() -> None:

    client = get_client()
    if client is None:
        return
    try:
        exists = await client.indices.exists(index=FINDINGS_INDEX)
        if not exists:
            await client.indices.create(
                index=FINDINGS_INDEX,
                mappings=FINDINGS_MAPPINGS,
            )
            logger.info("elasticsearch_index_created", index=FINDINGS_INDEX)
        else:
            # Safely put mappings on newly added fields
            try:
                await client.indices.put_mapping(
                    index=FINDINGS_INDEX,
                    properties=FINDINGS_MAPPINGS["properties"],
                )
                logger.info("elasticsearch_mapping_updated", index=FINDINGS_INDEX)
            except Exception as map_exc:
                logger.warning("elasticsearch_put_mapping_skipped", error=str(map_exc))
    except Exception as exc:  # noqa: BLE001
        logger.warning("elasticsearch_index_setup_skipped", error=str(exc))




async def index_scan_findings(scan_doc: dict) -> None:
    """Index (or re-index) every finding on a scan as one ES doc each.
    Called right after `_save_scan_metadata` in routers/scanner.py — best
    effort, failures are logged and swallowed so a search-index hiccup never
    fails the scan itself."""
    client = get_client()
    if client is None:
        return
    findings = scan_doc.get("findings") or []
    if not findings:
        return
    fixes = scan_doc.get("fixes") or {}

    def _doc(f: dict) -> dict:
        finding_id = f.get("id")
        fix_record = fixes.get(finding_id) or {}
        status = fix_record.get("status") or "AWAITING_APPROVAL"
        # Post-fix risk (fix_record["riskAfter"]) overrides the pre-fix
        # snapshot computed at scan time (f["risk"]) once a fix has been
        # verified — same "fixes map overrides the finding's own record"
        # pattern `status` above already uses. Falls back to pre-fix values
        # (or nothing) when there's no risk data at all yet.
        risk_before = f.get("risk") or {}
        risk_after = fix_record.get("riskAfter")
        effective_risk = risk_after or risk_before
        codex_review = fix_record.get("codexReview") or {}
        return {
            "_index": FINDINGS_INDEX,
            "_id": f"{scan_doc.get('scanId')}:{finding_id}",
            "_source": {
                "ownerId": scan_doc.get("ownerId"),
                "scanId": scan_doc.get("scanId"),
                "findingId": finding_id,
                "repo": scan_doc.get("repo"),
                "branch": scan_doc.get("branch"),
                "title": f.get("title"),
                "description": f.get("description"),
                "file": f.get("file"),
                "line": f.get("line"),
                "severity": (f.get("severity") or "").upper(),
                "category": f.get("category"),
                "source": f.get("source"),
                "status": status,
                "scannedAt": scan_doc.get("scannedAt"),
                "riskScore": effective_risk.get("riskScore"),
                "riskLevel": effective_risk.get("riskLevel"),
                "eal": (effective_risk.get("eal") or {}).get("annualLoss"),
                "riskReductionPct": fix_record.get("riskReductionPct"),
                "fixModel": fix_record.get("model"),
                "fixProvider": fix_record.get("provider"),
                "codexModel": codex_review.get("model"),
                "codexProvider": codex_review.get("provider"),
            },
        }

    try:
        await ensure_index()
        actions = [_doc(f) for f in findings]
        await async_bulk(client, actions, raise_on_error=False)
        logger.info("elasticsearch_indexed_findings", scan_id=scan_doc.get("scanId"), count=len(actions))
    except Exception as exc:  # noqa: BLE001
        logger.warning("elasticsearch_indexing_failed", scan_id=scan_doc.get("scanId"), error=str(exc))


async def search_findings(
    owner_id: str,
    query: str = "",
    severity: Optional[str] = None,
    repo: Optional[str] = None,
    status: Optional[str] = None,
    size: int = 20,
) -> Optional[list[dict]]:
    """Returns None (not []) when ES isn't configured/reachable, so callers
    can distinguish "no matches" from "search unavailable, fall back"."""
    client = get_client()
    if client is None:
        return None

    must: list[dict] = [{"term": {"ownerId": owner_id}}]
    if query.strip():
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["title^3", "description", "file^2", "repo"],
                    "fuzziness": "AUTO",
                }
            }
        )
    if severity:
        must.append({"term": {"severity": severity.upper()}})
    if repo:
        must.append({"term": {"repo": repo}})
    if status:
        must.append({"term": {"status": status.upper()}})

    try:
        result = await client.search(
            index=FINDINGS_INDEX,
            query={"bool": {"must": must}},
            sort=[{"scannedAt": {"order": "desc"}}],
            size=size,
        )
        return [hit["_source"] | {"_score": hit.get("_score")} for hit in result["hits"]["hits"]]
    except Exception as exc:  # noqa: BLE001
        logger.warning("elasticsearch_search_failed", error=str(exc))
        return None


async def aggregate_dashboard_metrics(owner_id: str) -> Optional[dict]:
    """Execute real-time Elasticsearch aggregations for dashboard analytics.
    Returns None if ES is not configured or fails, allowing seamless MongoDB fallback."""
    client = get_client()
    if client is None:
        return None

    try:
        query = {"bool": {"must": [{"term": {"ownerId": owner_id}}]}}
        # Note: fixProvider and fixModel might be mapped as text or keyword depending on index creation time.
        # We aggregate primarily on severity, category, status, and repo.
        aggs = {
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_category": {"terms": {"field": "category", "size": 15}},
            "by_status": {"terms": {"field": "status", "size": 10}},
            "by_repo": {
                "terms": {"field": "repo", "size": 20},
                "aggs": {
                    "severity": {"terms": {"field": "severity", "size": 10}},
                    "latest_scan": {"max": {"field": "scannedAt"}},
                },
            },
            "avg_risk": {"avg": {"field": "riskScore"}},
            "max_risk": {"max": {"field": "riskScore"}},
        }


        result = await client.search(
            index=FINDINGS_INDEX,
            query=query,
            aggs=aggs,
            size=0,
        )
        aggregations = result.get("aggregations", {})
        total_hits = result.get("hits", {}).get("total", {}).get("value", 0)

        return {
            "totalFindings": total_hits,
            "bySeverity": {
                b["key"]: b["doc_count"] for b in aggregations.get("by_severity", {}).get("buckets", [])
            },
            "byCategory": {
                b["key"]: b["doc_count"] for b in aggregations.get("by_category", {}).get("buckets", [])
            },
            "byStatus": {
                b["key"]: b["doc_count"] for b in aggregations.get("by_status", {}).get("buckets", [])
            },
            "byRepo": aggregations.get("by_repo", {}).get("buckets", []),
            "avgRisk": aggregations.get("avg_risk", {}).get("value") or 0.0,
            "maxRisk": aggregations.get("max_risk", {}).get("value") or 0.0,
            "fixProviders": {
                b["key"]: b["doc_count"] for b in aggregations.get("fix_providers", {}).get("buckets", [])
            },
            "fixModels": {
                b["key"]: b["doc_count"] for b in aggregations.get("fix_models", {}).get("buckets", [])
            },
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("elasticsearch_dashboard_agg_failed", error=str(exc))
        return None


async def close() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None

