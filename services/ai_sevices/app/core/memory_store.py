"""
Vector memory for the scan -> fix pipeline's "Remember" step.

Context: app/core/es_client.py already gives this service full-text/keyword
search over past findings (powers the frontend's command-K search bar). What
it does NOT give the pipeline is semantic recall at fix-generation time —
"has something like this been fixed before, and how" — which is what an
agent-hub framing means by "Memory Management: vector DB retrieval". This
module adds that.

  - Storage: a Chroma Cloud collection (app/core/chroma_client.py), one point
    per (scanId, findingId), holding the embedding vector plus the finding's
    title/description/category/severity/file and — once a fix is generated
    and verified — the fix outcome, all as point metadata. No separate
    MongoDB collection for this: Chroma is the source of truth for both the
    vector and the metadata it's retrieved with.
  - Similarity search: two-pass Chroma HNSW query:
      Pass 1 — owner-scoped (ownerId + hasFix=True): best signal, same team.
      Pass 2 — community fallback (hasFix=True only): fires when pass 1
        returns 0 above-threshold results. Ensures the pipeline provides
        value from the very first fix a new user generates.
  - Minimum similarity threshold (MIN_SIMILARITY_THRESHOLD=0.35 cosine):
    Chroma always returns n_results candidates regardless of distance.
    Without this gate a 10% match would be injected as "prior art" and
    actively mislead the fix model. Items below threshold are discarded
    silently before the prompt is built.
  - Ranking is NOT "nearest vector wins" (see PatchLine architecture rule
    "Do not blindly select the nearest vector" / "RAG must rank the
    strongest three viable remediation strategies"). Chroma's cosine
    distance only tells us the candidate is *about* a similar thing; it
    says nothing about whether the same fix even applies (different
    vulnerability class, different language) or whether the fix actually
    worked last time. `_composite_score()` re-ranks the raw similarity hits
    using:
      base       = cosine similarity
      + category/vulnerability-type match  (same root cause family)
      + language match (derived from file extension)
      + severity match
      + verified-fix bonus                 (proven strategy)
      − unverified/failed-attempt penalty  (known anti-pattern, still
        surfaced so the fix model is told what NOT to repeat, but it can't
        crowd a proven fix out of the top_k slots)
    Each returned item carries `matchedFactors` so callers/logs can see
    *why* a candidate ranked where it did (auditability).
  - Degrades like es_client.py: disabled via RAG_MEMORY_ENABLED, or any
    embedding/Chroma failure, only logs a warning and returns [] — it can
    never fail a scan or a fix.
"""

from __future__ import annotations

import asyncio
import datetime
import re
from typing import Any, Optional

from app.config import get_settings
from app.core import chroma_client
from app.core.logging import get_logger
from app.services import embeddings

logger = get_logger()

# NOTE: the values below are the documented defaults / fallback reference.
# The live values are read from Settings on every call (rag_min_similarity_
# threshold, rag_query_candidates) so ops can retune without a redeploy —
# see app/config.py. Chroma always returns n_results candidates regardless
# of distance — without the threshold gate a 10% similarity match would be
# injected as "prior art". Check the memory_retrieve_* log lines to tune.
MIN_SIMILARITY_THRESHOLD = 0.35
_QUERY_CANDIDATES = 12

# Weights for the multi-factor re-ranker. Similarity remains the dominant
# signal (it's the only thing that scales continuously); the rest are
# small, capped bonuses/penalties that break ties and stop a same-category
# proven fix from losing to a barely-more-similar failed attempt.
_WEIGHT_CATEGORY_MATCH = 0.12
_WEIGHT_LANGUAGE_MATCH = 0.05
_WEIGHT_SEVERITY_MATCH = 0.03
_WEIGHT_VERIFIED_BONUS = 0.10
_WEIGHT_FAILED_PENALTY = 0.18
# Bonus derived from the category's aggregate track record across the WHOLE
# candidate pool returned for this query (not just the one candidate being
# scored) — this is the "historical success" ranking factor called out
# separately from "verification history" in the RAG ranking spec. A
# candidate in a category where fixes have historically stuck scores a
# little higher even if this particular candidate's own similarity is
# middling.
_WEIGHT_HISTORICAL_SUCCESS = 0.06

# Metadata fields that get written back into a FUTURE fix-generation prompt
# verbatim (see scanner.py's "SIMILAR PAST FIXES" block). AI-sourced
# findings' title/category/etc. are ultimately derived from repository
# content, which app/routers/scanner.py's own prompt-injection rules treat
# as untrusted ("repo code != trusted instruction"). Without sanitizing
# these before they're persisted, a crafted repo comment could get stored
# via an AI-sourced finding and later replayed verbatim into a *different*
# owner's fix prompt through the community fallback tier — a stored,
# cross-tenant prompt-injection vector. `_sanitize_field` is applied both at
# write time (index_finding / record_fix_outcome) and at read time
# (_score_results, as defense in depth for records written before this
# existed or by any other path that touches the collection directly).
# Applied as two separate sequential passes (not one alternation) so a
# "### SYSTEM:" line gets BOTH markers stripped — a single combined
# alternation only consumes non-overlapping matches per scan, so the first
# match (the fence/heading) would otherwise "use up" the line start and let
# the adjacent role-marker survive untouched.
_STRUCTURAL_MARKER_RE = re.compile(r"```|#{3,}")
_ROLE_MARKER_RE = re.compile(r"(?im:^\s*(system|assistant|user)\s*:)|(?i:ignore (all )?previous instructions)")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s+")


def _sanitize_field(value: Optional[str], max_len: Optional[int] = None) -> str:
    """Collapse a metadata field to a single-line, control-char-free,
    length-capped, structural-marker-free string. Idempotent — sanitizing an
    already-sanitized string is a no-op, so it's safe to apply at both write
    and read time."""
    if not value:
        return ""
    text = _CONTROL_CHARS_RE.sub(" ", str(value))
    text = _STRUCTURAL_MARKER_RE.sub(" ", text)
    text = _ROLE_MARKER_RE.sub(" ", text)
    # Force single-line: a multi-line field is what a fake "### SYSTEM:"
    # header block needs to look legitimate once spliced into the prompt.
    text = _WHITESPACE_RE.sub(" ", text).strip()
    limit = max_len if max_len is not None else get_settings().rag_max_field_chars
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"  # "…"
    return text


# Coarse file-extension -> language map. Only used to compare "is this prior
# fix even in the same language" — doesn't need to be exhaustive, just
# needs to avoid e.g. matching a Python fix as prior art for a Go file.
_EXTENSION_LANGUAGE = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "java": "java",
    "go": "go",
    "rb": "ruby",
    "php": "php",
    "cs": "csharp",
    "cpp": "cpp",
    "cc": "cpp",
    "c": "c",
    "rs": "rust",
    "kt": "kotlin",
    "swift": "swift",
    "html": "html",
    "sql": "sql",
    "sh": "shell",
    "yml": "yaml",
    "yaml": "yaml",
    "tf": "terraform",
}


def _language_from_file(path: Optional[str]) -> Optional[str]:
    """Best-effort language guess from a file's extension. Returns None for
    missing/extensionless paths rather than guessing wrong."""
    if not path or "." not in path:
        return None
    ext = path.rsplit(".", 1)[-1].lower()
    return _EXTENSION_LANGUAGE.get(ext)


def is_enabled() -> bool:
    return get_settings().rag_memory_enabled


def _doc_id(scan_id: str, finding_id: str) -> str:
    return f"{scan_id}:{finding_id}"


def _embedding_text(finding: dict) -> str:
    parts = [
        finding.get("title") or "",
        finding.get("category") or "",
        finding.get("description") or "",
        f"severity:{finding.get('severity') or ''}",
        f"file:{finding.get('file') or ''}",
    ]
    text = "\n".join(p for p in parts if p)
    # Guard: if finding dict is entirely empty (e.g. record_fix_outcome fallback
    # with no finding context), produce a descriptive placeholder so the vector
    # isn't a near-zero-norm hash of an empty string.
    text = text or "unknown vulnerability finding"
    # Cost/latency control (PatchLine architecture rule: "do not send
    # unnecessary [...] content to models" — applies to the embedding call
    # too, not just chat completions). `description` on an AI-sourced
    # finding is model-generated from repository content and has no upper
    # bound otherwise.
    max_chars = get_settings().rag_max_embedding_chars
    if max_chars and len(text) > max_chars:
        text = text[:max_chars]
    return text


async def index_finding(owner_id: str, scan_id: str, repo: str, finding: dict) -> None:
    """Best-effort: embed one finding and upsert it into the Chroma
    finding_memory collection."""
    if not is_enabled():
        return
    finding_id = finding.get("id")
    if not finding_id:
        return
    try:
        vector = await embeddings.embed(_embedding_text(finding))
        collection = await chroma_client.get_collection()
        metadata: dict[str, Any] = {
            "ownerId": owner_id,
            "scanId": scan_id,
            "findingId": finding_id,
            # Sanitized: these fields get replayed verbatim into a future
            # fix-generation prompt (see module-level comment above
            # _INJECTION_MARKER_RE). repo/title/category/severity/file can
            # all be influenced by repository content for AI-sourced findings.
            "repo": _sanitize_field(repo),
            "title": _sanitize_field(finding.get("title")),
            "category": _sanitize_field(finding.get("category")),
            "severity": _sanitize_field(finding.get("severity")),
            "file": _sanitize_field(finding.get("file")),
            "embeddingProvider": get_settings().embedding_provider,
            "indexedAt": datetime.datetime.utcnow().isoformat() + "Z",
            "hasFix": False,
        }
        await asyncio.to_thread(
            collection.upsert,
            ids=[_doc_id(scan_id, finding_id)],
            embeddings=[vector],
            metadatas=[metadata],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory_index_finding_failed", scan_id=scan_id, finding_id=finding_id, error=str(exc))


async def record_fix_outcome(
    scan_id: str,
    finding_id: str,
    summary: str,
    verified: bool,
    method: str,
    finding: Optional[dict] = None,
    owner_id: Optional[str] = None,
    repo: Optional[str] = None,
) -> None:
    """Best-effort: attach the fix outcome to the finding's memory point once
    generate_and_verify_fix finishes. If the point was not pre-indexed, upsert it directly
    so Chroma memory is ALWAYS updated."""
    if not is_enabled():
        return
    doc_id = _doc_id(scan_id, finding_id)
    # fixSummary is model-generated (the fix model's own explanation of what
    # it changed) and gets replayed verbatim into the NEXT fix prompt for
    # this or any other similar finding — sanitize it same as the other
    # replayed fields, regardless of which branch below writes it.
    safe_summary = _sanitize_field(summary, max_len=get_settings().rag_max_field_chars * 2)
    try:
        collection = await chroma_client.get_collection()
        existing = await asyncio.to_thread(collection.get, ids=[doc_id], include=["metadatas"])
        metadatas = existing.get("metadatas") or []

        if metadatas and metadatas[0]:
            metadata = dict(metadatas[0])
            metadata["hasFix"] = True
            metadata["fixSummary"] = safe_summary
            metadata["fixVerified"] = verified
            metadata["fixVerificationMethod"] = method
            metadata["fixRecordedAt"] = datetime.datetime.utcnow().isoformat() + "Z"
            await asyncio.to_thread(collection.update, ids=[doc_id], metadatas=[metadata])
            logger.info(
                "memory_record_fix_outcome_updated",
                scan_id=scan_id,
                finding_id=finding_id,
                verified=verified,
            )
        else:
            # Point missing — construct metadata and upsert into Chroma
            f_dict = finding or {}
            emb_text = _embedding_text(f_dict) if f_dict else summary
            vector = await embeddings.embed(emb_text)
            metadata = {
                "ownerId": owner_id or "",
                "scanId": scan_id,
                "findingId": finding_id,
                "repo": _sanitize_field(repo),
                "title": _sanitize_field(f_dict.get("title") or summary or "Vulnerability Fix"),
                "category": _sanitize_field(f_dict.get("category")),
                "severity": _sanitize_field(f_dict.get("severity")),
                "file": _sanitize_field(f_dict.get("file")),
                "hasFix": True,
                "fixSummary": safe_summary,
                "fixVerified": verified,
                "fixVerificationMethod": method,
                "fixRecordedAt": datetime.datetime.utcnow().isoformat() + "Z",
            }
            await asyncio.to_thread(
                collection.upsert,
                ids=[doc_id],
                embeddings=[vector],
                metadatas=[metadata],
            )
            logger.info(
                "memory_record_fix_outcome_upserted",
                scan_id=scan_id,
                finding_id=finding_id,
                verified=verified,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory_record_fix_outcome_failed", scan_id=scan_id, finding_id=finding_id, error=str(exc))


def _composite_score(
    similarity: float,
    metadata: dict,
    query_finding: dict,
    verified: bool,
    category_success_rate: Optional[float] = None,
) -> tuple[float, list[str]]:
    """Multi-factor re-rank score for one candidate against the finding
    we're generating a fix for. Returns (score, matchedFactors) — the
    factor list is carried through to the item for observability/logging,
    not just used internally.

    This exists because raw vector similarity alone can be misled by
    surface wording (two findings can read similarly but be a different
    vulnerability class or a different language), and because similarity
    has no way to know a candidate already failed verification last time.
    """
    score = similarity
    factors: list[str] = []

    query_category = (query_finding.get("category") or "").strip().lower()
    cand_category = (metadata.get("category") or "").strip().lower()
    if query_category and cand_category and query_category == cand_category:
        score += _WEIGHT_CATEGORY_MATCH
        factors.append("category_match")

    query_lang = _language_from_file(query_finding.get("file"))
    cand_lang = _language_from_file(metadata.get("file"))
    if query_lang and cand_lang and query_lang == cand_lang:
        score += _WEIGHT_LANGUAGE_MATCH
        factors.append("language_match")

    query_severity = (query_finding.get("severity") or "").strip().lower()
    cand_severity = (metadata.get("severity") or "").strip().lower()
    if query_severity and cand_severity and query_severity == cand_severity:
        score += _WEIGHT_SEVERITY_MATCH
        factors.append("severity_match")

    if verified:
        score += _WEIGHT_VERIFIED_BONUS
        factors.append("verified_fix")
    else:
        # hasFix but not verified == a strategy that was already attempted
        # and did NOT pass verification. Still useful as an anti-pattern
        # for the prompt, but must not outrank a proven fix just because
        # its raw similarity happened to be a little higher.
        score -= _WEIGHT_FAILED_PENALTY
        factors.append("unverified_or_failed_attempt")

    # "Historical success" as its own factor (distinct from this one
    # candidate's own verified/failed flag): how often has THIS category, in
    # general, produced a verified fix across the whole pool of candidates
    # returned for this query? A candidate in a track-record-good category
    # gets a small nudge even if its own similarity is only middling —
    # mirrors the ranking spec's "Historical success: 96%" style signal.
    if category_success_rate is not None:
        score += _WEIGHT_HISTORICAL_SUCCESS * category_success_rate
        factors.append(f"category_success_rate={category_success_rate:.0%}")

    return round(max(0.0, min(1.0, score)), 4), factors


def _category_success_rates(metadatas: list) -> dict[str, float]:
    """Aggregate verified/attempted ratio per category across a raw
    candidate pool (BEFORE threshold filtering / top_k trim — the more data
    points, the more meaningful the rate). Categories with zero attempts
    aren't included, so callers should treat a missing key as 'no signal'
    rather than 0%."""
    totals: dict[str, int] = {}
    verified_counts: dict[str, int] = {}
    for metadata in metadatas:
        has_fix = bool(metadata.get("hasFix", False)) or bool(metadata.get("fixSummary"))
        if not has_fix:
            continue
        category = (metadata.get("category") or "").strip().lower()
        if not category:
            continue
        totals[category] = totals.get(category, 0) + 1
        if bool(metadata.get("fixVerified", False)):
            verified_counts[category] = verified_counts.get(category, 0) + 1
    return {cat: verified_counts.get(cat, 0) / count for cat, count in totals.items()}


def _score_results(
    metadatas: list, distances: list, source: str, top_k: int, query_finding: Optional[dict] = None
) -> list[dict[str, Any]]:
    """Convert raw Chroma query results into scored, threshold-filtered,
    multi-factor-ranked items. `source` is either 'owner' or 'community' —
    carried through to the prompt so the fix model knows the provenance of
    each piece of prior art.

    Ranking is deliberately NOT "highest cosine similarity wins" — see
    `_composite_score` docstring and the module docstring above.
    """
    settings = get_settings()
    is_mock = settings.embedding_provider == "mock"
    threshold = 0.0 if is_mock else settings.rag_min_similarity_threshold
    query_finding = query_finding or {}
    category_rates = _category_success_rates(metadatas)
    items: list[dict[str, Any]] = []

    for idx, (metadata, distance) in enumerate(zip(metadatas, distances)):
        # Only accept records that actually contain a fix outcome
        has_fix = bool(metadata.get("hasFix", False)) or bool(metadata.get("fixSummary"))
        if not has_fix:
            continue

        raw_sim = round(max(0.0, min(1.0, 1.0 - distance)), 4)
        # In mock mode, map pseudo-random distance into a realistic 75%-95% match range
        if is_mock:
            similarity = round(max(0.72, min(0.96, 0.94 - (idx * 0.06))), 2)
        else:
            similarity = raw_sim

        if similarity < threshold:
            continue

        verified = bool(metadata.get("fixVerified", False))
        cand_category = (metadata.get("category") or "").strip().lower()
        composite, factors = _composite_score(
            similarity, metadata, query_finding, verified, category_rates.get(cand_category)
        )

        items.append(
            {
                "similarity": similarity,
                "matchScore": composite,
                "matchedFactors": factors,
                "source": source,
                "scanId": metadata.get("scanId"),
                "findingId": metadata.get("findingId"),
                # Sanitized at read time too (defense in depth — see the
                # comment above _INJECTION_MARKER_RE): covers records
                # written before sanitization existed, or by any other
                # write path, so what actually reaches a future prompt is
                # never unsanitized regardless of how it got into Chroma.
                "repo": _sanitize_field(metadata.get("repo")),
                "title": _sanitize_field(metadata.get("title")) or _sanitize_field(metadata.get("fixSummary")) or "Prior Fix",
                "category": _sanitize_field(metadata.get("category")),
                "severity": _sanitize_field(metadata.get("severity")),
                "file": _sanitize_field(metadata.get("file")),
                "fixSummary": _sanitize_field(metadata.get("fixSummary"), max_len=settings.rag_max_field_chars * 2),
                "verified": verified,
            }
        )

    # Rank by the multi-factor composite score, not raw similarity — this is
    # the "don't blindly select the nearest vector" requirement. Similarity
    # is kept as a tiebreaker for candidates whose composite score ties.
    items.sort(key=lambda x: (x["matchScore"], x["similarity"]), reverse=True)
    return items[:top_k]


async def retrieve_similar(owner_id: str, finding: dict, top_k: int = 3) -> list[dict[str, Any]]:
    """Semantic retrieval for the fix-generation prompt.

    Three-tier fallback query strategy:
    Tier 1 — Owner-scoped query (ownerId + hasFix)
    Tier 2 — Community query (hasFix)
    Tier 3 — Broad query with Python-side metadata filtering

    Items below similarity threshold are discarded. Degrades safely to [] on error.
    """
    if not is_enabled():
        return []

    try:
        query_vector = await embeddings.embed(_embedding_text(finding))
        collection = await chroma_client.get_collection()

        query_candidates = get_settings().rag_query_candidates
        # Chroma raises if n_results > collection size — clamp to actual count
        # so new deployments (few documents) don't log errors on every fix.
        try:
            total_docs = await asyncio.to_thread(collection.count)
        except Exception:
            total_docs = query_candidates
        n_results = max(1, min(query_candidates, total_docs))
        if total_docs == 0:
            return []

        # ── Tier 1: Owner-scoped query ─────────────────────────────────────────
        if owner_id:
            for where_clause in [
                {"$and": [{"ownerId": {"$eq": owner_id}}, {"hasFix": {"$eq": True}}]},
                {"ownerId": owner_id},
            ]:
                try:
                    result = await asyncio.to_thread(
                        collection.query,
                        query_embeddings=[query_vector],
                        n_results=n_results,
                        where=where_clause,
                        include=["metadatas", "distances"],
                    )
                    raw_meta = (result.get("metadatas") or [[]])[0]
                    raw_dist = (result.get("distances") or [[]])[0]
                    owner_items = _score_results(
                        raw_meta, raw_dist, source="owner", top_k=top_k, query_finding=finding
                    )
                    if owner_items:
                        logger.info(
                            "memory_retrieve_owner_scoped_success",
                            finding_id=finding.get("id"),
                            owner_id=owner_id,
                            retrieved=len(owner_items),
                            match_scores=[it["matchScore"] for it in owner_items],
                            matched_factors=[it["matchedFactors"] for it in owner_items],
                        )
                        return owner_items
                except Exception as exc:  # noqa: BLE001
                    logger.warning("memory_retrieve_owner_tier_error", error=str(exc))

        # ── Tier 2: Community query (hasFix) ───────────────────────────────────
        for where_clause in [{"hasFix": {"$eq": True}}, {"hasFix": True}, None]:
            try:
                kwargs: dict[str, Any] = {
                    "query_embeddings": [query_vector],
                    "n_results": n_results,
                    "include": ["metadatas", "distances"],
                }
                if where_clause is not None:
                    kwargs["where"] = where_clause

                result = await asyncio.to_thread(collection.query, **kwargs)
                raw_meta = (result.get("metadatas") or [[]])[0]
                raw_dist = (result.get("distances") or [[]])[0]
                community_items = _score_results(
                    raw_meta, raw_dist, source="community", top_k=top_k, query_finding=finding
                )
                if community_items:
                    logger.info(
                        "memory_retrieve_community_fallback_success",
                        finding_id=finding.get("id"),
                        retrieved=len(community_items),
                        match_scores=[it["matchScore"] for it in community_items],
                        matched_factors=[it["matchedFactors"] for it in community_items],
                    )
                    return community_items
            except Exception as exc:  # noqa: BLE001
                logger.warning("memory_retrieve_community_tier_error", error=str(exc))

        return []

    except Exception as exc:  # noqa: BLE001
        logger.warning("memory_retrieve_similar_failed", owner_id=owner_id, error=str(exc))
        return []
