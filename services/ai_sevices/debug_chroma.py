"""
ChromaDB + Embedding pipeline diagnostic script.

Run from services/ai_sevices:
    python debug_chroma.py

Tests each step independently so you can see exactly where the failure is.
"""

import asyncio
import os
import sys

# Load .env the same way the app does
from dotenv import load_dotenv
load_dotenv()

# ── Step helpers ────────────────────────────────────────────────────────────

def ok(msg):   print(f"  [OK] {msg}")
def fail(msg): print(f"  [FAIL] {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def section(title): print(f"\n{'-'*60}\n  {title}\n{'-'*60}")


# ── 1. Environment variables ─────────────────────────────────────────────────
section("1 - Environment variables")

endpoint   = os.getenv("AZURE_OPENAI_ENDPOINT", "")
api_key    = os.getenv("AZURE_OPENAI_API_KEY", "")
emb_dep    = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "")
api_ver    = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
emb_prov   = os.getenv("EMBEDDING_PROVIDER", "mock")
rag_on     = os.getenv("RAG_MEMORY_ENABLED", "false").lower()
chroma_key = os.getenv("CHROMA_API_KEY", "")
chroma_ten = os.getenv("CHROMA_TENANT", "")
chroma_db  = os.getenv("CHROMA_DATABASE", "")
chroma_col = os.getenv("CHROMA_COLLECTION", "finding_memory")

print(f"  EMBEDDING_PROVIDER            = {emb_prov!r}")
print(f"  RAG_MEMORY_ENABLED            = {rag_on!r}")
print(f"  AZURE_OPENAI_ENDPOINT         = {endpoint!r}")
print(f"  AZURE_OPENAI_EMBEDDING_DEPLOY = {emb_dep!r}")
print(f"  AZURE_OPENAI_API_VERSION      = {api_ver!r}")
print(f"  AZURE_OPENAI_API_KEY          = {'SET (' + api_key[:8] + '...)' if api_key else 'NOT SET'}")
print(f"  CHROMA_API_KEY                = {'SET (' + chroma_key[:8] + '...)' if chroma_key else 'NOT SET'}")
print(f"  CHROMA_TENANT                 = {chroma_ten!r}")
print(f"  CHROMA_DATABASE               = {chroma_db!r}")
print(f"  CHROMA_COLLECTION             = {chroma_col!r}")

errors = []
if emb_prov != "azure_openai":
    warn(f"EMBEDDING_PROVIDER={emb_prov!r} - must be 'azure_openai' to use real vectors")
if rag_on != "true":
    fail("RAG_MEMORY_ENABLED is not 'true' - indexing is disabled!")
    errors.append("rag_off")
if not endpoint:
    fail("AZURE_OPENAI_ENDPOINT is not set")
    errors.append("no_endpoint")
if not api_key:
    fail("AZURE_OPENAI_API_KEY is not set")
    errors.append("no_api_key")
if not emb_dep:
    fail("AZURE_OPENAI_EMBEDDING_DEPLOYMENT is not set")
    errors.append("no_emb_dep")
if not chroma_key:
    fail("CHROMA_API_KEY is not set")
    errors.append("no_chroma_key")

if "rag_off" in errors:
    print("\n  [STOP] RAG is disabled - nothing will ever be indexed. Fix and re-run.")
    sys.exit(1)


# ── 2. Azure OpenAI embedding call ──────────────────────────────────────────
section("2 - Azure OpenAI embedding call")

async def test_embedding():
    import httpx

    base = endpoint.rstrip("/")
    for suffix in ("/openai/v1/responses", "/openai/v1", "/openai/deployments"):
        if base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break

    url = f"{base}/openai/deployments/{emb_dep}/embeddings?api-version={api_ver}"
    print(f"  POST {url}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            url,
            headers={"api-key": api_key, "Content-Type": "application/json"},
            json={"input": "SQL injection vulnerability in db.query"},
        )

    if resp.status_code >= 400:
        fail(f"HTTP {resp.status_code}: {resp.text[:400]}")
        return None

    data = resp.json()
    vector = data["data"][0]["embedding"]
    ok(f"Got embedding vector: {len(vector)} dimensions")
    return vector

vector = None
if "no_endpoint" in errors or "no_api_key" in errors or "no_emb_dep" in errors:
    warn("Skipping - missing env vars above")
else:
    try:
        vector = asyncio.run(test_embedding())
    except Exception as e:
        fail(f"Exception: {e}")


# ── 3. Chroma Cloud connectivity ─────────────────────────────────────────────
section("3 - Chroma Cloud connectivity")

collection_handle = None
if "no_chroma_key" in errors:
    warn("Skipping - CHROMA_API_KEY not set")
else:
    try:
        import chromadb
        print(f"  chromadb version: {chromadb.__version__}")

        kwargs = {"api_key": chroma_key}
        if chroma_ten: kwargs["tenant"] = chroma_ten
        if chroma_db:  kwargs["database"] = chroma_db

        client = chromadb.CloudClient(**kwargs)
        collection_handle = client.get_or_create_collection(
            name=chroma_col,
            metadata={"hnsw:space": "cosine"},
        )
        count = collection_handle.count()
        if count == 0:
            warn(f"Collection '{chroma_col}' is EMPTY - no findings indexed yet")
        else:
            ok(f"Collection '{chroma_col}' has {count} document(s)")

    except Exception as e:
        fail(f"Chroma connection failed: {e}")


# ── 4. Test upsert + query round-trip ───────────────────────────────────────
section("4 - Test upsert -> query round-trip")

async def test_roundtrip():
    if collection_handle is None:
        warn("Skipping - no Chroma collection (step 3 failed)")
        return
    if vector is None:
        warn("No real embedding vector (step 2 failed) - using mock vector for Chroma test")
        import hashlib, struct, math
        v = []
        while len(v) < 256:
            d = hashlib.sha256(f"test|{len(v)}".encode()).digest()
            for i in range(0, len(d) - 7, 8):
                (val,) = struct.unpack_from(">Q", d, i)
                v.append((val / 0xFFFFFFFFFFFFFFFF) * 2 - 1)
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        test_vec = [x / norm for x in v[:256]]
    else:
        test_vec = vector

    test_id = "debug_diagnostic_test_entry"
    print(f"  Upserting test document (id={test_id!r}) ...")
    try:
        collection_handle.upsert(
            ids=[test_id],
            embeddings=[test_vec],
            metadatas=[{
                "ownerId": "debug",
                "scanId": "debug-scan",
                "findingId": "debug-finding",
                "repo": "debug/repo",
                "title": "SQL Injection test",
                "category": "injection",
                "severity": "high",
                "file": "db.js",
                "hasFix": False,
                "embeddingProvider": emb_prov,
                "indexedAt": "2024-01-01T00:00:00Z",
            }],
        )
        ok("Upsert succeeded - Chroma write is working")
    except Exception as e:
        fail(f"Upsert failed: {e}")
        return

    print("  Querying back ...")
    try:
        result = collection_handle.query(
            query_embeddings=[test_vec],
            n_results=1,
            include=["metadatas", "distances"],
        )
        metas = (result.get("metadatas") or [[]])[0]
        if metas:
            ok(f"Query returned: {metas[0].get('title')!r} (distance={result['distances'][0][0]:.4f})")
        else:
            fail("Query returned no results even after upsert")
    except Exception as e:
        fail(f"Query failed: {e}")

    try:
        collection_handle.delete(ids=[test_id])
        ok("Cleaned up test document")
    except Exception:
        warn("Could not delete test document - remove it manually from the Chroma dashboard")

asyncio.run(test_roundtrip())


# ── Summary ──────────────────────────────────────────────────────────────────
section("Summary / next steps")
print("  Done.")
