import base64
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


def _decode_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception:
        return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    port: int = 5002
    service_name: str = "ai-storage-service"

    cors_origins: str = "http://localhost:3000"

    jwt_public_key_base64: Optional[str] = None
    # Optional: see auth-service's equivalent env var for the full
    # explanation — lets _verify() in core/security.py still accept tokens
    # signed under the pre-rotation key during the handover window.
    jwt_previous_public_key_base64: Optional[str] = None
    jwt_issuer: str = "hackathon-auth-service"
    jwt_audience: str = "patchline"

    internal_service_token: str = ""

    mongodb_uri: Optional[str] = None
    mongodb_database: str = "ai_storage_db"

    redis_url: str = "redis://localhost:6379"

    azure_storage_connection_string: Optional[str] = None
    azure_storage_container: str = "hackathon-uploads"
    max_upload_bytes: int = 25 * 1024 * 1024

    ai_provider: str = "mock"
    ai_model: str = "llama-3.1-8b-instant"
    ai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = ""
    azure_openai_deployment_name: str = ""  # alias used in .env
    azure_openai_api_key: str = ""          # maps to AZURE_OPENAI_API_KEY
    azure_openai_api_version: str = "2024-06-01"  # maps to AZURE_OPENAI_API_VERSION

    # ── AI Router: Featherless (primary) -> fallback provider, per task ──
    # See app/services/model_router.py and docs/AI-routing.md.
    #
    # AI_PROVIDER above stays the plain single-provider switch (mock for
    # tests/local dev with no key, or openai/azure_openai/groq to point the
    # WHOLE app at one provider) — nothing about it changes. FEATHERLESS_*
    # is additive: when FEATHERLESS_ENABLED=true and FEATHERLESS_API_KEY is
    # set, the router tries Featherless FIRST for the four routed pipeline
    # tasks below, and falls back to AI_PROVIDER's existing provider/model
    # only if the Featherless call itself fails (timeout, 5xx, auth error).
    # With FEATHERLESS_ENABLED unset/false (the default), behavior is
    # byte-for-byte identical to before this existed — every existing
    # deployment and every existing test keeps working unchanged.
    featherless_enabled: bool = False
    featherless_api_key: str = ""
    featherless_base_url: str = "https://api.featherless.ai/v1"
    featherless_timeout_seconds: int = 60

    # Per-task Featherless models. "rag_ranking" is defined here for
    # completeness/future use but is NOT currently called — RAG candidate
    # ranking is intentionally deterministic (app/core/memory_store.py's
    # composite scorer), matching the same "risk calculation must be
    # deterministic, not LLM-invented" principle the Risk Engine follows.
    # If an LLM-assisted re-rank/tie-break is added later, this is where its
    # model config already lives.
    featherless_model_analysis: str = "Qwen/Qwen3-Coder-30B-A3B-Instruct"
    featherless_model_rag_ranking: str = "deepseek-ai/DeepSeek-V3-0324"
    featherless_model_fix: str = "Qwen/Qwen3-Coder-480B-A35B-Instruct"
    featherless_model_verify: str = "deepseek-ai/DeepSeek-V3-0324"

    # Fallback provider name (must be a key in ai_providers._PROVIDERS) +
    # per-task fallback models — used both when Featherless is disabled
    # entirely (fallback becomes the ONLY path, via whichever of
    # azure_openai/openai below matches AI_PROVIDER's own deployment
    # settings for scan/fix/verify — see scanner.py's _scan_model/_fix_model
    # /_verify_model, which still take priority when set) and when
    # Featherless is enabled but fails for a given call.
    fallback_provider: str = "openai"
    fallback_model_analysis: str = "gpt-4.1-mini"
    fallback_model_rag_ranking: str = "gpt-5.2"
    fallback_model_fix: str = "gpt-5.2"
    fallback_model_verify: str = "gpt-5.3-codex"

    # ── Cost-tiered scanner deployments (Azure AI Foundry) ──
    # scan   (gpt-4.1-mini) — bulk repo scanning; fans out over every
    #                         scannable file, so it runs on the cheapest tier.
    # fix    (gpt-5.2)      — generates the actual patch for one approved
    #                         finding at a time.
    # verify (codex-5.3)    — code-specialized recheck of the generated patch.
    azure_openai_deployment_scan: str = ""    # gpt-4.1-mini
    azure_openai_deployment_fix: str = ""     # gpt-5.2
    azure_openai_deployment_verify: str = ""  # codex-5.3

    project_name: str = "hackathon-template"

    # ── SAST engine (Semgrep) ──
    # The deterministic scanner's primary pass. `semgrep_config_path` points
    # at a local, repo-committed rule pack (see semgrep-rules/patchline-rules.yml)
    # so a scan never depends on the public Semgrep Registry being reachable.
    # `semgrep_extra_configs` optionally layers registry rulesets (or other
    # local paths) on top for deployments that want broader coverage and
    # accept that network dependency — comma-separated, e.g.
    # "p/security-audit,p/secrets". Empty by default (local-only, no network
    # call at scan time).
    semgrep_enabled: bool = True
    semgrep_binary: str = "semgrep"
    semgrep_config_path: str = "semgrep-rules/patchline-rules.yml"
    semgrep_extra_configs: str = ""
    semgrep_timeout_seconds: int = 60
    semgrep_max_target_bytes: int = 2_000_000

    @property
    def semgrep_extra_config_list(self) -> list[str]:
        return [c.strip() for c in self.semgrep_extra_configs.split(",") if c.strip()]

    # ── AST engine (Tree-sitter) ──
    # The third deterministic pass (app/services/scanning/treesitter_engine.py).
    # Parses each supported file once into a real AST and re-derives the same
    # vulnerability categories the regex/Semgrep layers cover, but from
    # structure (call/assignment/import nodes) instead of text shape. Its
    # findings are never a replacement for Semgrep's — they exist to (a) give
    # a same-process structural signal when the semgrep binary is missing,
    # and (b) add corroborating "structural evidence" to the aggregator so a
    # finding two or three engines agree on can be surfaced as one
    # higher-confidence finding (see deterministic_scanner._dedupe) and given
    # richer AST context in the AI enrichment prompt.
    treesitter_enabled: bool = True

    # ── Stuck-fix reconciliation sweep ──
    # generate_and_verify_fix marks a finding FIX_PROCESSING before doing any
    # real work, then FIX_VERIFIED/FIX_NEEDS_REVIEW/FIX_FAILED when it's done.
    # A normal exception is already caught and marks FIX_FAILED (see
    # _mark_failed), but a hard process kill or infra-level timeout mid-request
    # skips that cleanup entirely, leaving the finding stuck in FIX_PROCESSING
    # forever with no retry possible (FIX_PROCESSING only has a self-loop, per
    # state_machine.TRANSITIONS). This periodic sweep catches that case.
    stuck_fix_processing_minutes: int = 30  # older than this = considered abandoned
    reconciliation_interval_seconds: int = 300  # how often the sweep runs

    # ── Elasticsearch (optional — search degrades gracefully if unset) ──
    # Direct endpoint URL (e.g. http://localhost:9200 or https://your-es-cluster-endpoint:9200)
    es_endpoint: Optional[str] = None
    es_url: Optional[str] = None
    es_cloud_id: Optional[str] = None
    es_api_key: Optional[str] = None
    es_username: Optional[str] = None
    es_password: Optional[str] = None

    # ── RAG memory (Remember step — app/core/memory_store.py) ──
    # Semantic recall over past findings/fixes at fix-generation time.
    # Disable to fall back to the pipeline's pre-existing behavior (fix
    # generation runs with no retrieved context, same as before this existed).
    rag_memory_enabled: bool = True

    # "mock" (default): deterministic hash-based vectors, zero dependency,
    # exercises the full index -> retrieve -> augment path with no API key —
    # not semantically meaningful, see app/services/embeddings.py docstring.
    # "azure_openai": real embeddings via AZURE_OPENAI_EMBEDDING_DEPLOYMENT,
    # reusing AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY from the chat tiers
    # above.
    embedding_provider: str = "mock"
    azure_openai_embedding_deployment: str = ""

    # Minimum cosine similarity (post 1-distance) a Chroma hit must clear to
    # be surfaced as prior art. Tunable per-environment without a redeploy —
    # raise towards 0.6 if retrieved items look noisy, lower towards 0.2 if
    # valid matches are being dropped. Watch the memory_retrieve_* log lines.
    rag_min_similarity_threshold: float = 0.35
    # How many raw candidates to pull per Chroma query before threshold
    # filtering + multi-factor re-ranking. Must stay meaningfully larger than
    # the top_k callers request, or there's no pool left to re-rank.
    rag_query_candidates: int = 12
    # Hard cap on characters sent to the embedding provider per finding.
    # Bounds embedding cost/latency and keeps one abnormally verbose
    # AI-sourced finding (untrusted repo content — see scanner.py's AI
    # supplemental-scan path) from blowing up a single embedding call.
    rag_max_embedding_chars: int = 4000
    # Hard cap on any single metadata field (title/category/severity/file/
    # fixSummary/repo) persisted to Chroma or spliced back into a future fix
    # prompt. Findings sourced from GPT-4.1-mini are derived from repository
    # content, which app/routers/scanner.py's own prompt-injection rules
    # treat as untrusted — this keeps a single field from becoming an
    # oversized or structurally-crafted payload once it's replayed into a
    # different fix-generation prompt later.
    rag_max_field_chars: int = 300

    # ── Chroma Cloud (vector storage for RAG memory — app/core/chroma_client.py) ──
    # Embeddings for finding_memory live in a Chroma Cloud collection rather
    # than alongside the finding metadata, so this is required whenever
    # RAG_MEMORY_ENABLED is true. tenant/database can be left unset — the
    # CloudClient resolves them from the API key's scope as long as the key
    # is scoped to a single database.
    chroma_api_key: Optional[str] = None
    chroma_host: str = "api.trychroma.com"   # override only for self-hosted Chroma
    chroma_tenant: Optional[str] = None
    chroma_database: Optional[str] = None
    chroma_collection: str = "finding_memory"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def jwt_public_key(self) -> Optional[str]:
        return _decode_key(self.jwt_public_key_base64)

    @property
    def jwt_previous_public_key(self) -> Optional[str]:
        return _decode_key(self.jwt_previous_public_key_base64)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.environment == "production" and not settings.jwt_public_key:
        raise RuntimeError(
            "JWT_PUBLIC_KEY_BASE64 must be set in production (copy it from auth-service)."
        )
    # CORS_ORIGINS is this service's CSRF defense (see docs/security.md) — no
    # separate CSRF token, so a tight origin allow-list plus httpOnly cookies
    # is what stops a cross-origin page from riding the user's session. A
    # wildcard silently removes that protection while everything else keeps
    # working, so fail loudly instead of deploying with CORS effectively open.
    if settings.environment == "production" and "*" in settings.cors_origin_list:
        raise RuntimeError(
            "CORS_ORIGINS must not contain '*' in production — this is the service's "
            "CSRF defense (see docs/security.md). List explicit origins instead."
        )
    return settings
