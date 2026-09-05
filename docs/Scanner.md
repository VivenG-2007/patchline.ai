# PatchLine — Scanner (Deterministic + AI Supplemental)

Covers `POST /api/scanner/scan` end to end: `services/main_services/src/controllers/scannerController.js` (queueing) → `services/main_services/src/workers/scannerWorkers.js` (BullMQ job) → `ai-service`'s `POST /scan` (`app/routers/scanner.py:run_scan`).

## 1. Three Deterministic Engines (Zero Token Cost)

`app/services/deterministic_scanner.py` orchestrates three zero-token-cost engines and merges their outputs:

1. **Semgrep** (`services/scanning/semgrep_engine.py`): AST SAST analysis with 248+ security rulesets.
2. **Tree-sitter** (`services/scanning/treesitter_engine.py`): In-process syntax tree parser for structural matching.
3. **Regex** (`services/scanning/regex_rules.py`): Pattern matching for secret detection and fallback scanning.

---

## 2. AI Supplemental Scan (`_ai_supplemental_scan`)

Runs an AI evaluation pass over the repo to discover business logic, auth/authz, and architectural flaws that deterministic SAST cannot catch:

- **Model Router Task**: `model_router.chat_for_task("analysis", ...)`
- **Primary Model**: `Qwen3-Coder-30B-A3B` (via Featherless)
- **Fallback Model**: `gpt-4.1-mini` (via OpenAI / Azure OpenAI)

Findings are tagged as `source: "ai"` with sequential `AI-###` IDs and deduplicated against deterministic findings.

---

## 3. Enrichment of Deterministic Findings (`_enrich_deterministic_findings`)

Deterministic findings are passed to `model_router.chat_for_task("analysis", ...)` (`Qwen3-Coder-30B-A3B` / `gpt-4.1-mini`) to generate human-readable contextual descriptions and suggested fix summaries while maintaining the deterministic category, severity, and ruleKey.
