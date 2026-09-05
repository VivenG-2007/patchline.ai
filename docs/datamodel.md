# PatchLine — Data Model

Authoritative reference for the shapes of data that move through the scan → fix
pipeline. This describes the actual objects produced/consumed by `main-service`
(Node/Express, `services/main`) and `ai-storage-service` (Python/FastAPI,
`services/ai_services`), not an idealized schema — field names below match the
JSON on the wire.

## 1. Scan Record (`scan:record:{scanId}`)

The scan record is the single mutable document that represents one scan from
`QUEUED` through `COMPLETED_WAITING_APPROVAL`/`SCAN_FAILED`, plus every
finding's fix sub-state. It lives in Redis (`redis-main`), written by
`services/main_services/src/services/scanStore.js`, and is mirrored into MongoDB
`scan_history` by `ai-storage-service` once a scan completes (see
[`database-schema.md`](./database-schema.md)).

```jsonc
{
  "scanId": "string (uuid)",
  "ownerId": "string (user id, from JWT sub claim)",
  "repo": "owner/name",
  "branch": "string",
  "status": "QUEUED | PROCESSING | COMPLETED_WAITING_APPROVAL | SCAN_FAILED",
  "previousStatus": "string — last status before this one, for audit",
  "scannedAt": "ISO-8601 timestamp",
  "findings": [ /* Finding, see §2 */ ],
  "fixes": {
    "<findingId>": { /* Fix record, see §3 */ }
  },
  "risk": { /* aggregate risk snapshot, see risk-engine.md */ }
}
```

`scanStore.saveScan`/`updateScan`/`transitionScan` are the only writers.
`updateScan()` deliberately refuses to touch `status` — any status change
must go through `transitionScan()`, which validates the move against
`scanState.js`'s transition table (see [`state-machines.md`](./state-machines.md)).
The record has a 24-hour TTL (`TTL_SECONDS` in `scanStore.js`) — a scan's
approval window is not meant to outlive a day.

A second, independent Redis key (`scan:stage:{scanId}`, on the *shared*
Redis instance, TTL 15 minutes) carries a live pipeline-stage checkpoint
written directly by `ai-storage-service` (`scan_progress.py`). It is read
via `scanStore.getScanStage()` and is treated as best-effort — a missing key
means "no checkpoint newer than 15 minutes," never an error.

## 2. Finding

A finding is either **deterministic** (produced by the Semgrep/Tree-sitter/
regex engines, `services/ai_services/app/services/deterministic_scanner.py`)
or **AI** (produced by the GPT-4.1-mini supplementary pass). Both shapes are
normalized onto the same envelope before they ever leave the scanner:

```jsonc
{
  "id": "DET-001 | AI-001",
  "source": "deterministic | ai",
  "engine": "semgrep | treesitter | regex | null (ai findings)",
  "evidence": ["semgrep", "regex"],   // which engines independently agreed — deterministic only
  "ruleKey": "string — stable rule identity, unique across all three engines",
  "category": "e.g. 'SQL Injection', 'Hardcoded Secret'",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",   // normalized, see severity.py
  "confidence": "high | medium | low",             // AI findings only
  "title": "string",
  "description": "string",
  "file": "path/relative/to/repo",
  "line": "integer",
  "suggestedFix": "string, human-readable — not the patch itself"
}
```

`severity` is always one of the four canonical values —
`app/services/severity.py:normalize()` is the single choke point every
finding, regardless of source, passes through before it reaches a response
or the frontend (see that module's docstring for the bug this fixed: AI
findings previously leaked a 5th "INFO" value that silently disagreed with
the deterministic scale).

## 3. Fix Record (`fixes[findingId]`)

```jsonc
{
  "status": "AWAITING_APPROVAL | FIX_QUEUED | FIX_PROCESSING | FIX_VERIFIED | FIX_NEEDS_REVIEW | FIX_FAILED | FIX_UNRESOLVED",
  "previousStatus": "string",
  "attempts": "integer — bumped only when (re-)entering FIX_QUEUED, capped at MAX_FIX_ATTEMPTS=3",
  "candidateId": "string — identity of the strategy currently in flight",
  "strategyHash": "string — see fingerprint.py:strategy_fingerprint",
  "patch": "unified diff string (present once a patch has been generated)",
  "codexVerification": { /* see verification.md */ },
  "deterministicScanResult": { /* see verification.md */ },
  "riskBefore": { /* see risk-engine.md */ },
  "riskAfter": { /* present only once VERIFIED */ },
  "failureReason": "string — actionable, not generic (see error-codes.md)",
  "reasonCode": "string — e.g. NO_VALID_FIX",
  "manualInterventionRequired": "boolean — true once FIX_UNRESOLVED"
}
```

`attempts` increments exactly once per `FIX_QUEUED` entry
(`scanStore.transitionFix`), which is what lets `findingState.js` /
`state_machine.py` enforce the bounded-retry rule without a separate
counter table.

## 4. RAG Memory Point (Chroma `finding_memory` collection)

One point per `(scanId, findingId)`, id = `"{scanId}:{findingId}"`. The
vector is the embedding of the finding's title/category/description/
severity/file (`memory_store._embedding_text`); everything else is point
metadata, sanitized (see `rag.md`) both at write time and at read time:

```jsonc
{
  "ownerId": "string",
  "scanId": "string",
  "findingId": "string",
  "repo": "string (sanitized)",
  "title": "string (sanitized)",
  "category": "string (sanitized)",
  "severity": "string (sanitized)",
  "file": "string (sanitized)",
  "embeddingProvider": "mock | azure_openai",
  "indexedAt": "ISO-8601",
  "hasFix": "boolean",
  "fixSummary": "string (sanitized) — only once a fix outcome is recorded",
  "fixVerified": "boolean",
  "fixVerificationMethod": "string",
  "fixRecordedAt": "ISO-8601"
}
```

## 5. Risk Snapshot

Produced by `app/services/risk_engine.py:calculate_finding_risk` (per
finding) and `aggregate_project_risk` (per scan). See
[`risk-engine.md`](./risk-engine.md) for the full methodology; the shape:

```jsonc
{
  "riskScore": "0-100 integer",
  "riskLevel": "CRITICAL | HIGH | MEDIUM | LOW",
  "severity": "string",
  "exploitability": "0-10 float",
  "exposure": "0.0-1.0 float",
  "assetCriticality": "0.5-1.0 float",
  "probabilityOfExploitation": "0-1 float",
  "financialImpact": "USD integer",
  "eal": { "annualLoss": "USD integer", "currency": "USD" },
  "methodology": "risk-engine-v1"
}
```

## 6. Users, OAuth Connections, Watched Repos (Supabase / Postgres)

`main-service` uses Supabase (`src/config/supabase.js`) for relational,
strongly-consistent account data — the opposite end of the durability
spectrum from the Redis-backed scan record. See
[`database-schema.md`](./database-schema.md) for table-level detail on
`github_connections`, `jira_connections`, and watched-repo rows; per
`docs/security.md`, OAuth tokens stored there are encrypted at rest with
AES-256-GCM (`OAUTH_TOKEN_ENCRYPTION_KEY_BASE64`).

## Cross-references

- Field-by-field storage location → [`database-schema.md`](./database-schema.md)
- Status transition legality → [`state-machines.md`](./state-machines.md)
- `failureReason`/`reasonCode` vocabulary → [`error-codes.md`](./error-codes.md)