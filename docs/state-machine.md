# PatchLine — State Machines

PatchLine has **two** explicit, code-enforced state machines, each
implemented **twice** — once in `main-service` (JS) and once in
`ai-storage-service` (Python) — because both services can independently
attempt a transition and both must agree on what's legal. If you change one
implementation, change the other (both files say so in their header
comments).

| Machine | JS implementation | Python implementation |
|---|---|---|
| Scan lifecycle | `services/main/src/services/scanState.js` | *(scan lifecycle only lives in main-service — ai-storage-service doesn't own scan status)* |
| Finding fix lifecycle | `services/main/src/services/findingState.js` | `services/ai_services/app/services/state_machine.py` |

Both are simple `{status: [allowedNextStatuses]}` tables plus an
`assertTransition` function that throws (JS: `InvalidTransitionError`, HTTP
409; Python: `InvalidTransitionError`) rather than silently allowing an
out-of-order write.

## 1. Scan Lifecycle (`scanState.js`)

```
QUEUED ──────────────► PROCESSING ──┬──► COMPLETED_WAITING_APPROVAL   (terminal)
                            ▲        └──► SCAN_FAILED                 (terminal)
                            │
                            └── self-loop (BullMQ retry re-enters PROCESSING)
```

- `PROCESSING → PROCESSING` is a **deliberate self-loop**: BullMQ's own
  `attempts` retry mechanism re-runs `processScanJob` from the top on a
  transient failure, which re-asserts `PROCESSING` before redoing the work.
  Without the self-loop, that re-assertion would itself be an "invalid
  transition" and the retry could never proceed.
- Both `COMPLETED_WAITING_APPROVAL` and `SCAN_FAILED` are terminal — no
  outgoing transitions. A scan that finished (successfully or not) is done;
  a *new* scan is a new `scanId`, not a resurrected old one.

## 2. Finding Fix Lifecycle

```
AWAITING_APPROVAL ──► FIX_QUEUED ──┬──► FIX_PROCESSING ──┬──► FIX_VERIFIED        (terminal)
                          ▲        └──► FIX_FAILED        ├──► FIX_NEEDS_REVIEW
                          │                                ├──► FIX_FAILED
              FIX_NEEDS_REVIEW ◄───────────────────────────┘
              FIX_FAILED ─────────────────────────────────────► FIX_QUEUED (retry, bounded)
                                                                └──► FIX_UNRESOLVED (terminal)
```

`AWAITING_APPROVAL` is **implicit**: a finding on a completed scan with no
entry in `fixes` yet is awaiting approval — there's no explicit "create the
fix record" step.

### Transition tables

**main-service (`findingState.js`)** — the textbook path, because
main-service's Redis-backed flow really does write `FIX_QUEUED` first
(`approveAndFix` in `scannerController.js`) before the worker ever asserts
`FIX_PROCESSING`:

```js
AWAITING_APPROVAL: ['FIX_QUEUED'],
FIX_QUEUED:        ['FIX_PROCESSING', 'FIX_FAILED'],
FIX_PROCESSING:    ['FIX_PROCESSING', 'FIX_VERIFIED', 'FIX_NEEDS_REVIEW', 'FIX_FAILED', 'FIX_UNRESOLVED'],
FIX_NEEDS_REVIEW:  ['FIX_QUEUED'],
FIX_FAILED:        ['FIX_QUEUED'],
FIX_VERIFIED:      [],   // terminal
FIX_UNRESOLVED:     [],   // terminal
```

**ai-storage-service (`state_machine.py`)** — intentionally diverges by one
edge: `AWAITING_APPROVAL → FIX_PROCESSING` is *also* allowed. This is not a
drift bug — it's documented:

> ai-storage-service's own Mongo-backed copy of finding status never learns
> about the `FIX_QUEUED` write, because that write only ever reaches Redis
> (`main-service`'s side). So by the time the worker calls
> `generate_and_verify_fix` with `FIX_PROCESSING`, Mongo still reads
> `AWAITING_APPROVAL` — even though the finding really was approved. This
> is expected: the whole router requires
> `require_internal_service_token`, so only `main-service`'s already-gated
> worker can ever reach here. Nothing external can use this extra edge to
> bypass human approval.

### Self-loops and terminal states

- `FIX_PROCESSING → FIX_PROCESSING`: same BullMQ-retry reasoning as the scan
  machine — a retried fix job re-enters `FIX_PROCESSING` before redoing the
  work.
- `FIX_VERIFIED` and `FIX_UNRESOLVED` are both terminal, but mean opposite
  things. `FIX_VERIFIED` is success. `FIX_UNRESOLVED` is reached directly
  from `FIX_PROCESSING` (not via `FIX_NEEDS_REVIEW`/`FIX_FAILED`) because
  the "this was the last bounded attempt" decision is made in the same
  request that just finished verifying it — see
  [`fix-generation.md`](./fix-generation.md) Step 5. `FIX_UNRESOLVED` is
  deliberately **not** retryable (unlike `FIX_NEEDS_REVIEW`/`FIX_FAILED`),
  so a finding stuck here reads unambiguously as "needs a human," letting a
  UI or ticketing integration filter on the status alone rather than
  cross-referencing the attempts counter.

### Bounded retries

`MAX_FIX_ATTEMPTS = 3` in both implementations. `attempts` increments only
on entry to `FIX_QUEUED` from a retry source (`FIX_NEEDS_REVIEW` or
`FIX_FAILED`). `assertTransition` rejects a `FIX_QUEUED` re-entry once
`attempts >= MAX_FIX_ATTEMPTS`, raising `code: FIX_ATTEMPTS_EXHAUSTED` (see
[`error-codes.md`](./error-codes.md)).

## Why two machines instead of one shared library

`main-service` and `ai-storage-service` are different runtimes (Node vs
Python) with no shared code deployment path in this architecture, and each
owns a different piece of ground truth (Redis vs Mongo) that can legitimately
be out of sync mid-flight (see the `AWAITING_APPROVAL → FIX_PROCESSING`
divergence above). Keeping both tables hand-maintained, cross-referenced by
comment, and covered by tests (`findingState.test.js`,
`test_state_machine.py`) is the deliberate tradeoff versus building
cross-language shared infrastructure for two small tables.