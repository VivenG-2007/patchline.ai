'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Code2,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  ChevronDown,
  ChevronUp,
  GitPullRequest,
  ExternalLink,
  Loader2,
  Copy,
  Check,
  Lock,
  GitBranch,
  Cpu,
  BrainCircuit,
  Terminal,
} from 'lucide-react';
import Card from '@/components/ui/Card';
import ModelBadge from '@/components/ui/ModelBadge';
import Badge from '@/components/ui/Badge';
import Button from '@/components/ui/Button';
import RagMemoryTrace, { SimilarPastFix } from '@/components/RagMemoryTrace';
import { useToast } from '@/components/ToastNotification';
import { scannerApi } from '@/lib/api';

// Real, backend-confirmed fix-pipeline checkpoints (ai-storage-service's
// app/services/scan_progress.py FIX_STAGES) → short human label. Keep in
// sync with that list — if a stage is added/renamed there, add it here too;
// an unrecognized stage string just falls back to the generic label below
// rather than showing nothing.
const FIX_STAGE_LABELS: Record<string, string> = {
  FIX_GENERATING: 'Synthesizing patch on isolated branch…',
  CODEX_VERIFYING: 'Running independent adversarial review…',
  DETERMINISTIC_VERIFYING: 'Executing deterministic AST re-scan…',
  RISK_RECALCULATING: 'Recalculating portfolio risk metrics…',
};
const MAX_FIX_ATTEMPTS = 3; // mirrors state_machine.MAX_FIX_ATTEMPTS — display only, never enforced client-side

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  file: string;
  line: number;
  description: string;
  suggestedFix?: string;
  source?: 'deterministic' | 'ai';
  confidence?: 'high' | 'medium' | 'low';
  category?: string;
  ruleKey?: string;
  evidence?: string[];
  cwe?: string;
  jiraTicket?: { key: string; id?: string; url: string } | null;
}


export interface FixStatus {
  // UNRESOLVED: backend-terminal state — every bounded attempt (3) was
  // exhausted without a verified fix (see state_machine.py FIX_UNRESOLVED).
  // Distinct from FAILED/NEEDS_REVIEW: this is NOT retryable, ever — the
  // backend's own state machine will reject a retry with 409
  // FIX_ATTEMPTS_EXHAUSTED, so the UI must not offer one.
  phase: 'QUEUED' | 'PROCESSING' | 'VERIFIED' | 'FAILED' | 'NEEDS_REVIEW' | 'UNRESOLVED' | null;
  // True only when the BROWSER stopped actively polling (its own bounded
  // wait elapsed) while the backend job itself never reported a terminal
  // status. Must never be presented as a failure — the backend may still be
  // legitimately working (bounded retries + backoff can legitimately take
  // several minutes) and may still verify, need review, or fail on its own.
  stillProcessingInBackground?: boolean;
  // Real, backend-confirmed checkpoint for an in-flight fix (see
  // app/services/scan_progress.py's FIX_STAGES) — FIX_GENERATING,
  // CODEX_VERIFYING, DETERMINISTIC_VERIFYING, or RISK_RECALCULATING. Null/
  // undefined simply means "no checkpoint reported yet", not an error.
  stage?: string | null;
  fixBranch?: string;
  summary?: string;
  details?: string;
  pullRequest?: { number: number; url: string };
  jiraTicket?: { key: string; id?: string; url: string } | null;
  error?: string;
  attempts?: number;
  similarPastFixes?: SimilarPastFix[];
  ragMemoryEnabled?: boolean;
  fixModel?: string;
  verifyModel?: string;
  fixProvider?: string | null;
  verifyProvider?: string | null;
  // Structured verification results from the backend — drives the
  // AI Verification / Deterministic Re-scan / Risk panels in the card.
  aiVerification?: {
    status: 'PASSED' | 'FAILED' | 'SKIPPED';
    provider?: string;
    model?: string;
    confidence?: number;
    vulnerabilityResolved?: boolean;
    rootCauseFixed?: boolean;
    regressionRisk?: string;
    bypasses?: string[];
    issues?: string[];
    reason?: string | null;
  } | null;
  deterministicVerification?: {
    status: 'PASSED' | 'FAILED' | 'SKIPPED';
    ruleKey?: string | null;
    matchedLines?: number[];
    resolved?: boolean;
  } | null;
  riskEvaluation?: {
    status: 'PASSED' | 'FAILED';
    riskBefore?: Record<string, any> | null;
    riskAfter?: Record<string, any> | null;
    reductionPct?: number | null;
  } | null;
}


interface FindingCardProps {
  finding: Finding;
  fixStatus?: FixStatus;
  ragMemoryEnabled?: boolean;
  onApproveAndFix: (findingId: string) => Promise<void> | void;
  onViewDeepTimeline?: (finding: Finding) => void;
  scanId?: string;
  onPrCreated?: (findingId: string, pr: { number: number; url: string }) => void;
}

const SEVERITY_TONE: Record<Finding['severity'], 'critical' | 'warning' | 'info' | 'neutral'> = {
  CRITICAL: 'critical',
  HIGH: 'critical',
  MEDIUM: 'warning',
  LOW: 'info',
};

export default function FindingCard({
  finding,
  fixStatus,
  ragMemoryEnabled = true,
  onApproveAndFix,
  onViewDeepTimeline,
  scanId,
  onPrCreated,
}: FindingCardProps) {
  const [diffExpanded, setDiffExpanded] = useState(false);
  const [ragExpanded, setRagExpanded] = useState(true);
  const [logsExpanded, setLogsExpanded] = useState(true);
  const [approving, setApproving] = useState(false);
  const [creatingPr, setCreatingPr] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);
  const { addToast } = useToast();

  const handleCreatePr = async () => {
    if (!scanId || !finding.id || creatingPr) return;
    setCreatingPr(true);
    try {
      const res = await scannerApi.createPr(scanId, finding.id);
      const pr = res.data?.pullRequest;
      if (pr) {
        addToast({
          type: 'success',
          title: 'Pull Request Created',
          message: `PR #${pr.number} opened successfully on GitHub.`,
        });
        if (onPrCreated) {
          onPrCreated(finding.id, pr);
        }
      }
    } catch (err: any) {
      addToast({
        type: 'error',
        title: 'PR Creation Failed',
        message: err?.response?.data?.error?.message || err?.message || 'Failed to create PR on GitHub.',
      });
    } finally {
      setCreatingPr(false);
    }
  };

  const attempts = fixStatus?.attempts || 0;
  const maxAttemptsReached = attempts >= 3;
  const isVerified = fixStatus?.phase === 'VERIFIED';
  const isNeedsReview = fixStatus?.phase === 'NEEDS_REVIEW';
  const isFailed = fixStatus?.phase === 'FAILED';
  const isUnresolved = fixStatus?.phase === 'UNRESOLVED';
  const isFixing = !isFailed && !isUnresolved && (fixStatus?.phase === 'QUEUED' || fixStatus?.phase === 'PROCESSING' || approving);
  const isSettled = isVerified || isNeedsReview || isFailed || isUnresolved;

  // Never fabricate a patch. If the backend hasn't generated one yet (or a
  // fix attempt never produced one), there is nothing honest to show — the
  // diff panel renders an explicit "not available" state instead.
  const patchDiff = finding.suggestedFix || null;

  // Dynamic, backend-attributed labels — never hardcode a specific model
  // name, since model_router.py can route fix/verify calls to different
  // providers per attempt. Falls back to a generic label when the backend
  // hasn't reported attribution yet, rather than guessing.
  const fixModelLabel = fixStatus?.fixModel
    ? `${fixStatus.fixModel} Patch Synthesizer`
    : 'AI Patch Synthesizer';
  const verifyModelLabel = fixStatus?.verifyModel
    ? `${fixStatus.verifyModel} Evaluator & Deterministic Re-scanner`
    : 'AI Evaluator & Deterministic Re-scanner';

  const remediationLogs = React.useMemo(() => {
    const logs: { id: number; text: string; done: boolean; active?: boolean }[] = [];
    const stage = fixStatus?.stage;

    logs.push({
      id: 1,
      text: fixStatus?.fixBranch
        ? `Git branch initialized: ${fixStatus.fixBranch}`
        : 'Initializing isolated git remediation branch & AST context…',
      done: Boolean(fixStatus?.fixBranch || isSettled || (stage && stage !== 'FIX_GENERATING')),
      active: isFixing && (!stage || stage === 'FIX_GENERATING'),
    });

    logs.push({
      id: 2,
      text: fixStatus?.similarPastFixes && fixStatus.similarPastFixes.length > 0
        ? `ChromaDB vector memory: recalled ${fixStatus.similarPastFixes.length} similar verified AST patch patterns`
        : 'Querying vector memory store for similar verified fixes…',
      done: Boolean((fixStatus?.similarPastFixes && fixStatus.similarPastFixes.length > 0) || isSettled || (stage && stage !== 'FIX_GENERATING')),
      active: isFixing && (!stage || stage === 'FIX_GENERATING'),
    });

    logs.push({
      id: 3,
      text: fixStatus?.summary
        ? `${fixModelLabel}: ${fixStatus.summary}`
        : `Dispatching minimal, syntax-accurate patch synthesis to ${fixModelLabel}…`,
      done: Boolean(fixStatus?.summary || isSettled || (stage && (stage === 'CODEX_VERIFYING' || stage === 'DETERMINISTIC_VERIFYING' || stage === 'RISK_RECALCULATING'))),
      active: isFixing && stage === 'FIX_GENERATING',
    });

    const verifyModelLabel = fixStatus?.verifyModel || fixStatus?.aiVerification?.model || 'Codex';
    logs.push({
      id: 4,
      text: fixStatus?.aiVerification?.status
        ? `Adversarial review (${verifyModelLabel}): ${fixStatus.aiVerification.status}`
        : `Running independent adversarial review (${verifyModelLabel})…`,
      done: Boolean(fixStatus?.aiVerification || isSettled || (stage && (stage === 'DETERMINISTIC_VERIFYING' || stage === 'RISK_RECALCULATING'))),
      active: isFixing && stage === 'CODEX_VERIFYING',
    });

    logs.push({
      id: 5,
      text: fixStatus?.deterministicVerification?.status
        ? `Deterministic AST re-scan: ${fixStatus.deterministicVerification.status === 'PASSED' ? '0 matches (CLEAN)' : 'rule still matches'}`
        : 'Executing deterministic AST re-scan to certify 0 regressions…',
      done: Boolean(fixStatus?.deterministicVerification || isSettled || (stage && stage === 'RISK_RECALCULATING')),
      active: isFixing && stage === 'DETERMINISTIC_VERIFYING',
    });

    if (isVerified || fixStatus?.pullRequest) {
      logs.push({
        id: 6,
        text: fixStatus?.pullRequest
          ? `GitHub PR #${fixStatus.pullRequest.number} opened and synced to dashboard`
          : 'Finalizing unified diff & opening Pull Request…',
        done: Boolean(fixStatus?.pullRequest),
        active: isFixing && stage === 'RISK_RECALCULATING',
      });
    }

    return logs;
  }, [fixStatus, isFixing, isSettled, isVerified, fixModelLabel]);

  const handleApprove = async () => {
    if (maxAttemptsReached || isFixing) return;
    setApproving(true);
    try {
      await onApproveAndFix(finding.id);
      addToast({
        type: 'info',
        title: 'Remediation Authorized',
        message: `Dispatching automated patch synthesis and verification for ${finding.id}.`,
      });
    } catch (err: any) {
      addToast({
        type: 'error',
        title: 'Authorization Error',
        message: err.message || 'Failed to dispatch remediation request.',
      });
    } finally {
      setApproving(false);
    }
  };

  const copyPatch = () => {
    if (!patchDiff) return;
    navigator.clipboard.writeText(patchDiff);
    setCopiedPatch(true);
    addToast({
      type: 'info',
      title: 'Patch Copied',
      message: 'Unified diff copied to clipboard.',
      duration: 2500,
    });
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  return (
    <Card className="p-5 overflow-hidden transition-all border-border-default hover:border-border-hover space-y-4">
      {/* Flaw Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div className="space-y-2 flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={SEVERITY_TONE[finding.severity]} dot>
              {finding.severity}
            </Badge>

            <span className="font-mono text-xs text-text-muted px-2 py-0.5 rounded bg-bg-subtle border border-border-default">
              {finding.cwe || 'CWE-89'}
            </span>

            <span className="font-mono text-xs text-text-muted px-2 py-0.5 rounded bg-bg-subtle border border-border-default">
              ID: {finding.id}
            </span>

            {finding.source && (
              <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-accent-purple-soft text-accent-purple uppercase tracking-wider font-semibold">
                {finding.source === 'ai' ? 'AI Validated' : 'Deterministic SAST'}
              </span>
            )}

            {/* Render which specific deterministic tools/engines confirmed this finding */}
            {finding.evidence && finding.evidence.length > 0 && (
              <div className="flex items-center gap-1">
                {finding.evidence.map((eng) => (
                  <span
                    key={eng}
                    className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-border-default bg-bg-subtle text-accent-cyan font-medium"
                    title={`Confirmed by ${eng} engine`}
                  >
                    {eng === 'semgrep' ? 'Semgrep AST' : eng === 'treesitter' ? 'Tree-sitter AST' : eng === 'regex' ? 'Regex Rule' : eng}
                  </span>
                ))}
              </div>
            )}

            {finding.confidence && (
              <span className="font-mono text-[10px] text-text-muted">
                Confidence: <strong className="text-text-primary capitalize">{finding.confidence}</strong>
              </span>
            )}
          </div>


          <h3 className="font-display text-base font-semibold text-text-primary leading-snug">
            {finding.title}
          </h3>

          <p className="text-xs text-text-secondary leading-relaxed max-w-3xl">
            {finding.description}
          </p>

          <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-text-muted pt-1">
            <span className="flex items-center gap-1 text-text-secondary">
              <FileCode size={13} className="text-accent-cyan" />
              <span className="text-text-primary font-medium">{finding.file}</span>
              <span className="text-accent-cyan">:{finding.line}</span>
            </span>

            {finding.category && (
              <span>Category: <strong className="text-text-secondary">{finding.category}</strong></span>
            )}
          </div>
        </div>

        {/* Human Authorization Gate / Fix Status Actions */}
        <div className="flex flex-col sm:items-end gap-2.5 shrink-0 pt-2 md:pt-0">
          {isVerified ? (
            <div className="flex flex-col sm:items-end gap-1.5">
              <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-emerald-soft text-accent-emerald border border-accent-emerald/30 font-mono text-xs font-semibold">
                <CheckCircle2 size={14} />
                {fixStatus?.riskEvaluation?.reductionPct != null
                  ? `Fix Verified · ↓${Math.round(fixStatus.riskEvaluation.reductionPct)}% Risk`
                  : 'Fix Verified'}
              </div>
              {fixStatus?.pullRequest ? (
                <a
                  href={fixStatus.pullRequest.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs font-mono text-accent-cyan hover:underline font-bold"
                >
                  <GitPullRequest size={13} />
                  PR #{fixStatus.pullRequest.number} <ExternalLink size={11} />
                </a>
              ) : scanId && (fixStatus?.fixBranch || finding.suggestedFix) ? (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleCreatePr}
                  disabled={creatingPr}
                  className="text-xs inline-flex items-center gap-1.5 h-7 px-2.5"
                >
                  {creatingPr ? <Loader2 size={12} className="animate-spin" /> : <GitPullRequest size={12} />}
                  {creatingPr ? 'Opening PR…' : 'Create PR'}
                </Button>
              ) : null}
            </div>
          ) : isNeedsReview ? (
            <div className="flex flex-col sm:items-end gap-1.5">
              <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-amber-soft text-accent-amber border border-accent-amber/30 font-mono text-xs font-semibold">
                <AlertTriangle size={14} />
                Needs Human Review
              </div>
              {!maxAttemptsReached && (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleApprove}
                  disabled={isFixing}
                  className="text-xs"
                >
                  Retry ({3 - attempts} left)
                </Button>
              )}
            </div>
          ) : isUnresolved ? (
            <div className="flex flex-col sm:items-end gap-1.5">
              <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-rose-soft text-accent-rose border border-accent-rose/30 font-mono text-xs">
                <AlertTriangle size={14} />
                Manual Review Required
              </div>
              <span className="text-[10px] font-mono text-text-muted max-w-[220px] text-right">
                All 3 bounded attempts exhausted without a verified fix — not retryable.
              </span>
            </div>
          ) : isFailed ? (
            <div className="flex flex-col sm:items-end gap-1.5">
              <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-rose-soft text-accent-rose border border-accent-rose/30 font-mono text-xs">
                <AlertTriangle size={14} />
                Fix Test Failed
              </div>
              {!maxAttemptsReached && (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleApprove}
                  disabled={isFixing}
                  className="text-xs"
                >
                  Retry ({3 - attempts} left)
                </Button>
              )}
            </div>
          ) : isFixing ? (
            <div className="flex flex-col sm:items-end gap-1.5">
              <div className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-bg-subtle border border-accent-cyan/40 text-accent-cyan font-mono text-xs">
                <Loader2 size={14} className="animate-spin" />
                <span>
                  {fixStatus?.stillProcessingInBackground
                    ? 'Still running in background…'
                    : `Processing — Fix attempt ${attempts || 1}/${MAX_FIX_ATTEMPTS}`}
                </span>
              </div>
              {!fixStatus?.stillProcessingInBackground && fixStatus?.stage && (
                <span className="text-[10px] font-mono text-text-muted">
                  {FIX_STAGE_LABELS[fixStatus.stage] || fixStatus.stage}
                </span>
              )}
              {fixStatus?.stillProcessingInBackground && (
                <span className="text-[10px] font-mono text-text-muted max-w-[220px] text-right">
                  This is taking longer than usual (bounded retries can take a few minutes) — we&apos;re still
                  checking. No need to re-approve.
                </span>
              )}
            </div>
          ) : (
            <div className="flex flex-col sm:items-end gap-1">
              <Button
                size="sm"
                variant="primary"
                onClick={handleApprove}
                disabled={maxAttemptsReached}
                className="gap-1.5"
              >
                <Sparkles size={13} />
                Approve &amp; Fix
              </Button>
              <span className="text-[10px] font-mono text-text-muted flex items-center gap-1">
                <Lock size={10} /> Human Gate (3 attempts max)
              </span>
            </div>
          )}

          {onViewDeepTimeline && (
            <button
              type="button"
              onClick={() => onViewDeepTimeline(finding)}
              className="text-xs font-mono text-accent-cyan hover:underline text-left sm:text-right"
            >
              5-Stage Timeline →
            </button>
          )}
        </div>
      </div>

      {/* ────────────────── Active Fix Details: Synthesis & Verification ────────────────── */}
      {(isFixing || isSettled || fixStatus?.summary || fixStatus?.fixBranch) && (
        <div className="pt-3 border-t border-border-default space-y-3">
          {/* 4-Step Remediation Flow Stepper */}
          <div className="rounded-xl border border-border-default bg-bg-card/70 p-3">
            <div className="flex items-center justify-between text-[11px] font-mono text-text-muted mb-2 pb-1.5 border-b border-border-default/50">
              <span className="flex items-center gap-1.5 font-semibold text-text-primary">
                <span className={`w-2 h-2 rounded-full ${isFailed ? 'bg-accent-rose' : isVerified ? 'bg-accent-emerald' : isNeedsReview ? 'bg-accent-amber' : 'bg-accent-cyan pulse-dot'}`} />
                PatchLine Autonomous Remediation Track
              </span>
              <span className={`text-[10px] ${isFailed ? 'text-accent-rose font-semibold' : isNeedsReview ? 'text-accent-amber' : 'text-accent-cyan'}`}>
                {isVerified ? 'Completed · PR Active' : isFixing ? 'Synthesis & Verification in Flight' : isNeedsReview ? 'Human Review Needed' : isUnresolved ? 'Attempts Exhausted' : isFailed ? 'Remediation Attempt Failed' : 'Awaiting Authorization'}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { step: 1, label: 'Branch & RAG', key: 'BRANCH', active: isFixing && (!fixStatus?.stage || fixStatus?.stage === 'FIX_GENERATING'), done: isVerified || isSettled || (isFixing && fixStatus?.stage && fixStatus?.stage !== 'FIX_GENERATING') },
                { step: 2, label: 'AI Patch Synthesis', key: 'SYNTHESIS', active: isFixing && fixStatus?.stage === 'FIX_GENERATING', done: isVerified || (isSettled && Boolean(fixStatus?.summary)) || (isFixing && (fixStatus?.stage === 'CODEX_VERIFYING' || fixStatus?.stage === 'DETERMINISTIC_VERIFYING' || fixStatus?.stage === 'RISK_RECALCULATING')) },
                { step: 3, label: 'Dual Verification', key: 'VERIFY', active: isFixing && (fixStatus?.stage === 'CODEX_VERIFYING' || fixStatus?.stage === 'DETERMINISTIC_VERIFYING'), done: isVerified || (isFixing && fixStatus?.stage === 'RISK_RECALCULATING'), failed: isNeedsReview || isFailed || isUnresolved },
                { step: 4, label: 'GitHub PR & Sync', key: 'DEPLOY', active: isFixing && fixStatus?.stage === 'RISK_RECALCULATING', done: isVerified },
              ].map((st) => (
                <div
                  key={st.step}
                  className={`flex items-center gap-2 p-2 rounded-lg border text-xs font-mono transition-all ${
                    st.done
                      ? 'border-accent-emerald/30 bg-accent-emerald-soft/10 text-accent-emerald'
                      : st.failed
                        ? 'border-accent-amber/30 bg-accent-amber-soft/10 text-accent-amber'
                        : st.active
                          ? 'border-accent-cyan bg-accent-cyan-soft/20 text-accent-cyan shadow-sm'
                          : 'border-border-default/40 bg-bg-subtle/30 text-text-muted opacity-60'
                  }`}
                >
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 ${
                    st.done
                      ? 'bg-accent-emerald text-white'
                      : st.failed
                        ? 'bg-accent-amber text-black'
                        : st.active
                          ? 'bg-accent-cyan text-white pulse-ring-active'
                          : 'bg-bg-subtle border border-border-default text-text-muted'
                  }`}>
                    {st.done ? <Check size={11} strokeWidth={3} /> : st.active ? <Loader2 size={11} className="animate-spin" /> : st.step}
                  </div>
                  <span className="truncate text-[11px] font-medium">{st.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Fix Synthesis Card — model attribution is dynamic (fixModelLabel) */}
          <div className="rounded-xl border border-accent-purple/30 bg-bg-subtle/70 p-3.5 space-y-2 font-mono text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-default/60 pb-2">
              <div className="flex items-center gap-1.5 text-accent-purple font-semibold">
                <Cpu size={14} />
                <span>{fixModelLabel}</span>
              </div>
              {fixStatus?.fixBranch && (
                <div className="flex items-center gap-1 text-[11px] text-text-muted bg-bg-card px-2 py-0.5 rounded border border-border-default">
                  <GitBranch size={11} className="text-accent-cyan" />
                  <span className="text-text-primary">{fixStatus.fixBranch}</span>
                </div>
              )}
            </div>

            <p className="text-text-secondary text-xs leading-relaxed">
              {fixStatus?.summary || (isFixing ? 'Synthesizing minimal, syntax-accurate patch on isolated branch…' : isFailed ? (fixStatus?.error || 'Fix synthesis or verification failed for this attempt.') : 'No synthesis summary reported by the backend for this attempt.')}
            </p>
          </div>

          {/* Real-time AI Remediation Execution Log Stream */}
          <div className="rounded-xl border border-white/10 bg-terminal-bg p-3 font-mono text-xs space-y-1.5 animate-fade-rise-in">
            <div className="flex items-center justify-between text-[11px] text-terminal-muted border-b border-white/10 pb-1.5">
              <div className="flex items-center gap-1.5 text-accent-cyan font-semibold">
                <Terminal size={12} />
                <span>[AI_REMEDIATION_LOG] daemon://fix_{finding.id.toLowerCase()}.log</span>
              </div>
              <button
                type="button"
                onClick={() => setLogsExpanded((v) => !v)}
                className="text-[10px] text-terminal-muted hover:text-terminal-text flex items-center gap-1 transition-colors"
              >
                {logsExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                <span>{logsExpanded ? 'Collapse Logs' : 'View Stream Logs'}</span>
              </button>
            </div>

            {logsExpanded && (
              <div className="space-y-1 pt-1 max-h-40 overflow-y-auto">
                {remediationLogs.map((log) => (
                  <div key={log.id} className="flex items-start gap-2 text-terminal-text text-[11px] leading-relaxed">
                    <span className="text-terminal-muted select-none font-mono">[{log.id}]</span>
                    <span className="flex-1 flex items-center gap-1.5">
                      {log.done ? (
                        <Check size={11} className="text-accent-emerald shrink-0" strokeWidth={2.5} />
                      ) : log.active ? (
                        <Loader2 size={11} className="text-accent-cyan animate-spin shrink-0" />
                      ) : (
                        <span className="w-2.5 h-2.5 rounded-full border border-white/20 shrink-0 inline-block" />
                      )}
                      <span className={log.active ? 'text-accent-cyan font-medium' : log.done ? 'text-slate-200' : 'text-slate-400'}>
                        {log.text}
                      </span>
                    </span>
                  </div>
                ))}
                {isFixing && (
                  <div className="text-accent-cyan text-[11px] flex items-center gap-1.5 animate-pulse pt-0.5">
                    <span>&gt;</span> <span>executing in-process synthesis &amp; adversarial verification…</span>
                  </div>
                )}
                {isSettled && (
                  <div className="text-terminal-muted text-[10px] pt-1 border-t border-white/5 flex items-center justify-between">
                    <span>Audit trail recorded</span>
                    <span className={isVerified ? 'text-accent-emerald font-semibold' : 'text-accent-amber'}>
                      ● {isVerified ? 'PASSED & ACTIVE' : isFailed ? 'FAILED' : 'NEEDS REVIEW'}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Verification Card — every claim below is derived from the
              backend's structured verification fields (deterministicVerification /
              aiVerification), never inferred purely from the coarse `isVerified`
              flag, so the badges can't overstate what was actually checked. */}
          {(isVerified || isNeedsReview || isSettled || fixStatus?.details) && (
            <div className={`rounded-xl border p-3.5 space-y-2 font-mono text-xs ${
              isVerified
                ? 'border-accent-emerald/30 bg-accent-emerald-soft/10'
                : 'border-accent-amber/30 bg-accent-amber-soft/10'
            }`}>
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-default/60 pb-2">
                <div className="flex items-center gap-1.5 font-semibold text-text-primary">
                  <ShieldCheck size={14} className={isVerified ? 'text-accent-emerald' : 'text-accent-amber'} />
                  <span>{verifyModelLabel}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-bold ${
                    fixStatus?.deterministicVerification?.status === 'PASSED'
                      ? 'bg-bg-card border-border-default text-accent-cyan'
                      : fixStatus?.deterministicVerification?.status === 'FAILED'
                        ? 'bg-accent-rose-soft border-accent-rose/30 text-accent-rose'
                        : 'bg-bg-card border-border-default text-text-muted'
                  }`}>
                    Deterministic Rescan:{' '}
                    {fixStatus?.deterministicVerification?.status === 'PASSED'
                      ? 'Passed'
                      : fixStatus?.deterministicVerification?.status === 'FAILED'
                        ? 'Failed'
                        : 'Not Reported'}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-bold ${
                    isVerified
                      ? 'bg-accent-emerald-soft text-accent-emerald border-accent-emerald/30'
                      : 'bg-accent-amber-soft text-accent-amber border-accent-amber/30'
                  }`}>
                    {isVerified ? 'Fix Verified' : 'Manual Review Advised'}
                  </span>
                </div>
              </div>

              <div className="text-text-secondary text-xs leading-relaxed space-y-2">
                <div>
                  {fixStatus?.details || 'Deterministic AST re-scanner and AI verification model independently evaluated post-fix code.'}
                </div>

                {/* Granular verification & risk breakdown from FixResponse v2 */}
                {(fixStatus?.aiVerification || fixStatus?.deterministicVerification || fixStatus?.riskEvaluation) && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 border-t border-border-default/40">
                    {/* Deterministic Re-scan */}
                    <div className="p-2 rounded bg-bg-card/70 border border-border-default">
                      <div className="text-[10px] text-text-muted uppercase tracking-wider">Deterministic SAST</div>
                      <div className="font-semibold text-text-primary flex items-center gap-1 mt-0.5">
                        {fixStatus.deterministicVerification?.status === 'PASSED' ? (
                          <span className="text-accent-emerald flex items-center gap-1">
                            <CheckCircle2 size={11} /> 0 Matches (Clean)
                          </span>
                        ) : fixStatus.deterministicVerification?.status === 'FAILED' ? (
                          <span className="text-accent-rose flex items-center gap-1">
                            <AlertTriangle size={11} /> Rule Still Matches
                          </span>
                        ) : (
                          <span className="text-text-muted">Not Verified</span>
                        )}
                      </div>
                    </div>

                    {/* AI Verifier / Codex Review */}
                    <div className="p-2 rounded bg-bg-card/70 border border-border-default">
                      <div className="text-[10px] text-text-muted uppercase tracking-wider">AI Verifier Review</div>
                      <div className="font-semibold text-text-primary flex items-center gap-1 mt-0.5">
                        {fixStatus.aiVerification?.status === 'PASSED' ? (
                          <span className="text-accent-emerald flex items-center gap-1">
                            <CheckCircle2 size={11} /> 0 Regressions
                          </span>
                        ) : fixStatus.aiVerification?.status === 'FAILED' ? (
                          <span className="text-accent-rose flex items-center gap-1">
                            <AlertTriangle size={11} /> Needs Review
                          </span>
                        ) : (
                          <span className="text-text-muted">Not Reviewed</span>
                        )}
                        {fixStatus.aiVerification?.confidence && (
                          <span className="text-[10px] font-mono text-text-muted">
                            ({Math.round(fixStatus.aiVerification.confidence * 100)}%)
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Risk Engine Delta */}
                    <div className="p-2 rounded bg-bg-card/70 border border-border-default">
                      <div className="text-[10px] text-text-muted uppercase tracking-wider">Risk Reduction</div>
                      <div className="font-semibold text-accent-emerald flex items-center gap-1 mt-0.5">
                        {fixStatus.riskEvaluation?.reductionPct != null ? (
                          <span>↓ {Math.round(fixStatus.riskEvaluation.reductionPct)}% Reduced</span>
                        ) : isVerified ? (
                          <span className="text-text-muted">Not Reported</span>
                        ) : (
                          <span className="text-text-muted">Pending</span>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Model attribution — which model actually generated the fix
                  and which performed the independent Codex review. Featherless
                  primary shows a teal badge, a fallback answer shows the amber
                  "Fallback — <model>" badge (model_router.py). */}
              {(fixStatus?.fixModel || fixStatus?.verifyModel) && (
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  {fixStatus?.fixModel && (
                    <ModelBadge task="Fix" model={fixStatus.fixModel} provider={fixStatus.fixProvider} size="xs" />
                  )}
                  {fixStatus?.verifyModel && (
                    <ModelBadge task="Codex" model={fixStatus.verifyModel} provider={fixStatus.verifyProvider} size="xs" />
                  )}
                </div>
              )}

              {fixStatus?.pullRequest ? (
                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[11px] text-text-muted">Target branch updated:</span>
                  <a
                    href={fixStatus.pullRequest.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-bold text-accent-cyan hover:underline"
                  >
                    <GitPullRequest size={12} />
                    View PR #{fixStatus.pullRequest.number} on GitHub <ExternalLink size={10} />
                  </a>
                </div>
              ) : isVerified && scanId && (fixStatus?.fixBranch || finding.suggestedFix) ? (
                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[11px] text-text-muted">
                    {fixStatus?.fixBranch ? `Branch: ${fixStatus.fixBranch}` : 'Patch verified, PR pending'}
                  </span>
                  <button
                    type="button"
                    onClick={handleCreatePr}
                    disabled={creatingPr}
                    className="inline-flex items-center gap-1 text-xs font-bold text-accent-cyan hover:underline disabled:opacity-50"
                  >
                    {creatingPr ? <Loader2 size={11} className="animate-spin" /> : <GitPullRequest size={11} />}
                    {creatingPr ? 'Opening…' : 'Create PR on GitHub'}
                  </button>
                </div>
              ) : null}

              {(fixStatus?.jiraTicket || finding.jiraTicket) && (
                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[11px] text-text-muted">Jira issue:</span>
                  <a
                    href={(fixStatus?.jiraTicket || finding.jiraTicket)!.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-bold text-[#0052CC] dark:text-[#4c9aff] hover:underline"
                  >
                    <ExternalLink size={11} />
                    Jira {(fixStatus?.jiraTicket || finding.jiraTicket)!.key}
                  </a>
                </div>
              )}
            </div>
          )}

          {/* RAG Memory Trace */}
          <RagMemoryTrace
            ragMemoryEnabled={ragMemoryEnabled}
            phase={fixStatus?.phase}
            settled={isSettled}
            similarPastFixes={fixStatus?.similarPastFixes}
          />
        </div>
      )}

      {/* Suggested Solution & Diff Box */}
      <div className="pt-3 border-t border-border-default">
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => setDiffExpanded((prev) => !prev)}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
          >
            <Code2 size={13} className="text-accent-cyan" />
            <span>Remediation Patch Diff</span>
            {diffExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>

          {diffExpanded && patchDiff && (
            <button
              type="button"
              onClick={copyPatch}
              className="inline-flex items-center gap-1 text-[11px] font-mono text-accent-cyan hover:underline transition-colors"
            >
              {copiedPatch ? <Check size={11} className="text-accent-emerald" /> : <Copy size={11} />}
              {copiedPatch ? 'Copied' : 'Copy Unified Diff'}
            </button>
          )}
        </div>

        {diffExpanded && (
          <div className="mt-3 rounded-xl bg-terminal-bg border border-white/10 p-4 font-mono text-xs overflow-x-auto animate-fade-rise-in">
            {patchDiff ? (
              <>
                <div className="text-[11px] text-terminal-muted pb-2 border-b border-white/10 mb-2 flex items-center justify-between">
                  <span>patchline_remediation.diff</span>
                  <span className="text-accent-cyan">{fixStatus?.fixModel ? `${fixStatus.fixModel} Synthesized` : 'AI Synthesized'}</span>
                </div>
                <pre className="text-terminal-text leading-relaxed">
                  {patchDiff.split('\n').map((line, idx) => {
                    const isDel = line.startsWith('-');
                    const isAdd = line.startsWith('+');
                    const isHunk = line.startsWith('@@');

                    return (
                      <div
                        key={idx}
                        className={`px-1.5 py-0.5 rounded ${
                          isDel
                            ? 'bg-accent-rose-soft/80 text-accent-rose-strong'
                            : isAdd
                              ? 'bg-accent-emerald-soft/80 text-accent-emerald-strong'
                              : isHunk
                                ? 'text-accent-cyan font-bold'
                                : 'text-terminal-muted'
                        }`}
                      >
                        {line}
                      </div>
                    );
                  })}
                </pre>
              </>
            ) : (
              <div className="text-terminal-muted py-2 text-center">
                No generated patch available yet.
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
