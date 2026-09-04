'use client';

import { Suspense, useEffect, useState, useCallback, useRef } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Radar,
  GitBranch,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  Loader2,
  Sparkles,
  Search,
  Filter,
  CheckCircle2,
  X,
  History,
  FolderGit2,
  ExternalLink,
} from 'lucide-react';
import ProtectedShell from '@/components/ProtectedShell';
import Card from '@/components/ui/Card';
import Badge from '@/components/ui/Badge';
import Button from '@/components/ui/Button';
import EmptyState from '@/components/ui/EmptyState';
import ErrorBanner from '@/components/ErrorBanner';
import ScanSkeleton from '@/components/ScanSkeleton';
import ScanPipeline, { PIPELINE_STAGES } from '@/components/scanner/ScanPipeline';
import FindingCard, { Finding, FixStatus } from '@/components/scanner/FindingCard';
import VulnerabilityDetail from '@/components/scanner/VulnerabilityDetail';
import VulnerabilityTimeline from '@/components/scanner/VulnerabilityTimeline';
import RepoSelectDropdown, { RepoItem } from '@/components/scanner/RepoSelectDropdown';
import { useToast } from '@/components/ToastNotification';
import { scannerApi, githubApi } from '@/lib/api';

// Coarse scan `status` → pipeline stage index (0-indexed into PIPELINE_STAGES,
// which now has exactly 6 entries — one per step ai-storage-service actually
// executes; see ScanPipeline.tsx). Only QUEUED/PROCESSING/terminal are ever
// actually written to scan:record:{scanId} by main-service's worker (see
// workers/scannerWorkers.js) — everything between "processing started" and
// "processing finished" comes from the real `stage` field below, not this map.
const STATUS_TO_STAGE: Record<string, number> = {
  QUEUED: 0,
  PROCESSING: 1,
  COMPLETED_WAITING_APPROVAL: 5,
  COMPLETED: 5,
  SCAN_FAILED: 5,
};

// Real, backend-confirmed checkpoint (ai-storage-service's
// app/services/scan_progress.py SCAN_STAGES, read via
// GET /api/scanner/status/:scanId's `stage` field) → pipeline stage index.
// This is the only thing that should ever move the indicator past index 1
// while a scan is still in flight — nothing here is estimated or animated.
const STAGE_TO_INDEX: Record<string, number> = {
  REPO_FETCHED: 1,
  DETERMINISTIC_SCAN: 2,
  AI_ANALYSIS: 3,
  RISK_ENGINE: 4,
};


type ScanResult = {
  scanId: string;
  status: string;
  repo: string;
  branch?: string;
  findingsCount: number;
  findings: Finding[];
  blobUri?: string;
  fixBranch?: string;
  fixedAt?: string;
  ragMemoryEnabled?: boolean;
  scanTier?: string;
  aiAnalysisNote?: string;
  pullRequest?: { number: number; url: string };
  jiraTicket?: { key: string; id?: string; url: string } | null;
  fixes?: Record<string, {
    status: string;
    attempts?: number;
    verified?: boolean;
    fixBranch?: string;
    summary?: string;
    details?: string;
    similarPastFixes?: any[];
    pullRequest?: { number: number; url: string };
    error?: string;
  }>;
};

const DEFAULT_DEMO_REPOS: RepoItem[] = [
  {
    id: 1,
    fullName: 'octocat/secure-api',
    private: false,
    url: 'https://github.com/octocat/secure-api',
    description: 'Sample Node.js REST API with SQL & template endpoints',
    defaultBranch: 'main',
  },
  {
    id: 2,
    fullName: 'acme/core-gateway',
    private: true,
    url: 'https://github.com/acme/core-gateway',
    description: 'Core authentication gateway and token verification service',
    defaultBranch: 'main',
  },
  {
    id: 3,
    fullName: 'enterprise/payment-hub',
    private: true,
    url: 'https://github.com/enterprise/payment-hub',
    description: 'Stripe webhook and billing reconciliation microservice',
    defaultBranch: 'develop',
  },
  {
    id: 4,
    fullName: 'patchline/telemetry-engine',
    private: false,
    url: 'https://github.com/patchline/telemetry-engine',
    description: 'Real-time security telemetry and event stream aggregator',
    defaultBranch: 'prod',
  },
];

const REPO_REGEX = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/;

export default function ScannerPage() {
  return (
    <Suspense fallback={<ScanSkeleton />}>
      <ScannerView />
    </Suspense>
  );
}

function ScannerView() {
  const [repoInput, setRepoInput] = useState('');
  const [branchInput, setBranchInput] = useState('main');
  const [repoError, setRepoError] = useState<string | null>(null);

  const [scanning, setScanning] = useState(false);
  const [activeStage, setActiveStage] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [fixStates, setFixStates] = useState<Record<string, FixStatus>>({});
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [aiProvider, setAiProvider] = useState<{
    currentProvider?: string;
    currentModel?: string;
    verifierProvider?: string;
    verifierModel?: string;
  } | null>(null);

  const [userRepos, setUserRepos] = useState<RepoItem[]>([]);
  const [githubConnected, setGithubConnected] = useState<boolean | null>(null);
  const { addToast } = useToast();
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  // One self-rescheduling poll timer per in-flight fix (findingId → timer),
  // so approving multiple findings concurrently (handleFixAllVulnerabilities)
  // doesn't have separate polls stomp on a single shared ref.
  const fixPollTimersRef = useRef<Record<string, NodeJS.Timeout>>({});

  const searchParams = useSearchParams();
  const paramRepo = searchParams.get('repo');
  const paramBranch = searchParams.get('branch');
  const paramScanId = searchParams.get('scanId');

  useEffect(() => {
    if (paramRepo) setRepoInput(paramRepo);
    if (paramBranch) setBranchInput(paramBranch);
  }, [paramRepo, paramBranch]);

  // Load existing scan from URL scanId if present
  useEffect(() => {
    if (!paramScanId) return;
    scannerApi
      .status(paramScanId)
      .then(({ data }) => {
        setScanResult({ scanId: paramScanId, ...data } as ScanResult);
        setActiveStage(5); // 6-stage pipeline (0-5) — 5 is "Awaiting Approval"
        if (data.fixes) {
          const mapped: Record<string, FixStatus> = {};
          Object.entries(data.fixes).forEach(([fId, fix]: [string, any]) => {
            mapped[fId] = {
              phase: fix.status === 'FIX_VERIFIED' ? 'VERIFIED'
                   : fix.status === 'FIX_NEEDS_REVIEW' ? 'NEEDS_REVIEW'
                   : fix.status === 'FIX_UNRESOLVED' ? 'UNRESOLVED'
                   : fix.status === 'FIX_FAILED' ? 'FAILED'
                   : fix.status === 'FIX_PROCESSING' || fix.status === 'FIX_QUEUED' ? 'PROCESSING'
                   : null,
              fixBranch: fix.fixBranch,
              summary: fix.summary,
              details: fix.details,
              similarPastFixes: fix.similarPastFixes,
              pullRequest: fix.pullRequest,
              jiraTicket: fix.jiraTicket,
              error: fix.error,
              attempts: fix.attempts,
              ragMemoryEnabled: data.ragMemoryEnabled ?? true,
              fixModel: fix.model,
              fixProvider: fix.provider,
              verifyModel: fix.codexReview?.model,
              verifyProvider: fix.codexReview?.provider,
              aiVerification: fix.aiVerification ?? null,
              deterministicVerification: fix.deterministicVerification ?? null,
              riskEvaluation: fix.riskEvaluation ?? null,
            };
          });
          setFixStates(mapped);
        }
      })
      .catch((err) => {
        setError(
          err?.response?.data?.error?.message ||
            `Could not load scan ${paramScanId}. It may have expired or does not exist.`
        );
      });
  }, [paramScanId]);

  // Check GitHub connection and fetch repos
  useEffect(() => {
    githubApi
      .status()
      .then(({ data }) => {
        setGithubConnected(data.connected ?? false);
        if (data.connected) {
          return githubApi.listRepos();
        } else {
          setUserRepos([]);
        }
      })
      .then((res) => {
        if (res?.data) {
          const raw = res.data;
          const list = Array.isArray(raw)
            ? raw
            : Array.isArray(raw?.repos)
              ? raw.repos
              : [];
          setUserRepos(list);
          if (list.length > 0) {
            setRepoInput((prev) => (!prev || prev === 'octocat/secure-api' ? list[0].fullName : prev));
            if (list[0].defaultBranch) {
              setBranchInput((prev) => (prev === 'main' ? list[0].defaultBranch! : prev));
            }
          }
        }
      })
      .catch(() => {
        setGithubConnected(false);
        setUserRepos([]);
      });
  }, []);

  // Fetch live AI provider info on mount
  useEffect(() => {
    scannerApi.aiProviderStatus()
      .then(({ data }) => setAiProvider(data))
      .catch(() => setAiProvider(null));
  }, []);

  // Clean up timer on unmount
  useEffect(() => {
    const fixTimers = fixPollTimersRef.current;
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      Object.values(fixTimers).forEach((t) => clearTimeout(t));
    };
  }, []);

  // Poll status endpoint until finished.
  //
  // IMPORTANT: this only ever moves `activeStage` forward using (a) the
  // coarse `status` field (QUEUED/PROCESSING/terminal — see STATUS_TO_STAGE)
  // or (b) the real, backend-confirmed `stage` field ai-storage-service
  // writes as it actually completes each pipeline step (see STAGE_TO_INDEX
  // and services/ai_sevices/app/services/scan_progress.py). There is no
  // client-side timer pretending to be progress anymore — a scan on a large
  // repo genuinely spends most of its time in one real stage (e.g. AI
  // Analysis), and the UI now reflects that honestly instead of sailing
  // through 6 fabricated stages every ~11 seconds regardless of what's
  // actually happening.
  const startPolling = useCallback((scanId: string, repo: string, branch: string) => {
    let elapsedMs = 0;
    // Matches main-service's own configured budget for this call (see
    // env.timeouts.scan=180000ms × attempts:2 + backoff, in scanTriggerService.js
    // / workers/scannerWorkers.js) — the client must never give up before the
    // backend's own worst-case bounded retry budget could plausibly finish.
    const FAST_INTERVAL_MS = 2500;
    const SLOW_INTERVAL_MS = 8000;
    const SWITCH_TO_SLOW_AFTER_MS = 90_000; // stay responsive for the common case
    const OUTER_CEILING_MS = 8 * 60 * 1000; // covers 2 attempts × 180s + backoff, with margin

    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    let consecutiveErrors = 0;

    const poll = async () => {
      elapsedMs += elapsedMs < SWITCH_TO_SLOW_AFTER_MS ? FAST_INTERVAL_MS : SLOW_INTERVAL_MS;

      try {
        const { data } = await scannerApi.status(scanId);

        // Real backend checkpoint first (most specific); fall back to the
        // coarse status. Never move the indicator backward.
        const stageFromCheckpoint = data.stage ? STAGE_TO_INDEX[data.stage] : undefined;
        const stageFromStatus = STATUS_TO_STAGE[data.status ?? ''];
        const nextStage = stageFromCheckpoint ?? stageFromStatus;
        if (nextStage !== undefined) {
          setActiveStage((prev) => Math.max(prev, nextStage));
        }

        if (data.status === 'COMPLETED_WAITING_APPROVAL' || data.status === 'COMPLETED' || data.findings) {
          if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
          setActiveStage(5);
          setScanning(false);
          setScanResult({
            scanId,
            repo,
            branch,
            status: data.status || 'COMPLETED_WAITING_APPROVAL',
            findingsCount: data.findingsCount ?? (data.findings?.length || 0),
            findings: data.findings || [],
            blobUri: data.blobUri,
            fixes: data.fixes,
            ragMemoryEnabled: data.ragMemoryEnabled ?? true,
            scanTier: data.scanTier,
            aiAnalysisNote: data.aiAnalysisNote,
          });


          // Sync existing fix states — map all backend fix fields including verification
          if (data.fixes) {
            const mapped: Record<string, FixStatus> = {};
            Object.entries(data.fixes).forEach(([fId, fix]: [string, any]) => {
              mapped[fId] = {
                phase: fix.status === 'FIX_VERIFIED' ? 'VERIFIED'
                     : fix.status === 'FIX_NEEDS_REVIEW' ? 'NEEDS_REVIEW'
                     : fix.status === 'FIX_UNRESOLVED' ? 'UNRESOLVED'
                     : fix.status === 'FIX_FAILED' ? 'FAILED'
                     : fix.status === 'FIX_PROCESSING' || fix.status === 'FIX_QUEUED' ? 'PROCESSING'
                     : null,
                fixBranch: fix.fixBranch,
                summary: fix.summary,
                details: fix.details,
                similarPastFixes: fix.similarPastFixes,
                pullRequest: fix.pullRequest,
                error: fix.error,
                attempts: fix.attempts,
                ragMemoryEnabled: data.ragMemoryEnabled ?? true,
                fixModel: fix.model,
                fixProvider: fix.provider,
                verifyModel: fix.codexReview?.model,
                verifyProvider: fix.codexReview?.provider,
                // Backend verification structures (FixResponse v2)
                aiVerification: fix.aiVerification ?? null,
                deterministicVerification: fix.deterministicVerification ?? null,
                riskEvaluation: fix.riskEvaluation ?? null,
              };
            });
            setFixStates(mapped);
          }

          addToast({
            type: data.findings?.length > 0 ? 'warning' : 'success',
            title: `Scan Completed: ${data.findings?.length || 0} findings`,
            message: data.findings?.length > 0 ? 'Review findings below and authorize automated patches.' : 'Zero security vulnerabilities detected.',
          });
          return; // terminal — stop scheduling further polls
        } else if (data.status === 'SCAN_FAILED') {
          if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
          setScanning(false);
          setError(data.error || 'Scan analysis failed during background processing.');
          return; // terminal — backend actually reported failure, this one IS honest
        }
        consecutiveErrors = 0;
      } catch (err: any) {
        // Only stop polling after 10 consecutive gateway failures — a single
        // blip (e.g. a deploy restarting main-service) shouldn't abandon an
        // otherwise-healthy background scan.
        consecutiveErrors += 1;
        if (consecutiveErrors >= 10) {
          if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
          setScanning(false);
          setError(
            err?.response?.data?.error?.message ||
            'Unable to reach backend gateway. Please check that main-service and redis are running.'
          );
          return;
        }
      }

      if (elapsedMs >= OUTER_CEILING_MS) {
        // We are stopping OUR OWN polling — this is not a claim that the
        // backend job failed. It may still be legitimately retrying (bounded
        // by the same job-level `attempts` main-service's worker was
        // configured with). Say so honestly instead of a bare "scan failed".
        if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
        setScanning(false);
        setError(
          `Still waiting on the backend after ${Math.round(OUTER_CEILING_MS / 60000)} minutes — the scan job may ` +
          'still be running. Reload this page with the same scan ID in the URL to check its latest status, or launch a new scan.'
        );
        return;
      }

      pollTimerRef.current = setTimeout(poll, elapsedMs < SWITCH_TO_SLOW_AFTER_MS ? FAST_INTERVAL_MS : SLOW_INTERVAL_MS);
    };

    pollTimerRef.current = setTimeout(poll, FAST_INTERVAL_MS);
  }, [addToast]);

  // Launch scan handler with double-click guard and regex validation
  const handleLaunchScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (scanning) return;

    if (!REPO_REGEX.test(repoInput.trim())) {
      setRepoError('Please specify repository in valid format: owner/repository');
      return;
    }

    setRepoError(null);
    setScanning(true);
    setError(null);
    setActiveStage(0);

    const [owner, name] = repoInput.split('/');

    try {
      const res = await scannerApi.scan({
        repoOwner: owner,
        repoName: name,
        branch: branchInput || 'main',
      });

      const scanId = res.data?.scanId;
      if (!scanId) {
        // The backend responded but didn't hand back a scan ID — there is
        // nothing real to poll. Surface this honestly instead of inventing
        // an ID and polling a scan that was never actually queued.
        setScanning(false);
        setError('Scan request succeeded but the backend did not return a scan ID. Please try again.');
        return;
      }
      startPolling(scanId, repoInput, branchInput);
    } catch (err: any) {
      // The scan was never actually queued on the backend — say so, rather
      // than fabricating a scanId and polling a scan that doesn't exist
      // (which would just spin/404 forever while looking like progress).
      setScanning(false);
      setError(
        err?.response?.data?.error?.message ||
        err?.message ||
        'Failed to launch scan. Please check that main-service is reachable and try again.'
      );
    }
  };

  // Human approval action handler with live status polling.
  //
  // Correctness contract: this poller must NEVER set phase:'FAILED' or
  // phase:'UNRESOLVED' unless the BACKEND actually reported that status.
  // Previously it hard-declared FAILED after exactly 60s (40 polls × 1.5s)
  // regardless of what the backend was doing — but main-service's own
  // configured budget for this call is up to 150s × 3 attempts with
  // exponential backoff (workers/scannerWorkers.js env.timeouts.fix +
  // BullMQ job opts), so a fix that was still legitimately working (or had
  // already verified) was being shown to the user as failed. If our own
  // polling window elapses, we say so honestly via
  // `stillProcessingInBackground` instead of lying about the outcome.
  const handleApproveAndFix = async (findingId: string) => {
    setFixStates((prev) => ({
      ...prev,
      [findingId]: {
        phase: 'PROCESSING',
        attempts: (prev[findingId]?.attempts || 0) + 1,
        summary: 'Synthesizing minimal, syntax-accurate patch on isolated branch…',
        ragMemoryEnabled: scanResult?.ragMemoryEnabled ?? true,
      },
    }));

    try {
      if (scanResult?.scanId) {
        await scannerApi.approveAndFix({
          scanId: scanResult.scanId,
          findingId,
        });
      }

      const FAST_INTERVAL_MS = 1500;
      const SLOW_INTERVAL_MS = 5000;
      const SWITCH_TO_SLOW_AFTER_MS = 60_000;
      // Covers main-service's own worst case: 3 attempts × 150s upstream
      // timeout + exponential backoff between them, with margin.
      const OUTER_CEILING_MS = 8 * 60 * 1000;

      let elapsedMs = 0;
      let consecutiveErrors = 0;

      if (fixPollTimersRef.current[findingId]) clearTimeout(fixPollTimersRef.current[findingId]);

      const poll = async () => {
        elapsedMs += elapsedMs < SWITCH_TO_SLOW_AFTER_MS ? FAST_INTERVAL_MS : SLOW_INTERVAL_MS;

        try {
          if (scanResult?.scanId) {
            const { data } = await scannerApi.status(scanResult.scanId);
            const fixData = data.fixes?.[findingId];
            // FIX_UNRESOLVED: every bounded attempt exhausted, terminal,
            // NOT retryable — must be its own case, not lumped into FAILED
            // (previously this fell through to the 'PROCESSING' default
            // below and would poll/spin forever, since the backend will
            // never move it any further).
            if (
              fixData &&
              (fixData.status === 'FIX_VERIFIED' ||
                fixData.status === 'FIX_NEEDS_REVIEW' ||
                fixData.status === 'FIX_FAILED' ||
                fixData.status === 'FIX_UNRESOLVED')
            ) {
              delete fixPollTimersRef.current[findingId];
              setFixStates((prev) => ({
                ...prev,
                [findingId]: {
                  phase: fixData.status === 'FIX_VERIFIED' ? 'VERIFIED'
                       : fixData.status === 'FIX_NEEDS_REVIEW' ? 'NEEDS_REVIEW'
                       : fixData.status === 'FIX_UNRESOLVED' ? 'UNRESOLVED'
                       : 'FAILED',
                  fixBranch: fixData.fixBranch,
                  summary: fixData.summary,
                  details: fixData.details,
                  pullRequest: fixData.pullRequest,
                  error: fixData.error,
                  attempts: fixData.attempts || (prev[findingId]?.attempts || 1),
                  similarPastFixes: fixData.similarPastFixes || [],
                  ragMemoryEnabled: data.ragMemoryEnabled ?? true,
                  fixModel: fixData.model,
                  fixProvider: fixData.provider,
                  verifyModel: fixData.codexReview?.model,
                  verifyProvider: fixData.codexReview?.provider,
                  // Structured verification results from FixResponse v2
                  aiVerification: fixData.aiVerification ?? null,
                  deterministicVerification: fixData.deterministicVerification ?? null,
                  riskEvaluation: fixData.riskEvaluation ?? null,
                },
              }));

              addToast({
                type: fixData.status === 'FIX_VERIFIED' ? 'success' : 'warning',
                title: fixData.status === 'FIX_VERIFIED' ? 'Fix Verified'
                     : fixData.status === 'FIX_UNRESOLVED' ? 'Manual Review Required'
                     : 'Fix Needs Review',
                message: fixData.status === 'FIX_VERIFIED'
                  ? `Pull Request generated for ${findingId}.`
                  : fixData.status === 'FIX_UNRESOLVED'
                  ? `All bounded remediation attempts exhausted for ${findingId} — a human needs to fix this one directly.`
                  : `Patch generated but flagged for human review.`,
              });
              return; // terminal — stop scheduling further polls
            }

            // Still in flight (FIX_QUEUED/FIX_PROCESSING, or no fix record
            // written yet): surface the real backend checkpoint — stage
            // (scan_progress.py's FIX_STAGES, via GET status's `stage`
            // field) and the bounded attempt counter — instead of a static
            // "Synthesizing…" string that never changes for however long
            // the request actually takes. Never fabricate a stage; if the
            // backend hasn't reported one yet, leave it undefined and let
            // FindingCard fall back to its own generic "in progress" copy.
            setFixStates((prev) => ({
              ...prev,
              [findingId]: {
                ...prev[findingId],
                phase: 'PROCESSING',
                stage: data.stage ?? null,
                attempts: fixData?.attempts || prev[findingId]?.attempts || 1,
              },
            }));
          }
          consecutiveErrors = 0;
        } catch {
          // Transient poll error — don't abandon an otherwise-healthy fix
          // job over one blip, but do stop eventually so a truly dead
          // gateway doesn't poll forever.
          consecutiveErrors += 1;
          if (consecutiveErrors >= 10) {
            delete fixPollTimersRef.current[findingId];
            setFixStates((prev) => ({
              ...prev,
              [findingId]: {
                ...prev[findingId],
                phase: 'PROCESSING',
                stillProcessingInBackground: true,
              },
            }));
            return;
          }
        }

        if (elapsedMs >= OUTER_CEILING_MS) {
          // Our own polling window elapsed — this is NOT the backend
          // reporting failure. Say so honestly; never write phase:'FAILED'
          // here. The finding may still verify, need review, or genuinely
          // fail — the browser just isn't going to wait to find out.
          delete fixPollTimersRef.current[findingId];
          setFixStates((prev) => ({
            ...prev,
            [findingId]: {
              ...prev[findingId],
              phase: 'PROCESSING',
              stillProcessingInBackground: true,
            },
          }));
          return;
        }

        fixPollTimersRef.current[findingId] = setTimeout(
          poll,
          elapsedMs < SWITCH_TO_SLOW_AFTER_MS ? FAST_INTERVAL_MS : SLOW_INTERVAL_MS
        );
      };

      fixPollTimersRef.current[findingId] = setTimeout(poll, FAST_INTERVAL_MS);
    } catch (err: any) {
      setFixStates((prev) => ({

        ...prev,
        [findingId]: {
          phase: 'FAILED',
          error: err?.response?.data?.error?.message || err.message,
          attempts: (prev[findingId]?.attempts || 1),
        },
      }));
    }
  };

  const handleFixAllVulnerabilities = async () => {
    if (!scanResult || !scanResult.findings || scanResult.findings.length === 0) return;
    // UNRESOLVED is terminal and NOT retryable — the backend's state
    // machine rejects any further FIX_QUEUED transition for it with 409
    // FIX_ATTEMPTS_EXHAUSTED (see state_machine.py), so including it here
    // would just fire a doomed request. NEEDS_REVIEW/FAILED are genuinely
    // retryable and stay eligible for a batch re-attempt.
    const unfixed = scanResult.findings.filter(
      (f) =>
        !fixStates[f.id] ||
        (fixStates[f.id].phase !== 'VERIFIED' &&
          fixStates[f.id].phase !== 'PROCESSING' &&
          fixStates[f.id].phase !== 'UNRESOLVED')
    );
    if (unfixed.length === 0) {
      addToast({
        type: 'info',
        title: 'All Fixes In Progress or Complete',
        message: 'All identified vulnerabilities have already been fixed or are currently synthesizing.',
      });
      return;
    }
    addToast({
      type: 'success',
      title: `Batch AI Fix Triggered (${unfixed.length} vulnerabilities)`,
      message: `Synthesizing patches for ${unfixed.length} vulnerability findings simultaneously.`,
    });
    for (const f of unfixed) {
      handleApproveAndFix(f.id);
    }
  };

  return (
    <ProtectedShell>
      {/* Page Header */}
      <div className="flex flex-wrap items-end justify-between gap-4 mb-8">
        <div>
          <div className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-accent-cyan mb-1.5">
            <span className="w-2 h-2 rounded-full bg-accent-cyan pulse-dot" />
            Live Security Analysis
          </div>
          <h1 className="font-display text-2xl md:text-3xl font-bold text-text-primary">
            Autonomous Vulnerability Scanner
          </h1>
          <p className="text-text-secondary text-sm mt-1">
            {aiProvider
              ? <>6-stage SAST + AI fix synthesis via <strong>{aiProvider.currentProvider}</strong> · verifier: <strong>{aiProvider.verifierProvider}</strong></>
              : 'Execute 6-stage deterministic SAST + AI patch synthesis & verification.'}
          </p>
        </div>

        <Link href="/scanner/history">
          <Button variant="secondary" size="sm" className="gap-1.5 font-mono">
            <History size={13} /> Scan History
          </Button>
        </Link>
      </div>

      {error && (
        <ErrorBanner
          message={error}
          category="GATEWAY"
          onRetry={handleLaunchScan}
          className="mb-6"
        />
      )}

      {/* 1. Validated Scan Launch Form with Repository Dropdown */}
      <Card className="p-5 mb-8">
        <form onSubmit={handleLaunchScan} className="space-y-4">
          <div className="flex flex-col md:flex-row items-stretch md:items-end gap-3">
            {/* Repository Select Dropdown */}
            <div className="flex-1 min-w-[280px] space-y-1.5">
              <label className="text-xs font-mono uppercase tracking-wider text-text-muted flex items-center justify-between">
                <span>Target Repository</span>
                {userRepos.length > 0 ? (
                  <span className="text-[11px] text-accent-cyan">
                    {userRepos.length} connected
                  </span>
                ) : (
                  <span className="text-[11px] text-text-muted font-mono flex items-center gap-1.5">
                    <Link href="/github" className="text-accent-cyan hover:underline">
                      Connect GitHub
                    </Link>
                    <span>·</span>
                    <button
                      type="button"
                      onClick={() => {
                        setUserRepos(DEFAULT_DEMO_REPOS);
                        setRepoInput(DEFAULT_DEMO_REPOS[0].fullName);
                        setBranchInput(DEFAULT_DEMO_REPOS[0].defaultBranch || 'main');
                      }}
                      className="text-accent-cyan hover:underline"
                    >
                      Use Demo Repo
                    </button>
                  </span>
                )}
              </label>
              <RepoSelectDropdown
                repos={userRepos}
                selectedRepo={repoInput}
                disabled={scanning}
                onSelectRepo={(repoFullName, defaultBranch) => {
                  setRepoInput(repoFullName);
                  if (defaultBranch) setBranchInput(defaultBranch);
                  setRepoError(null);
                }}
              />
            </div>

            {/* Branch Input */}
            <div className="w-full md:w-44 space-y-1.5">
              <label className="text-xs font-mono uppercase tracking-wider text-text-muted">
                Branch Target
              </label>
              <div className="relative">
                <GitBranch size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  type="text"
                  value={branchInput}
                  onChange={(e) => setBranchInput(e.target.value)}
                  placeholder="main"
                  disabled={scanning}
                  className="w-full pl-8 pr-3 py-2.5 rounded-lg bg-bg-subtle border border-border-default focus:border-accent-cyan text-xs font-mono text-text-primary outline-none transition-all disabled:opacity-60"
                />
              </div>
            </div>

            {/* Launch Scan Button with double-click guard and gradient-button effect */}
            <Button
              type="submit"
              variant="gradient"
              disabled={scanning || !repoInput.trim()}
              className="py-2.5 px-6 font-mono text-xs gap-2 shrink-0"
            >
              {scanning ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  Running Pipeline…
                </>
              ) : (
                <>
                  <Play size={13} fill="currentColor" />
                  Launch Scanner
                </>
              )}
            </Button>
          </div>

          {repoError && (
            <p className="text-xs font-mono text-accent-rose animate-fade-rise-in">
              {repoError}
            </p>
          )}
        </form>
      </Card>

      {/* 2. 8-Stage Security Pipeline Stepper */}
      {(scanning || scanResult) && (
        <ScanPipeline
          repo={repoInput}
          branch={branchInput}
          currentStageIndex={activeStage}
          isScanning={scanning}
          aiProvider={aiProvider}
        />
      )}

      {/* 3. Findings & Remediation Grid */}
      {scanResult && (() => {
        const verifiedCount = scanResult.findings.filter((f) => fixStates[f.id]?.phase === 'VERIFIED').length;
        const processingCount = scanResult.findings.filter((f) => fixStates[f.id]?.phase === 'PROCESSING').length;
        const pendingCount = scanResult.findings.length - verifiedCount - processingCount;

        return (
        <div className="space-y-6">
          {/* Remediation Action Banner */}
          <div className="rounded-2xl border border-accent-cyan/30 bg-gradient-to-r from-accent-cyan/10 via-bg-card to-accent-purple/10 p-5 shadow-lg space-y-4 animate-fade-rise-in">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-accent-cyan-soft/60 border border-accent-cyan/30 text-accent-cyan font-mono text-[11px] font-semibold uppercase tracking-wider">
                  <ShieldCheck size={13} />
                  Autonomous Remediation Gate Armed
                </div>
                <h3 className="font-display text-lg font-bold text-text-primary">
                  {verifiedCount === scanResult.findings.length
                    ? 'All Vulnerabilities Verified & Remediated'
                    : `${scanResult.findings.length} Vulnerabilities Detected · Awaiting Human Authorization`}
                </h3>
                <p className="text-xs text-text-secondary max-w-3xl leading-relaxed">
                  Security policy requires developer authorization before AI commits code changes.
                  Authorize patches to generate syntax-accurate fixes on isolated branches, run dual adversarial verification, and submit GitHub Pull Requests.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                {scanResult.jiraTicket?.url && (
                  <a
                    href={scanResult.jiraTicket.url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-2 bg-[#0052CC]/15 border border-[#0052CC]/40 hover:border-[#0052CC] text-[#0052CC] dark:text-[#4c9aff] font-mono text-xs rounded-xl transition-colors inline-flex items-center gap-1.5 font-semibold"
                  >
                    <ExternalLink size={13} /> Jira {scanResult.jiraTicket.key}
                  </a>
                )}

                <Button
                  type="button"
                  onClick={handleFixAllVulnerabilities}
                  disabled={pendingCount === 0 && processingCount > 0}
                  className={`gap-2 font-mono text-xs py-2.5 px-5 shadow-lg flex items-center transition-all ${
                    pendingCount > 0
                      ? 'bg-gradient-to-r from-accent-cyan via-accent-purple to-accent-emerald text-white hover:opacity-95 pulse-ring-active'
                      : ''
                  }`}
                >
                  <Sparkles size={14} />
                  <span>
                    {processingCount > 0 && pendingCount === 0
                      ? `Synthesizing ${processingCount} Patches…`
                      : `Fix All Vulnerabilities (${pendingCount > 0 ? pendingCount : scanResult.findings.length})`}
                  </span>
                </Button>
              </div>
            </div>

            {/* Live Status Flow Pills */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2 border-t border-border-default/50 font-mono text-xs">
              <div className="p-2.5 rounded-xl bg-bg-card/70 border border-border-default flex items-center justify-between">
                <span className="text-text-muted text-[11px]">Total Flaws</span>
                <span className="font-bold text-text-primary">{scanResult.findings.length}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-bg-card/70 border border-border-default flex items-center justify-between">
                <span className="text-text-muted text-[11px]">Awaiting Approval</span>
                <span className={`font-bold ${pendingCount > 0 ? 'text-accent-amber' : 'text-text-muted'}`}>{pendingCount}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-bg-card/70 border border-border-default flex items-center justify-between">
                <span className="text-text-muted text-[11px]">In Synthesis</span>
                <span className={`font-bold ${processingCount > 0 ? 'text-accent-cyan flex items-center gap-1' : 'text-text-muted'}`}>
                  {processingCount > 0 && <Loader2 size={12} className="animate-spin" />}
                  {processingCount}
                </span>
              </div>
              <div className="p-2.5 rounded-xl bg-bg-card/70 border border-border-default flex items-center justify-between">
                <span className="text-text-muted text-[11px]">Verified &amp; PRs</span>
                <span className={`font-bold ${verifiedCount > 0 ? 'text-accent-emerald flex items-center gap-1' : 'text-text-muted'}`}>
                  {verifiedCount > 0 && <CheckCircle2 size={12} />}
                  {verifiedCount}
                </span>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {scanResult.findings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                fixStatus={fixStates[f.id]}
                ragMemoryEnabled={scanResult.ragMemoryEnabled ?? true}
                onApproveAndFix={handleApproveAndFix}
                onViewDeepTimeline={(finding) => setSelectedFinding(finding)}
                scanId={scanResult.scanId}
                onPrCreated={(findingId, pr) => {
                  setFixStates((prev) => ({
                    ...prev,
                    [findingId]: {
                      ...prev[findingId],
                      pullRequest: pr,
                    },
                  }));
                }}
              />
            ))}
          </div>
        </div>
        );
      })()}

      {/* 4. Deep Vulnerability Inspection & 5-Stage Timeline Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl bg-bg-card border border-border-hover shadow-2xl p-6 space-y-6">

            <VulnerabilityDetail
              finding={selectedFinding}
              fixStatus={fixStates[selectedFinding.id]}
              ragMemoryEnabled={scanResult?.ragMemoryEnabled ?? true}
              onClose={() => setSelectedFinding(null)}
            />
            <VulnerabilityTimeline
              finding={selectedFinding}
              fixStatus={fixStates[selectedFinding.id]}
              repo={repoInput}
            />
          </div>
        </div>
      )}
    </ProtectedShell>
  );
}