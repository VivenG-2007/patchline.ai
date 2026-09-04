'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Check,
  Loader2,
  Clock,
  Code2,
  Cpu,
  Terminal,
  ShieldAlert,
  Sparkles,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  X,
  Layers,
} from 'lucide-react';
import Card from '@/components/ui/Card';

export interface PipelineStage {
  id: number;
  name: string;
  shortLabel: string;
  engine: string;
  description: string;
  logs: string[];
}

// Six stages — one per step ai-storage-service's /scan endpoint actually
// executes, in the order it executes them (app/routers/scanner.py). Each
// non-Queued/Awaiting-Approval stage below is backed by a real checkpoint
// written to Redis by app/services/scan_progress.py and surfaced to the
// frontend via GET /api/scanner/status/:scanId's `stage` field — see
// STAGE_TO_INDEX in app/scanner/page.tsx. "logs" here are illustrative of
// what that step does, not literal captured output — no per-run counts
// (file counts, rule counts, confidence percentages) are fabricated.
export const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 1,
    name: 'Queued',
    shortLabel: 'Queue',
    engine: 'Redis BullMQ Worker',
    description: 'Scan job verified, rate limits evaluated, and dispatched to background worker daemon.',
    logs: [
      'Authenticating repository access tokens via GitHub OAuth…',
      'Evaluating rate limits and per-user scan concurrency budget…',
      'BullMQ worker daemon claimed payload from priority queue.',
    ],
  },
  {
    id: 2,
    name: 'Repository Fetch',
    shortLabel: 'Fetch',
    engine: 'GitHub Contents API',
    description: 'Walking the target branch\'s file tree via the GitHub API and collecting scannable source files.',
    logs: [
      'Requesting branch file tree from the GitHub Contents API…',
      'Filtering to scannable source files (vendor/build directories excluded)…',
      'File set collected — handing off to the deterministic scanner.',
    ],
  },
  {
    id: 3,
    name: 'Deterministic Scan',
    shortLabel: 'SAST',
    engine: 'Patchline Pattern Scanner',
    description: 'Running the deterministic pattern-based rule engine against the collected files — the primary, always-on finding source.',
    logs: [
      'Executing deterministic rule set against collected source files…',
      'Matching known-vulnerable patterns (injection, auth, secrets, ...)…',
      'Deterministic pass complete — findings handed to AI enrichment.',
    ],
  },
  {
    id: 4,
    name: 'AI Analysis',
    shortLabel: 'AI Scan',
    engine: 'AI Model Router',
    description: 'AI model explains/enriches each deterministic finding, then runs a supplemental scan (tiered by repo size) for issues pattern rules can\'t catch.',
    logs: [
      'Requesting root-cause explanations for deterministic findings…',
      'Running supplemental AI analysis (tier depends on repository size)…',
      'AI analysis pass complete.',
    ],
  },
  {
    id: 5,
    name: 'Risk Engine',
    shortLabel: 'Risk',
    engine: 'Patchline Risk Engine',
    description: 'Deterministically scoring every finding — risk score, EAL, VaR, exploitability, exposure — and rolling that up into a project-level risk overview.',
    logs: [
      'Computing per-finding risk score, EAL, and VaR…',
      'Aggregating project-level risk overview…',
      'Risk snapshot attached to every finding.',
    ],
  },
  {
    id: 6,
    name: 'Awaiting Approval',
    shortLabel: 'Ready',
    engine: 'Patchline Gatekeeper',
    description: 'Scan artifacts persisted to MongoDB and Azure Blob Storage. Human approval gate armed.',
    logs: [
      'Scan report artifact written to Azure Blob Storage container.',
      'Finding metadata indexed in MongoDB scan_history collection.',
      'Human approval gate armed. Awaiting patch authorization.',
    ],
  },
];


interface ScanPipelineProps {
  currentStageIndex?: number; // 0 to 7
  repo: string;
  branch: string;
  isScanning?: boolean;
  onSelectStage?: (stage: PipelineStage) => void;
  // Live AI provider info from model_router — if provided, stage labels update
  // to show the actual model instead of static placeholder names.
  aiProvider?: {
    currentProvider?: string;
    currentModel?: string;
    verifierProvider?: string;
    verifierModel?: string;
  } | null;
  // Real log lines forwarded from backend stdout markers
  // ([SCAN], [DETERMINISTIC_SCAN], [AI_ANALYSIS], etc.).
  // When absent, falls back to static demo logs.
  liveLogLines?: Record<number, string[]>;
}

export default function ScanPipeline({
  currentStageIndex = 0,
  repo,
  branch,
  isScanning = true,
  onSelectStage,
  aiProvider,
  liveLogLines,
}: ScanPipelineProps) {
  // Merge static stage definitions with live provider info
  const stages = React.useMemo(() => {
    return PIPELINE_STAGES.map((s) => {
      // Stage 4 ("AI Analysis") is the only scan-pipeline step that actually
      // calls the AI model router — the verifier model (Codex) only runs
      // during fix generation/verification, never during a scan, so it has
      // no stage to attach to here.
      if (s.id === 4 && aiProvider?.currentProvider) {
        const model = aiProvider.currentModel || aiProvider.currentProvider;
        return {
          ...s,
          engine: model,
          description: s.description.replace('AI model explains/enriches', `${aiProvider.currentProvider} explains/enriches`),
        };
      }
      return s;
    });
  }, [aiProvider]);

  // selectedStage: auto-follows the active stage while scanning; user can click to override
  const activeStageData = stages[Math.min(currentStageIndex, stages.length - 1)];
  const [userSelectedStage, setUserSelectedStage] = useState<PipelineStage | null>(null);
  const selectedStage = isScanning ? activeStageData : (userSelectedStage ?? activeStageData);

  const [drawerOpen, setDrawerOpen] = useState(true); // default open so logs are visible
  const [visibleLogCount, setVisibleLogCount] = useState(1);
  const [elapsedSec, setElapsedSec] = useState(0);
  const startRef = useRef<number>(Date.now());
  const prevStageRef = useRef<number>(currentStageIndex);

  // Reset timer when scanning starts
  useEffect(() => {
    if (isScanning) {
      startRef.current = Date.now();
      setElapsedSec(0);
    }
  }, [isScanning]);

  // Live elapsed clock
  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - startRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [isScanning]);

  // When active stage advances, reset log reveal and auto-follow
  useEffect(() => {
    if (currentStageIndex !== prevStageRef.current) {
      prevStageRef.current = currentStageIndex;
      setVisibleLogCount(1);
      setUserSelectedStage(null); // snap back to active stage
      setDrawerOpen(true);
    }
  }, [currentStageIndex]);

  // Typewriter-style log reveal: reveal one log line every 900ms during active stage
  useEffect(() => {
    if (!isScanning || !selectedStage) return;
    const maxLogs = (liveLogLines?.[selectedStage.id] ?? selectedStage.logs).length;
    if (visibleLogCount >= maxLogs) return;
    const t = setTimeout(() => setVisibleLogCount((n) => Math.min(n + 1, maxLogs)), 900);
    return () => clearTimeout(t);
  }, [isScanning, selectedStage, visibleLogCount, liveLogLines]);

  const handleStageClick = (stage: PipelineStage) => {
    setUserSelectedStage(stage);
    setDrawerOpen(true);
    if (onSelectStage) onSelectStage(stage);
  };

  // Progress: each completed stage = 1/8 of total
  const progressPercent = isScanning
    ? Math.min(97, Math.round(((currentStageIndex) / PIPELINE_STAGES.length) * 100))
    : 100;


  return (
    <Card className="p-6 mb-8 relative overflow-hidden">
      {/* Decorative scanline glow during scan */}
      {isScanning && <div className="scanline" />}

      {/* Header telemetry info */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-accent-cyan px-2 py-0.5 rounded bg-accent-cyan-soft border border-accent-cyan/30 shadow-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan pulse-dot" />
              6-Stage Security Engine
            </span>
            <span className="font-mono text-xs text-text-muted">
              {repo} ({branch})
            </span>
          </div>
          <h2 className="font-display text-xl font-bold text-text-primary">
            {isScanning ? 'Autonomous Pipeline Processing…' : 'Pipeline Execution Complete'}
          </h2>
        </div>

        <div className="flex items-center gap-4 text-right">
          <div>
            <div className="text-[11px] font-mono text-text-muted uppercase">Duration</div>
            <div className="font-mono text-sm font-semibold text-text-primary flex items-center gap-1 justify-end">
              <Clock size={13} className="text-text-muted" />
              {elapsedSec}s
            </div>
          </div>
          <div>
            <div className="text-[11px] font-mono text-text-muted uppercase">Progress</div>
            <div className="font-display text-2xl font-bold text-accent-cyan tabular-nums">
              {progressPercent}%
            </div>
          </div>
        </div>
      </div>

      {/* 8-Stage Connected Stepper Track */}
      <div className="relative mb-6">
        {/* Continuous background track line */}
        <div className="hidden lg:block absolute top-5 left-6 right-6 h-0.5 bg-border-default -z-0" />
        {/* Active progress fill line */}
        <div
          className="hidden lg:block absolute top-5 left-6 h-0.5 bg-gradient-to-r from-accent-emerald via-accent-cyan to-accent-purple transition-all duration-500 -z-0"
          style={{ width: `${Math.max(0, (currentStageIndex / (PIPELINE_STAGES.length - 1)) * 100)}%` }}
        />

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 sm:gap-3 relative z-10 overflow-x-auto pb-1">
          {stages.map((stage, idx) => {
            const isPipelineFinished = !isScanning || currentStageIndex >= stages.length - 1;
            const isDone = idx < currentStageIndex || (isPipelineFinished && idx <= stages.length - 1);
            const isActive = idx === currentStageIndex && isScanning;
            const isPending = idx > currentStageIndex && !isPipelineFinished;
            const isSelected = selectedStage?.id === stage.id;

            return (
              <button
                key={stage.id}
                type="button"
                onClick={() => handleStageClick(stage)}
                className={`flex flex-col items-center text-center p-3 rounded-xl border transition-all cursor-pointer group ${
                  isSelected
                    ? 'border-accent-cyan bg-accent-cyan-soft/30 ring-2 ring-accent-cyan/20'
                    : isActive
                      ? 'border-accent-cyan bg-bg-card shadow-md'
                      : isDone
                        ? 'border-accent-emerald/30 bg-bg-card hover:border-accent-emerald/60'
                        : 'border-border-default bg-bg-subtle/40 opacity-70 hover:opacity-100'
                }`}
              >
                {/* Status Indicator Icon */}
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs font-bold mb-2 transition-transform group-hover:scale-110 ${
                    isDone
                      ? 'bg-accent-emerald text-white shadow-sm'
                      : isActive
                        ? 'bg-accent-cyan text-white pulse-ring-active'
                        : 'bg-bg-subtle border border-border-default text-text-muted'
                  }`}
                >
                  {isDone ? (
                    <Check size={14} strokeWidth={2.5} />
                  ) : isActive ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <span>{stage.id}</span>
                  )}
                </div>

                <div className="font-display text-xs font-semibold text-text-primary leading-tight truncate w-full">
                  {stage.name}
                </div>
                <div className="text-[10px] font-mono text-text-muted mt-0.5 truncate w-full">
                  {stage.engine.split(' ')[0]}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Stage Inspector Drawer */}
      {selectedStage && (
        <div className="mt-4 rounded-xl border border-border-default bg-bg-subtle/70 p-4 transition-all">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-border-default">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-accent-cyan-soft text-accent-cyan flex items-center justify-center font-mono text-xs font-bold">
                {selectedStage.id}
              </div>
              <div>
                <div className="font-display font-semibold text-text-primary text-sm flex items-center gap-2">
                  <span>Stage {selectedStage.id}: {selectedStage.name}</span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-bg-card border border-border-default text-text-secondary">
                    {selectedStage.engine}
                  </span>
                </div>
                <p className="text-xs text-text-secondary mt-0.5">{selectedStage.description}</p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setDrawerOpen((prev) => !prev)}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-bg-card border border-border-default text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
            >
              <Terminal size={12} />
              {drawerOpen ? 'Collapse Logs' : 'View Stream Logs'}
              {drawerOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
          </div>

          {/* Real-time Stage Log Stream */}
          {drawerOpen && (
            <div className="mt-3 rounded-lg bg-terminal-bg border border-white/10 p-3 font-mono text-xs space-y-1.5 max-h-48 overflow-y-auto animate-fade-rise-in">
              <div className="text-[11px] text-terminal-muted border-b border-white/10 pb-1 flex items-center justify-between">
                <span>[LOG_STREAM] daemon://stage_{selectedStage.id}_{selectedStage.shortLabel.toLowerCase()}.log</span>
                <span className="text-accent-emerald flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald pulse-dot" /> STREAMING
                </span>
              </div>
              {/* Engine badge */}
              <div className="flex items-center gap-1.5 pb-1 border-b border-white/5">
                <Cpu size={10} className="text-accent-cyan" />
                <span className="text-accent-cyan text-[10px]">{selectedStage.engine}</span>
                {selectedStage.id === currentStageIndex + 1 && isScanning && (
                  <span className="ml-auto text-[10px] text-accent-amber animate-pulse">● ACTIVE</span>
                )}
              </div>
              {(liveLogLines?.[selectedStage.id] ?? selectedStage.logs)
                .slice(0, isScanning && selectedStage.id === currentStageIndex + 1 ? visibleLogCount : undefined)
                .map((logLine, i) => (
                  <div key={i} className="text-terminal-text flex items-start gap-2 animate-fade-rise-in">
                    <span className="text-terminal-muted select-none">[{i + 1}]</span>
                    <span>{logLine}</span>
                  </div>
                ))}
              {isScanning && selectedStage.id === currentStageIndex + 1 && (
                <div className="text-accent-cyan flex items-center gap-1.5 animate-pulse">
                  <span>&gt;</span> <span>executing in-process analysis…</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
