'use client';

import React from 'react';
import { BrainCircuit, Loader2, Check, Sparkles, Database } from 'lucide-react';

export type SimilarPastFix = {
  similarity: number;
  title?: string;
  category?: string;
  severity?: string;
  file?: string;
  fixSummary?: string;
  verified: boolean;
};

export interface RagMemoryTraceProps {
  /** Whether the backend has RAG memory switched on */
  ragMemoryEnabled?: boolean;
  /** In-flight fix phase for this finding, or null once settled */
  phase?: 'QUEUED' | 'PROCESSING' | 'VERIFIED' | 'FAILED' | 'NEEDS_REVIEW' | null;
  /** Set once the fix call returns (verified or needs-review) */
  settled?: boolean;
  similarPastFixes?: SimilarPastFix[];
  className?: string;
}

/**
 * Traces the Chroma Cloud RAG memory pipeline for this finding:
 *   1. Recall — Semantic similarity search across historical finding/fix vectors
 *   2. Augment — Prior art injected into GPT-4.1 mini patch prompt
 *   3. Remember — Verified outcome indexed back to Chroma vector collection
 */
export default function RagMemoryTrace({
  ragMemoryEnabled = true,
  phase = null,
  settled = false,
  similarPastFixes = [],
  className = '',
}: RagMemoryTraceProps) {
  if (!ragMemoryEnabled) return null;

  const recalling = phase === 'QUEUED' || phase === 'PROCESSING';
  const hasSimilar = (similarPastFixes?.length ?? 0) > 0;

  // Render when recalling or when fix is settled or similar past fixes are present
  if (!recalling && !settled && !hasSimilar) return null;

  return (
    <div className={`text-xs rounded-xl border border-accent-purple/30 bg-bg-card/90 backdrop-blur-sm p-4 space-y-3 font-mono shadow-sm ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border-default pb-2">
        <div className="flex items-center gap-2 text-accent-purple font-semibold text-xs tracking-wider uppercase">
          <BrainCircuit size={14} className="animate-pulse" />
          <span>Chroma Cloud · RAG Memory Trace</span>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded bg-accent-purple-soft text-accent-purple border border-accent-purple/20">
          Vector Recall &amp; Augment
        </span>
      </div>

      {/* Step 1: Semantic Recall */}
      <div className="flex items-start gap-2.5">
        {recalling ? (
          <Loader2 size={14} className="animate-spin mt-0.5 shrink-0 text-accent-cyan" />
        ) : (
          <Check size={14} className="mt-0.5 shrink-0 text-accent-emerald" />
        )}
        <div className="flex-1 min-w-0 space-y-1.5">
          <div className="flex items-center gap-1.5 text-text-primary font-semibold text-xs">
            <span>Step 1: Semantic Vector Recall</span>
            <span className="text-text-muted text-[10px] font-normal">(Collection: finding_memory)</span>
          </div>

          {recalling ? (
            <p className="text-text-muted text-xs">
              Querying Chroma Cloud embeddings for past fixes with matching vulnerability patterns…
            </p>
          ) : hasSimilar ? (
            <div className="space-y-2 mt-1">
              <p className="text-text-secondary text-xs">
                Recalled <strong className="text-accent-cyan">{similarPastFixes.length} prior art match{similarPastFixes.length === 1 ? '' : 'es'}</strong> to guide patch synthesis:
              </p>
              <div className="space-y-2 pl-2 border-l-2 border-accent-purple/40">
                {similarPastFixes.map((item, i) => (
                  <div
                    key={i}
                    className={`text-xs p-2 rounded-lg border space-y-1.5 ${
                      item.verified
                        ? 'bg-accent-emerald-soft/10 border-accent-emerald/30'
                        : 'bg-accent-rose-soft/10 border-accent-rose/30'
                    }`}
                  >
                    {/* Label row */}
                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded ${
                          item.verified
                            ? 'bg-accent-emerald-soft text-accent-emerald'
                            : 'bg-accent-rose-soft text-accent-rose'
                        }`}
                      >
                        {item.verified ? '✓ Verified Successful Patch' : '✗ Failed / Unverified — Strategy Avoided'}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-cyan-soft text-accent-cyan font-bold">
                        {Math.round(item.similarity * 100)}% match
                      </span>
                    </div>
                    {/* Finding title */}
                    <div className="text-text-primary font-medium truncate">
                      &ldquo;{item.title}&rdquo;
                    </div>
                    {/* File + category */}
                    {item.file && (
                      <div className="text-[11px] text-text-muted truncate">
                        File: {item.file}{item.category ? ` · ${item.category}` : ''}
                      </div>
                    )}
                    {/* Fix summary */}
                    {item.fixSummary && (
                      <div className={`text-[11px] p-1.5 rounded border ${
                        item.verified
                          ? 'text-text-secondary bg-bg-card border-accent-emerald/20'
                          : 'text-accent-rose/80 bg-bg-card border-accent-rose/20'
                      }`}>
                        <span className="font-semibold">{item.verified ? 'Strategy: ' : 'Failed strategy (do not repeat): '}</span>
                        {item.fixSummary}
                      </div>
                    )}
                    {/* Directive note for failed items */}
                    {!item.verified && (
                      <div className="text-[10px] text-accent-rose/70 italic">
                        ⚠ AI instructed to avoid repeating this patch strategy.
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-text-muted text-xs">
              No previous occurrences in vector database — first time encountering this vulnerability signature.
            </p>
          )}
        </div>
      </div>

      {/* Step 2: Prompt Augmentation */}
      {(recalling || settled || hasSimilar) && (
        <div className="flex items-start gap-2.5 pt-2 border-t border-border-default/60">
          <Sparkles size={14} className={`mt-0.5 shrink-0 ${recalling ? 'text-accent-cyan animate-pulse' : 'text-accent-purple'}`} />
          <div className="flex-1 min-w-0">
            <div className="text-text-primary font-semibold text-xs">Step 2: GPT-4.1 mini Prompt Context Augmentation</div>
            <p className="text-text-muted text-xs mt-0.5">
              {hasSimilar
                ? 'Synthesizer prompt injected with verified AST transformations from prior art.'
                : 'Zero-shot high-context remediation prompt dispatched to GPT-4.1 mini engine.'}
            </p>
          </div>
        </div>
      )}

      {/* Step 3: Remember (Indexing back to Chroma Cloud) */}
      {settled && (
        <div className="flex items-start gap-2.5 pt-2 border-t border-border-default/60">
          <Check size={14} className="mt-0.5 shrink-0 text-accent-emerald" />
          <div className="flex-1 min-w-0">
            <div className="text-text-primary font-semibold text-xs flex items-center gap-1.5">
              <span>Step 3: Outcome Indexed to Chroma Memory</span>
              <Database size={11} className="text-accent-cyan" />
            </div>
            <p className="text-text-muted text-xs mt-0.5">
              Patch outcome and verification metadata embedded to Chroma Cloud for future automated recall.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
