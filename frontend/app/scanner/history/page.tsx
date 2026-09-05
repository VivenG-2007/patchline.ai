'use client';

import { useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { ChevronDown, ChevronUp, Package, GitBranch, Search, Plus, Sparkles, ExternalLink } from 'lucide-react';
import ProtectedShell from '@/components/ProtectedShell';
import PageHeader from '@/components/ui/PageHeader';
import Card from '@/components/ui/Card';
import Badge from '@/components/ui/Badge';
import Button from '@/components/ui/Button';
import EmptyState from '@/components/ui/EmptyState';
import ErrorBanner from '@/components/ErrorBanner';
import VulnerabilityTimeline from '@/components/scanner/VulnerabilityTimeline';
import { scannerApi } from '@/lib/api';

// Lazily load recharts components — heavy JS not needed on initial paint
const { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } =
  (await import('recharts')) as typeof import('recharts');

type ScanRecord = {
  scanId: string;
  repo: string;
  branch: string;
  scannedAt: string;
  findingsCount: number;
  status: string;
  blobUri?: string;
  fixBranch?: string;
  fixedAt?: string;
  findings?: Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    file: string;
    line: number;
    description: string;
    source?: 'deterministic' | 'ai';
  }>;
};

const STATUS_TONE: Record<string, 'warning' | 'success' | 'critical' | 'neutral'> = {
  COMPLETED_WAITING_APPROVAL: 'warning',
  FIX_VERIFIED: 'success',
  FIX_NEEDS_REVIEW: 'warning',
  FIX_FAILED: 'critical',
};

const SEVERITY_TONE: Record<string, 'critical' | 'warning' | 'info' | 'neutral'> = {
  CRITICAL: 'critical',
  HIGH: 'critical',
  MEDIUM: 'warning',
  LOW: 'info',
};

export default function ScanHistoryPage() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = () => {
    setLoading(true);
    setError(null);
    scannerApi
      .history(50)
      .then(({ data }) => {
        const raw = data?.history ?? data ?? [];
        if (Array.isArray(raw)) {
          const getTime = (iso?: string | null) => {
            if (!iso) return 0;
            const t = new Date(iso).getTime();
            return isNaN(t) ? 0 : t;
          };
          const sorted = [...raw].sort((a, b) => getTime(b.scannedAt) - getTime(a.scannedAt));
          setRecords(sorted);
        } else {
          setRecords([]);
        }
      })
      .catch((err: any) => {
        setError(
          err?.response?.data?.error?.message ??
            'Failed to load scan history — ensure ai-storage service is reachable.'
        );
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const toggleExpand = (scanId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(scanId)) next.delete(scanId);
      else next.add(scanId);
      return next;
    });
  };

  const velocitySeries = useMemo(() => {
    const byDay = new Map<string, { day: string; found: number; fixed: number; sortKey: string }>();
    const dayLabel = (iso: string) => {
      const d = new Date(iso);
      return {
        key: d.toISOString().slice(0, 10),
        label: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      };
    };
    for (const r of records) {
      if (r.scannedAt) {
        const { key, label } = dayLabel(r.scannedAt);
        const entry = byDay.get(key) ?? { day: label, found: 0, fixed: 0, sortKey: key };
        entry.found += r.findingsCount || 0;
        byDay.set(key, entry);
      }
      if (r.fixedAt) {
        const { key, label } = dayLabel(r.fixedAt);
        const entry = byDay.get(key) ?? { day: label, found: 0, fixed: 0, sortKey: key };
        entry.fixed += 1;
        byDay.set(key, entry);
      }
    }
    return Array.from(byDay.values()).sort((a, b) => a.sortKey.localeCompare(b.sortKey)).slice(-14);
  }, [records]);

  return (
    <ProtectedShell>
      <PageHeader
        eyebrow="Azure Blob · MongoDB Telemetry"
        title="Audit Logs &amp; Scan History"
        description="Comprehensive historical ledger of all deterministic SAST scans, GPT-4.1 mini patches, and regression verification passes."
        action={
          <Link href="/scanner">
            <Button size="sm" className="gap-1.5 font-mono">
              <Plus size={14} /> New Scan
            </Button>
          </Link>
        }
      />

      {error && <ErrorBanner message={error} category="STORAGE" onRetry={load} className="mb-6" />}

      {/* Fix Velocity Histogram */}
      {velocitySeries.length > 0 && (
        <Card className="p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-display text-sm font-semibold text-text-primary">Remediation Velocity</h2>
              <p className="text-xs text-text-muted">Findings detected vs. patches verified &amp; merged per day</p>
            </div>
            <span className="font-mono text-xs text-text-muted">14-day window</span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={velocitySeries} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="0" stroke="rgba(16,185,129,0.08)" vertical={false} />
                <XAxis dataKey="day" stroke="var(--muted-2)" fontSize={11} tickLine={false} axisLine={false} fontFamily="var(--font-mono)" />
                <YAxis stroke="var(--muted-2)" fontSize={11} tickLine={false} axisLine={false} width={30} allowDecimals={false} fontFamily="var(--font-mono)" />
                <Tooltip
                  contentStyle={{
                    background: 'var(--surface-elevated)',
                    borderColor: 'var(--border-strong)',
                    borderRadius: 10,
                    fontSize: 12,
                    color: '#F4F1F7',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: 11, color: '#9B93A5', fontFamily: 'var(--font-mono)', paddingTop: 10 }} />
                <Bar dataKey="found" name="Vulnerabilities Found" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                <Bar dataKey="fixed" name="Patches Verified" fill="#22C55E" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}

      {loading && <p className="text-text-muted text-sm font-mono">Loading telemetry history…</p>}

      {!loading && records.length === 0 && (
        <EmptyState
          icon={Search}
          title="No scan records found"
          description="Execute your first scan on the Scanner page to populate the history ledger."
          action={
            <Link href="/scanner" className="text-accent-cyan text-sm font-mono hover:underline mt-2">
              Go to scanner →
            </Link>
          }
        />
      )}

      {/* Historical Record Cards */}
      <div className="space-y-3">
        {records.map((record) => {
          const isOpen = expanded.has(record.scanId);
          const tone = STATUS_TONE[record.status] ?? 'neutral';

          return (
            <Card key={record.scanId} className="overflow-hidden">
              <button
                type="button"
                onClick={() => toggleExpand(record.scanId)}
                className="w-full text-left px-5 py-4 flex flex-wrap items-start justify-between gap-4 hover:bg-bg-subtle/50 transition-colors"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-display font-semibold text-sm text-text-primary truncate">
                      {record.repo}
                    </span>
                    <span className="font-mono text-xs text-text-muted">({record.branch})</span>
                    <Badge tone={tone} dot>
                      {record.status.replaceAll('_', ' ').toLowerCase()}
                    </Badge>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 font-mono text-xs text-text-secondary">
                    <span>{new Date(record.scannedAt).toLocaleString()}</span>
                    <span className={record.findingsCount > 0 ? 'text-accent-rose font-medium' : 'text-accent-emerald'}>
                      {record.findingsCount} issue{record.findingsCount !== 1 ? 's' : ''}
                    </span>
                    <span className="text-text-muted truncate max-w-[200px]">{record.scanId}</span>
                  </div>

                  {record.fixBranch && (
                    <div className="font-mono text-xs text-accent-emerald flex items-center gap-1.5 pt-0.5">
                      <GitBranch size={12} />
                      {record.fixBranch}
                      {record.fixedAt && (
                        <span className="text-text-muted">({new Date(record.fixedAt).toLocaleTimeString()})</span>
                      )}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  {record.blobUri && (
                    <a
                      href={record.blobUri}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="px-2.5 py-1.5 bg-bg-card border border-border-default hover:border-accent-cyan text-accent-cyan font-mono text-xs rounded-lg transition-colors inline-flex items-center gap-1.5"
                      title="Download raw report from Azure Blob"
                    >
                      <Package size={12} /> Report
                    </a>
                  )}
                  {isOpen ? <ChevronUp size={15} className="text-text-muted" /> : <ChevronDown size={15} className="text-text-muted" />}
                </div>
              </button>

              {isOpen && (
                <div className="border-t border-border-default bg-bg-subtle/30 px-5 py-4 space-y-4 animate-fade-rise-in">
                  {!record.findings || record.findings.length === 0 ? (
                    <p className="text-xs font-mono text-accent-emerald">
                      No vulnerabilities discovered in this scan cycle.
                    </p>
                  ) : (
                    <div className="space-y-4">
                      <div className="text-xs font-mono uppercase tracking-wider text-text-muted">
                        Discovered Flaws ({record.findings.length})
                      </div>
                      {record.findings.map((f) => (
                        <div key={f.id} className="p-4 rounded-xl border border-border-default bg-bg-card space-y-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge tone={SEVERITY_TONE[f.severity] ?? 'neutral'}>{f.severity}</Badge>
                            <span className="font-semibold text-xs text-text-primary">{f.title}</span>
                            <span className="font-mono text-xs text-text-muted">{f.id}</span>
                          </div>
                          <p className="text-xs text-text-secondary leading-relaxed">{f.description}</p>
                          <p className="font-mono text-xs text-text-muted">
                            <span className="text-text-primary">{f.file}</span>
                            <span className="text-accent-cyan">:{f.line}</span>
                          </p>

                          {/* Embedded Timeline */}
                          <div className="pt-2">
                            <VulnerabilityTimeline
                              finding={f}
                              repo={record.repo}
                              fixBranch={record.fixBranch || `fix/patchline-${f.id.toLowerCase()}`}
                              detectedAt={record.scannedAt}
                              fixedAt={record.fixedAt}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </ProtectedShell>
  );
}
