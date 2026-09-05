'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { Sparkles, RefreshCw, ScanSearch } from 'lucide-react';
import ProtectedShell from '@/components/ProtectedShell';
import EmptyState from '@/components/ui/EmptyState';
import DashboardSkeleton from '@/components/DashboardSkeleton';
import ErrorBanner from '@/components/ErrorBanner';
// Critical above-the-fold components — static import (fast first paint)
import DashboardMetrics from '@/components/dashboard/DashboardMetrics';
import DashboardFilters, { FilterState } from '@/components/dashboard/DashboardFilters';
import RecentScansTable, { RepoHealthItem } from '@/components/dashboard/RecentScansTable';
import { mainApi } from '@/lib/api';

// Heavy chart components — lazy-loaded after first paint (recharts tree-shaking)
const SeverityDistributionChart = dynamic(
  () => import('@/components/dashboard/SeverityDistributionChart'),
  { ssr: false, loading: () => <div className="h-56 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const ScanTrendsChart = dynamic(
  () => import('@/components/dashboard/ScanTrendsChart'),
  { ssr: false, loading: () => <div className="h-56 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const VulnHeatmap = dynamic(
  () => import('@/components/dashboard/VulnHeatmap'),
  { ssr: false, loading: () => <div className="h-48 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const AIFixEngine = dynamic(
  () => import('@/components/dashboard/AIFixEngine'),
  { ssr: false, loading: () => <div className="h-40 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const RepoAtRisk = dynamic(
  () => import('@/components/dashboard/RepoAtRisk'),
  { ssr: false, loading: () => <div className="h-40 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const SecurityRadar = dynamic(
  () => import('@/components/dashboard/SecurityRadar'),
  { ssr: false, loading: () => <div className="h-48 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);
const PipelineStatus = dynamic(
  () => import('@/components/dashboard/PipelineStatus'),
  { ssr: false, loading: () => <div className="h-56 rounded-xl bg-bg-subtle/60 animate-pulse" /> }
);

interface DashboardStats {
  kpis: {
    connectedRepos: { value: number; deltaLabel?: string | null };
    openFindings: { value: number };
    criticalIssues: { value: number };
    aiFixesApplied: { value: number; windowLabel?: string | null };
  };
  globalRiskScore: number;
  riskScoreSeries: { day: string; score: number; scans?: number; remediated?: number }[];
  activityFeed: { id: string; type: string; message: string; repo?: string; timestamp: string }[];
  repoHealth: RepoHealthItem[];
  severityBreakdown: { critical: number; high: number; medium: number; low?: number };
  aiFixEngine?: {
    fixesGenerated: number;
    fixesVerified: number;
    prsCreated: number;
    verificationRate: number;
    // Featherless primary / GPT fallback attribution — model_router.py.
    // See ModelBadge / AIFixEngine's own model-usage strip.
    modelUsage?: {
      featherlessCalls: number;
      fallbackCalls: number;
      fallbackModels: { model: string; count: number }[];
    };
  };
  vulnHeatmap?: { type: string; weeks: number[] }[];
  reposAtRisk?: { name: string; critical: number; high: number; medium: number; low: number; total: number }[];
  securityRadar?: { axis: string; value: number }[];
  isElasticActive?: boolean;
  // Per-stage telemetry for the 9-stage remediation loop (Elastic-backed —
  // see PipelineStatus.tsx). Absent until main-service aggregates
  // scan_history + fixes into this shape; the component itself degrades
  // gracefully (idle stage track, no fabricated progress) when this is
  // undefined or empty.
  pipelineStatus?: {
    id: string;
    status: 'completed' | 'running' | 'waiting' | 'failed';
    model?: string | null;
    provider?: string | null;
    count?: number;
  }[];
}

const DEFAULT_FILTERS: FilterState = {
  searchQuery: '',
  status: 'ALL',
  severity: 'ALL',
  sortBy: 'recent',
};

const ZERO_STATS: DashboardStats = {
  kpis: {
    connectedRepos: { value: 0, deltaLabel: null },
    openFindings: { value: 0 },
    criticalIssues: { value: 0 },
    aiFixesApplied: { value: 0, windowLabel: null },
  },
  globalRiskScore: 0,
  riskScoreSeries: [],
  activityFeed: [],
  repoHealth: [],
  severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
  aiFixEngine: { fixesGenerated: 0, fixesVerified: 0, prsCreated: 0, verificationRate: 0 },
  vulnHeatmap: [],
  reposAtRisk: [],
  securityRadar: [],
  pipelineStatus: [],
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  const load = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const { data } = await mainApi.get('/api/proxy/api/v1/dashboard/stats');
      setStats(data || ZERO_STATS);
    } catch (err: any) {
      setStats(ZERO_STATS);
      setError(
        err?.response?.data?.error?.message ??
          'Failed to load live telemetry from Elastic / MongoDB services.'
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(() => load(true), 60000);
    return () => clearInterval(interval);
  }, [load]);

  // Client-side filtering & sorting by Date, Risk, or Findings
  const filteredRepos = useMemo(() => {
    if (!stats?.repoHealth) return [];
    let list = [...stats.repoHealth];

    if (filters.searchQuery.trim()) {
      const q = filters.searchQuery.toLowerCase();
      list = list.filter(
        (r) =>
          r.repo.toLowerCase().includes(q) ||
          r.branch.toLowerCase().includes(q) ||
          r.status.toLowerCase().includes(q)
      );
    }
    if (filters.status !== 'ALL') {
      list = list.filter((r) => r.status.toLowerCase() === filters.status.toLowerCase());
    }
    if (filters.severity !== 'ALL') {
      list = list.filter((r) => r.riskLevel.toUpperCase() === filters.severity.toUpperCase());
    }

    const getTime = (iso?: string | null) => {
      if (!iso) return 0;
      const t = new Date(iso).getTime();
      return isNaN(t) ? 0 : t;
    };

    if (filters.sortBy === 'risk_desc') {
      const rank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      list.sort((a, b) => (rank[b.riskLevel] || 0) - (rank[a.riskLevel] || 0));
    } else if (filters.sortBy === 'findings_desc') {
      list.sort((a, b) => b.findings - a.findings);
    } else if (filters.sortBy === 'oldest') {
      list.sort((a, b) => getTime(a.lastScan) - getTime(b.lastScan));
    } else {
      // recent / date_desc
      list.sort((a, b) => getTime(b.lastScan) - getTime(a.lastScan));
    }
    return list;
  }, [stats?.repoHealth, filters]);

  return (
    <ProtectedShell>
      {/* ── Page header ── */}
      <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
        <div>
          <div
            className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest mb-1.5"
            style={{ color: 'var(--primary)' }}
          >
            <span className="w-1.5 h-1.5 rounded-full pulse-dot inline-block" style={{ background: 'var(--primary)' }} />
            Security Control Center {stats?.isElasticActive && '· Elastic Engine'}
          </div>
          <h1 className="font-sans font-bold text-[22px] leading-tight" style={{ color: 'var(--foreground)' }}>
            Security Overview
          </h1>
          <p className="text-[12px] mt-0.5" style={{ color: 'var(--muted)' }}>
            Real-time multi-repo telemetry, deterministic SAST &amp; AI remediation
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => load(true)}
            disabled={refreshing}
            className="pl-btn-secondary"
            title="Refresh dashboard"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} style={{ color: 'var(--primary)' }} />
            {refreshing ? 'Syncing…' : 'Sync'}
          </button>

          <Link href="/scanner">
            <button
              type="button"
              className="pl-btn-primary group"
            >
              <Sparkles
                size={14}
                className="transition-transform group-hover:rotate-12"
              />
              Launch Security Scan
            </button>
          </Link>
        </div>
      </div>

      {error && (
        <ErrorBanner message={error} category="GATEWAY" onRetry={() => load()} className="mb-5" />
      )}

      {loading ? (
        <DashboardSkeleton />
      ) : !stats ? (
        <EmptyState
          icon={ScanSearch}
          title="No telemetry available"
          description="Connect your GitHub organization or run a live scan to initialize your security telemetry."
          action={
            <Link href="/scanner" className="text-[13px] font-mono hover:underline mt-2 inline-block" style={{ color: 'var(--primary)' }}>
              Launch first scan →
            </Link>
          }
        />
      ) : (
        <div className="space-y-4">

          {/* ── Row 1: KPI metrics ── */}
          <DashboardMetrics
            kpis={stats.kpis}
            severityBreakdown={stats.severityBreakdown}
            activePipelineCount={stats.kpis.connectedRepos.value > 0 ? 1 : 0}
            clearanceRate={stats.kpis.connectedRepos.value > 0 ? 100 : 0}
          />

          {/* ── Row 2: Hero chart (2/3) + Severity donut (1/3) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <ScanTrendsChart
                data={stats.riskScoreSeries}
                title="Security Activity"
                subtitle="Open and resolved exposures overtime"
              />
            </div>
            <div>
              <SeverityDistributionChart
                critical={stats.severityBreakdown.critical}
                high={stats.severityBreakdown.high}
                medium={stats.severityBreakdown.medium}
                low={stats.severityBreakdown.low ?? 0}
                globalRiskScore={stats.globalRiskScore}
              />
            </div>
          </div>

          {/* ── Row 2.5: Remediation pipeline (Elastic-backed, full width) ── */}
          <PipelineStatus steps={stats.pipelineStatus} isElasticActive={stats.isElasticActive} />

          {/* ── Row 3: Vuln heatmap (1/2) + AI Fix engine (1/2) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <VulnHeatmap data={stats.vulnHeatmap} />
            <AIFixEngine data={stats.aiFixEngine} />
          </div>

          {/* ── Row 4: Repos at risk (1/2) + Security radar (1/2) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <RepoAtRisk repos={stats.reposAtRisk} />
            <SecurityRadar data={stats.securityRadar} />
          </div>

          {/* ── Row 5: Filters & Recent scans table ── */}
          <div className="space-y-3">
            <DashboardFilters
              filters={filters}
              onFilterChange={setFilters}
              onReset={() => setFilters(DEFAULT_FILTERS)}
              totalCount={stats.repoHealth.length}
              filteredCount={filteredRepos.length}
            />
            <RecentScansTable items={filteredRepos} pageSize={5} />
          </div>

        </div>
      )}
    </ProtectedShell>
  );
}
