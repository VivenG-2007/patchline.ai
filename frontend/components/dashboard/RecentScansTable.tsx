'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import { GitBranch, ChevronRight, ChevronLeft, CheckCircle2, Sparkles, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import Card from '@/components/ui/Card';

export interface RepoHealthItem {
  repo: string;
  branch: string;
  riskLevel: string;
  findings: number;
  lastScan: string;
  status: string;
  scanId?: string;
  fixBranch?: string;
  jiraTicket?: { key: string; id?: string; url: string } | null;
}

interface RecentScansTableProps {
  items: RepoHealthItem[];
  pageSize?: number;
}

type SortField = 'repo' | 'riskLevel' | 'findings' | 'lastScan';
type SortDir = 'asc' | 'desc';

const SEVERITY_STYLE: Record<string, { bg: string; border: string; color: string }> = {
  Critical: { bg: 'rgba(244,63,94,0.10)',  border: 'rgba(244,63,94,0.25)',  color: '#F43F5E' },
  High:     { bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.25)', color: '#F97316' },
  Medium:   { bg: 'rgba(234,179,8,0.10)',  border: 'rgba(234,179,8,0.25)',  color: '#EAB308' },
  Low:      { bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.25)',  color: '#22C55E' },
};

const STATUS_DOT: Record<string, string> = {
  Healthy: '#22C55E',
  'Action Required': '#F43F5E',
  'Review Fixes': '#EAB308',
  Warning: '#EAB308',
  Scanning: '#14B8A6',
  Clean: '#22C55E',
};

function SeverityBadge({ level }: { level: string }) {
  const s = SEVERITY_STYLE[level] ?? { bg: 'rgba(107,99,115,0.10)', border: 'rgba(107,99,115,0.25)', color: '#6B6373' };
  return (
    <span
      className="pl-badge"
      style={{ background: s.bg, borderColor: s.border, color: s.color }}
    >
      {level.toUpperCase()}
    </span>
  );
}

function formatTime(iso: string) {
  if (!iso) return 'Recent';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

export default function RecentScansTable({ items, pageSize = 5 }: RecentScansTableProps) {
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState<SortField>('lastScan');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const handleHeaderClick = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const sortedItems = useMemo(() => {
    const list = [...items];
    const getTime = (iso?: string | null) => {
      if (!iso) return 0;
      const t = new Date(iso).getTime();
      return isNaN(t) ? 0 : t;
    };

    list.sort((a, b) => {
      let res = 0;
      if (sortField === 'lastScan') {
        res = getTime(a.lastScan) - getTime(b.lastScan);
      } else if (sortField === 'repo') {
        res = a.repo.localeCompare(b.repo);
      } else if (sortField === 'findings') {
        res = a.findings - b.findings;
      } else if (sortField === 'riskLevel') {
        const rank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
        res = (rank[a.riskLevel] || 0) - (rank[b.riskLevel] || 0);
      }
      return sortDir === 'desc' ? -res : res;
    });
    return list;
  }, [items, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sortedItems.length / pageSize));
  const pagedItems = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedItems.slice(start, start + pageSize);
  }, [sortedItems, currentPage, pageSize]);

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ArrowUpDown size={10} className="inline opacity-40 ml-1" />;
    return sortDir === 'desc' ? <ArrowDown size={10} className="inline text-primary ml-1" /> : <ArrowUp size={10} className="inline text-primary ml-1" />;
  };

  return (
    <Card className="overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between px-5 py-4"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <div>
          <h2 className="text-[13px] font-semibold" style={{ color: 'var(--foreground)' }}>
            Recent Vulnerabilities
          </h2>
          <p className="text-[11px]" style={{ color: 'var(--muted-2)' }}>
            Monitored repositories &amp; pipeline status
          </p>
        </div>
        <span className="font-mono text-[11px]" style={{ color: 'var(--muted-2)' }}>
          {currentPage} / {totalPages}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr
              className="text-[10px] font-mono uppercase tracking-wider"
              style={{
                background: 'var(--surface-2)',
                color: 'var(--muted-2)',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <th
                className="px-5 py-2.5 font-semibold cursor-pointer hover:text-foreground transition-colors select-none"
                onClick={() => handleHeaderClick('repo')}
              >
                Repository <SortIcon field="repo" />
              </th>
              <th className="px-4 py-2.5 font-semibold hidden sm:table-cell select-none">Branch</th>
              <th
                className="px-4 py-2.5 font-semibold cursor-pointer hover:text-foreground transition-colors select-none"
                onClick={() => handleHeaderClick('riskLevel')}
              >
                Severity <SortIcon field="riskLevel" />
              </th>
              <th
                className="px-4 py-2.5 font-semibold cursor-pointer hover:text-foreground transition-colors select-none"
                onClick={() => handleHeaderClick('findings')}
              >
                Findings <SortIcon field="findings" />
              </th>
              <th
                className="px-4 py-2.5 font-semibold hidden md:table-cell cursor-pointer hover:text-foreground transition-colors select-none"
                onClick={() => handleHeaderClick('lastScan')}
              >
                Last Scanned <SortIcon field="lastScan" />
              </th>
              <th className="px-4 py-2.5 font-semibold select-none">Status</th>
              <th className="px-5 py-2.5 font-semibold text-right select-none">Actions</th>
            </tr>
          </thead>
          <tbody>
            {pagedItems.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-8 text-center text-[12px]" style={{ color: 'var(--muted-2)' }}>
                  No repositories match your active filter criteria.
                </td>
              </tr>
            ) : (
              pagedItems.map((r) => {
                const [owner, name] = r.repo.includes('/')
                  ? r.repo.split('/')
                  : ['', r.repo];
                const isScanning = r.status === 'Scanning';
                const dotColor = STATUS_DOT[r.status] ?? '#6B6373';

                return (
                  <tr
                    key={r.repo}
                    className="transition-colors group"
                    style={{ borderBottom: '1px solid var(--border)' }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-hover)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = '')}
                  >
                    {/* Repo */}
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-6 h-6 rounded-lg flex items-center justify-center shrink-0"
                          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
                        >
                          <GitBranch size={11} style={{ color: 'var(--muted)' }} />
                        </div>
                        <div className="min-w-0">
                          <div className="font-mono text-[12px] truncate max-w-[220px]" style={{ color: 'var(--foreground)' }}>
                            {owner && <span style={{ color: 'var(--muted)' }}>{owner}/</span>}
                            {name}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Branch */}
                    <td className="px-4 py-3 hidden sm:table-cell">
                      <span
                        className="font-mono text-[11px] px-2 py-0.5 rounded"
                        style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--muted)' }}
                      >
                        {r.branch}
                      </span>
                    </td>

                    {/* Severity */}
                    <td className="px-4 py-3">
                      <SeverityBadge level={r.riskLevel} />
                    </td>

                    {/* Findings */}
                    <td className="px-4 py-3 font-mono text-[12px]">
                      {r.findings > 0 ? (
                        <span style={{ color: '#F43F5E', fontStyle: 'normal', fontWeight: 600 }}>{r.findings} issues</span>
                      ) : (
                        <span className="flex items-center gap-1" style={{ color: '#22C55E' }}>
                          <CheckCircle2 size={11} /> Clean
                        </span>
                      )}
                    </td>

                    {/* Last scanned */}
                    <td className="px-4 py-3 font-mono text-[11px] hidden md:table-cell" style={{ color: 'var(--muted-2)' }}>
                      {formatTime(r.lastScan)}
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${isScanning ? 'pulse-dot' : ''}`}
                          style={{ background: dotColor }}
                        />
                        <span className="text-[12px]" style={{ color: 'var(--muted)' }}>
                          {r.status}
                        </span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="px-5 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {r.jiraTicket?.url && (
                          <a
                            href={r.jiraTicket.url}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center gap-1 px-2 py-1 rounded-md font-mono text-[11px] transition-all hover:brightness-110"
                            style={{
                              background: 'rgba(0,82,204,0.12)',
                              border: '1px solid rgba(0,82,204,0.35)',
                              color: '#4c9aff',
                            }}
                            title={`Open Jira Ticket ${r.jiraTicket.key}`}
                          >
                            Jira {r.jiraTicket.key}
                          </a>
                        )}
                        {r.findings > 0 && (
                          <button
                            className="flex items-center gap-1 px-2 py-1 rounded-md font-mono text-[11px] transition-all"
                            style={{
                              background: 'rgba(20,184,166,0.10)',
                              border: '1px solid rgba(20,184,166,0.25)',
                              color: '#14B8A6',
                            }}
                            title="AI Fix"
                          >
                            <Sparkles size={10} /> FIX
                          </button>
                        )}
                        <Link
                          href={`/scanner?repo=${encodeURIComponent(r.repo)}&branch=${encodeURIComponent(r.branch)}`}
                          className="flex items-center gap-1 px-2 py-1 rounded-md font-mono text-[11px] transition-all"
                          style={{
                            background: 'var(--surface-2)',
                            border: '1px solid var(--border-strong)',
                            color: 'var(--muted)',
                          }}
                        >
                          Inspect <ChevronRight size={10} />
                        </Link>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div
          className="px-5 py-3 flex items-center justify-between text-[12px]"
          style={{ borderTop: '1px solid var(--border)' }}
        >
          <button
            type="button"
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="pl-btn-secondary disabled:opacity-40 disabled:pointer-events-none"
            style={{ height: 30, fontSize: 11, padding: '0 10px' }}
          >
            <ChevronLeft size={12} /> Prev
          </button>
          <span className="font-mono" style={{ color: 'var(--muted-2)' }}>
            {currentPage} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="pl-btn-secondary disabled:opacity-40 disabled:pointer-events-none"
            style={{ height: 30, fontSize: 11, padding: '0 10px' }}
          >
            Next <ChevronRight size={12} />
          </button>
        </div>
      )}
    </Card>
  );
}
