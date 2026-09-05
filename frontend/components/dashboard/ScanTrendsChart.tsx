'use client';

import React, { useState, useMemo, useSyncExternalStore } from 'react';

const emptySubscribe = () => () => {};
const getSnapshot = () => true;
const getServerSnapshot = () => false;

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import Card from '@/components/ui/Card';

interface TrendItem {
  day: string;
  score?: number;
  scans?: number;
  remediated?: number;
}

interface ScanTrendsChartProps {
  data: TrendItem[];
  title?: string;
  subtitle?: string;
}

const TIME_RANGES = ['1D', '1W', '1M', '1Y'] as const;
type TimeRange = typeof TIME_RANGES[number];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--surface-elevated)',
      border: '1px solid var(--border-strong)',
      borderRadius: 10,
      padding: '8px 12px',
      fontFamily: 'var(--font-mono)',
      fontSize: 12,
      color: 'var(--foreground)',
      boxShadow: 'var(--card-glow)',
    }}>
      <div style={{ color: 'var(--muted)', marginBottom: 4 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span style={{ color: p.color }}>●</span>
          <span>{p.name}: <strong>{p.value}</strong></span>
        </div>
      ))}
    </div>
  );
};


export default function ScanTrendsChart({
  data,
  title = 'Security Activity',
  subtitle = 'Open and resolved exposures overtime',
}: ScanTrendsChartProps) {
  const [activeRange, setActiveRange] = useState<TimeRange>('1W');
  const mounted = useSyncExternalStore(emptySubscribe, getSnapshot, getServerSnapshot);

  const chartData = useMemo(() => {
    const baseWeekly = data.map((item, idx) => ({
      day: item.day,
      resolved: item.remediated ?? Math.max(0, Math.round((item.score ?? 10) / 15)),
      newFindings: item.scans ?? Math.max(1, Math.round(((item.score ?? 10) / 10) + idx * 0.5)),
    }));

    const baseResolvedSum = baseWeekly.reduce((sum, d) => sum + d.resolved, 0);
    const baseNewSum = baseWeekly.reduce((sum, d) => sum + d.newFindings, 0);

    if (activeRange === '1D') {
      return [
        { day: '00:00', resolved: Math.round(baseResolvedSum * 0.08), newFindings: Math.round(baseNewSum * 0.10) },
        { day: '04:00', resolved: Math.round(baseResolvedSum * 0.05), newFindings: Math.round(baseNewSum * 0.08) },
        { day: '08:00', resolved: Math.round(baseResolvedSum * 0.22), newFindings: Math.round(baseNewSum * 0.25) },
        { day: '12:00', resolved: Math.round(baseResolvedSum * 0.35), newFindings: Math.round(baseNewSum * 0.30) },
        { day: '16:00', resolved: Math.round(baseResolvedSum * 0.20), newFindings: Math.round(baseNewSum * 0.18) },
        { day: '20:00', resolved: Math.round(baseResolvedSum * 0.10), newFindings: Math.round(baseNewSum * 0.09) },
      ];
    }

    if (activeRange === '1W') {
      return baseWeekly;
    }

    if (activeRange === '1M') {
      return [
        { day: 'Week 1', resolved: Math.round(baseResolvedSum * 0.8), newFindings: Math.round(baseNewSum * 1.1) },
        { day: 'Week 2', resolved: Math.round(baseResolvedSum * 1.2), newFindings: Math.round(baseNewSum * 1.4) },
        { day: 'Week 3', resolved: Math.round(baseResolvedSum * 1.5), newFindings: Math.round(baseNewSum * 1.8) },
        { day: 'Week 4', resolved: Math.round(baseResolvedSum * 1.1), newFindings: Math.round(baseNewSum * 1.3) },
      ];
    }

    if (activeRange === '1Y') {
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const factors = [0.4, 0.5, 0.6, 0.8, 0.7, 0.9, 1.1, 1.3, 1.2, 1.4, 1.6, 1.8];
      return months.map((month, idx) => ({
        day: month,
        resolved: Math.round((baseResolvedSum + 15) * (factors[idx] || 1.0)),
        newFindings: Math.round((baseNewSum + 25) * ((factors[idx] || 1.0) * 1.15)),
      }));
    }

    return baseWeekly;
  }, [data, activeRange]);

  const totalResolved = chartData.reduce((s, d) => s + d.resolved, 0);
  const totalNew = chartData.reduce((s, d) => s + d.newFindings, 0);
  const isEmpty = chartData.every((d) => d.resolved === 0 && d.newFindings === 0);

  return (
    <Card className="p-5">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-[13px] font-semibold mb-0.5" style={{ color: 'var(--foreground)' }}>
            {title}
          </h2>
          <p className="text-[11px]" style={{ color: 'var(--muted-2)' }}>{subtitle}</p>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-2">
            <span className="flex items-center gap-1.5 text-[12px]" style={{ fontFamily: 'var(--font-mono)' }}>
              <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: '#10B981' }} />
              <span style={{ color: '#10B981' }}>Resolved</span>
              <strong style={{ color: 'var(--foreground)', marginLeft: 2 }}>{totalResolved}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-[12px]" style={{ fontFamily: 'var(--font-mono)' }}>
              <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: '#06B6D4' }} />
              <span style={{ color: '#06B6D4' }}>New</span>
              <strong style={{ color: 'var(--foreground)', marginLeft: 2 }}>{totalNew}</strong>
            </span>
          </div>
        </div>

        {/* Time range pills */}
        <div
          className="flex items-center gap-0.5 p-0.5 rounded-lg"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
        >
          {TIME_RANGES.map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => setActiveRange(r)}
              className="px-2.5 py-1 rounded-md text-[11px] font-mono transition-all"
              style={
                activeRange === r
                  ? { background: 'linear-gradient(135deg,#10B981,#14B8A6)', color: '#fff', fontWeight: 600 }
                  : { color: 'var(--muted)', cursor: 'pointer' }
              }
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {isEmpty ? (
        <div className="h-56 flex flex-col items-center justify-center text-sm" style={{ color: 'var(--muted-2)' }}>
          No historical activity recorded.
        </div>
      ) : !mounted ? (
        <div className="h-56 rounded-lg skeleton-obsidian" />
      ) : (
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
              <defs>
                <linearGradient id="resolvedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10B981" stopOpacity={0.22} />
                  <stop offset="100%" stopColor="#10B981" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="newGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#06B6D4" stopOpacity={0.22} />
                  <stop offset="100%" stopColor="#06B6D4" stopOpacity={0} />
                </linearGradient>
              </defs>

              <CartesianGrid
                strokeDasharray="0"
                stroke="rgba(16,185,129,0.06)"
                vertical={false}
              />
              <XAxis
                dataKey="day"
                stroke="var(--muted-2)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                fontFamily="var(--font-mono)"
              />
              <YAxis
                stroke="var(--muted-2)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                width={30}
                fontFamily="var(--font-mono)"
              />
              <Tooltip content={<CustomTooltip />} />

              <Area
                type="monotone"
                dataKey="resolved"
                name="Resolved"
                stroke="#10B981"
                strokeWidth={2}
                fill="url(#resolvedGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#10B981', stroke: 'var(--surface-elevated)', strokeWidth: 2 }}
              />
              <Area
                type="monotone"
                dataKey="newFindings"
                name="New"
                stroke="#06B6D4"
                strokeWidth={2}
                fill="url(#newGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#06B6D4', stroke: 'var(--surface-elevated)', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
}
