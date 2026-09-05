'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Workflow, ExternalLink } from 'lucide-react';
import ProtectedShell from '@/components/ProtectedShell';
import PageHeader from '@/components/ui/PageHeader';
import Card from '@/components/ui/Card';
import Badge from '@/components/ui/Badge';
import Button from '@/components/ui/Button';
import Alert from '@/components/ui/Alert';
import { jiraApi } from '@/lib/api';

interface JiraStatus {
  connected: boolean;
  siteName?: string;
  siteUrl?: string;
}

function JiraPageInner() {
  const params = useSearchParams();
  const [status, setStatus] = useState<JiraStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [lastIssue, setLastIssue] = useState<{ key: string; url: string } | null>(null);

  const callbackError = params.get('error');

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await jiraApi.status();
      setStatus(data);
    } catch {
      setStatus({ connected: false });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const onDisconnect = async () => {
    await jiraApi.disconnect();
    load();
  };

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!summary.trim() || !description.trim()) return;
    setCreating(true);
    setCreateError(null);
    setLastIssue(null);
    try {
      const { data } = await jiraApi.createIssue({ summary, description });
      setLastIssue(data.issue);
      setSummary('');
      setDescription('');
    } catch (err: any) {
      setCreateError(err?.response?.data?.error?.message || 'Could not create Jira issue');
    } finally {
      setCreating(false);
    }
  };

  return (
    <ProtectedShell>
      <PageHeader
        eyebrow="main-service · Jira OAuth 2.0"
        title="Jira"
        description="Connect your own Jira account. Every teammate authorizes individually — there's no shared admin token."
      />

      {callbackError && <Alert className="mb-6">Connection failed: {callbackError}</Alert>}

      {loading ? (
        <p className="text-muted text-sm">Checking connection…</p>
      ) : status?.connected ? (
        <Card className="px-4 py-3.5 mb-8 flex items-center justify-between">
          <div>
            <Badge tone="success" dot>Connected</Badge>
            <div className="text-muted text-sm mt-1.5">
              {status.siteName} — {status.siteUrl}
            </div>
          </div>
          <Button variant="danger" size="sm" onClick={onDisconnect}>
            Disconnect
          </Button>
        </Card>
      ) : (
        <a href={jiraApi.connectUrl()} className="inline-block mb-8">
          <Button className="gap-2">
            <Workflow size={15} /> Connect Jira account
          </Button>
        </a>
      )}

      {status?.connected && (
        <Card className="p-5 max-w-lg">
          <h2 className="text-xs text-muted uppercase tracking-widest mb-4 font-mono">Create an issue</h2>
          <form onSubmit={onCreate} className="space-y-3">
            <input
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Summary"
              className="w-full bg-canvas border border-border rounded-md px-3 py-2.5 text-sm text-ink placeholder:text-faint focus:border-accent outline-none transition-colors"
            />
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
              placeholder="Description"
              className="w-full bg-canvas border border-border rounded-md px-3 py-2.5 text-sm text-ink placeholder:text-faint focus:border-accent outline-none resize-none transition-colors"
            />
            <Button type="submit" disabled={creating}>
              {creating ? 'Creating…' : 'Create issue'}
            </Button>
          </form>
          {createError && <Alert className="mt-3">{createError}</Alert>}
          {lastIssue && (
            <div className="mt-4 flex items-center gap-2 text-sm text-success">
              Created{' '}
              <a href={lastIssue.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline underline-offset-2">
                {lastIssue.key} <ExternalLink size={12} />
              </a>
            </div>
          )}
        </Card>
      )}
    </ProtectedShell>
  );
}

export default function JiraPage() {
  return (
    <Suspense fallback={null}>
      <JiraPageInner />
    </Suspense>
  );
}
