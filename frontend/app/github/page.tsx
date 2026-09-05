'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Github as GithubIcon, Lock } from 'lucide-react';
import ProtectedShell from '@/components/ProtectedShell';
import PageHeader from '@/components/ui/PageHeader';
import Card from '@/components/ui/Card';
import Badge from '@/components/ui/Badge';
import Button from '@/components/ui/Button';
import Alert from '@/components/ui/Alert';
import EmptyState from '@/components/ui/EmptyState';
import { githubApi } from '@/lib/api';

interface GithubStatus {
  connected: boolean;
  username?: string;
  avatarUrl?: string;
}

interface Repo {
  id: number;
  fullName: string;
  private: boolean;
  url: string;
  description: string | null;
}

interface WatchedRepo {
  repositoryId: string;
  githubRepo: string;
}

function GithubPageInner() {
  const params = useSearchParams();
  const callbackError = params.get('error');

  const [status, setStatus] = useState<GithubStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [reposError, setReposError] = useState<string | null>(null);
  const [watchedCount, setWatchedCount] = useState<number | null>(null);

  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await githubApi.status();
      setStatus(data);
      if (data.connected) {
        try {
          const reposRes = await githubApi.listRepos();
          setRepos(reposRes.data.repos);
        } catch (err: any) {
          setReposError(err?.response?.data?.error?.message || 'Could not load repositories');
        }
        try {
          const watchedRes = await githubApi.listWatched();
          setWatchedCount((watchedRes.data.repositories as WatchedRepo[]).length);
        } catch {
          // Non-critical to the page's main purpose — the disconnect
          // confirmation just won't show a repo count if this fails.
          setWatchedCount(null);
        }
      }
    } catch {
      setStatus({ connected: false });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const onConfirmDisconnect = async () => {
    setDisconnecting(true);
    setDisconnectError(null);
    try {
      await githubApi.disconnect();
      setRepos([]);
      setWatchedCount(null);
      setConfirmingDisconnect(false);
      await load();
    } catch (err: any) {
      setDisconnectError(err?.response?.data?.error?.message || 'Could not disconnect GitHub — please try again.');
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <ProtectedShell>
      <PageHeader
        eyebrow="main-service · GitHub OAuth"
        title="GitHub"
        description="Connect your own GitHub account. Patchline never sees your password, and the token is encrypted at rest."
      />

      {callbackError && (
        <Alert className="mb-6">Connection failed: {callbackError}</Alert>
      )}

      {loading ? (
        <p className="text-muted text-sm">Checking connection…</p>
      ) : status?.connected ? (
        <Card className="px-4 py-3.5 mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {status.avatarUrl ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={status.avatarUrl} alt={status.username} className="w-8 h-8 rounded-full" />
              ) : (
                <div className="w-8 h-8 rounded-full bg-surface-raised flex items-center justify-center text-muted">
                  <GithubIcon size={15} />
                </div>
              )}
              <div>
                <Badge tone="success" dot>Connected</Badge>
                <div className="text-muted text-sm mt-1.5">@{status.username}</div>
              </div>
            </div>
            {!confirmingDisconnect && (
              <Button variant="danger" size="sm" onClick={() => setConfirmingDisconnect(true)}>
                Disconnect
              </Button>
            )}
          </div>

          {confirmingDisconnect && (
            <div className="mt-4 pt-4 border-t border-border-strong">
              <p className="text-sm text-ink mb-1">Disconnect this GitHub account?</p>
              <p className="text-muted text-sm mb-3">
                This revokes Patchline&apos;s access token at GitHub{watchedCount ? (
                  <> and stops continuous scanning on <strong>{watchedCount}</strong> watched {watchedCount === 1 ? 'repository' : 'repositories'} (their push webhooks are removed too)</>
                ) : null}. You can reconnect at any time.
              </p>
              {disconnectError && <Alert className="mb-3">{disconnectError}</Alert>}
              <div className="flex gap-2">
                <Button variant="danger" size="sm" onClick={onConfirmDisconnect} disabled={disconnecting}>
                  {disconnecting ? 'Disconnecting…' : 'Yes, disconnect'}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setConfirmingDisconnect(false);
                    setDisconnectError(null);
                  }}
                  disabled={disconnecting}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </Card>
      ) : (
        <a href={githubApi.connectUrl()} className="inline-block mb-8">
          <Button className="gap-2">
            <GithubIcon size={15} /> Connect GitHub account
          </Button>
        </a>
      )}

      {status?.connected && (
        <>
          <h2 className="text-xs text-muted uppercase tracking-widest mb-3 font-mono">Repositories</h2>
          {reposError && <Alert className="mb-4">{reposError}</Alert>}
          {repos.length === 0 && !reposError ? (
            <EmptyState icon={Lock} title="No repositories found" description="Grant repo access when connecting, or add repositories on GitHub." />
          ) : (
            <div className="space-y-2">
              {repos.map((r) => (
                <Card key={r.id} className="px-4 py-3.5 flex items-center justify-between">
                  <div>
                    <a href={r.url} target="_blank" rel="noreferrer" className="text-ink text-sm hover:text-accent-strong transition-colors">
                      {r.fullName}
                    </a>
                    {r.description && <div className="text-muted text-sm mt-1">{r.description}</div>}
                  </div>
                  {r.private && <Badge tone="neutral">Private</Badge>}
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </ProtectedShell>
  );
}

export default function GithubPage() {
  return (
    <Suspense fallback={null}>
      <GithubPageInner />
    </Suspense>
  );
}
