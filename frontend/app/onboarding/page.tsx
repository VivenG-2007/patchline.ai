'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Github as GithubIcon, Workflow, Check, ArrowRight, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { githubApi, jiraApi, getConnectionStatus } from '@/lib/api';
import Button from '@/components/ui/Button';
import Card from '@/components/ui/Card';
import Alert from '@/components/ui/Alert';
import ThemeToggle from '@/components/ThemeToggle';

import LoadingScreen from '@/components/LoadingScreen';

type Step = 1 | 2 | 3;

const STEPS: { step: Step; label: string }[] = [
  { step: 1, label: 'GitHub' },
  { step: 2, label: 'Jira' },
  { step: 3, label: 'Ready' },
];

function OnboardingInner() {
  const router = useRouter();
  const params = useSearchParams();
  const { user, loading: authLoading } = useAuth();

  const [resolving, setResolving] = useState(true);
  const [step, setStep] = useState<Step>(1);
  const [githubConnected, setGithubConnected] = useState(false);
  const [jiraConnected, setJiraConnected] = useState(false);
  const [launching, setLaunching] = useState(false);

  const oauthError = params.get('error');
  const justConnected = params.get('provider');

  useEffect(() => {
    if (!authLoading && !user) router.push('/login');
  }, [authLoading, user, router]);

  useEffect(() => {
    if (!user) return;
    getConnectionStatus().then(({ githubConnected, jiraConnected }) => {
      setGithubConnected(githubConnected);
      setJiraConnected(jiraConnected);

      const stepParam = Number(params.get('step'));
      if (stepParam === 1 || stepParam === 2 || stepParam === 3) {
        setStep(stepParam as Step);
      } else if (!githubConnected) {
        setStep(1);
      } else if (!jiraConnected) {
        setStep(2);
      } else {
        setStep(3);
      }
      setResolving(false);
    });
  }, [user, params]);

  if (launching) {
    return (
      <LoadingScreen
        title="Finalizing Account Setup…"
        subtitle="Configuring security scanners & initializing workspace telemetry."
        durationMs={2400}
        onComplete={() => router.push('/dashboard')}
      />
    );
  }

  if (authLoading || resolving) {
    return (
      <div className="min-h-screen bg-bg-base flex items-center justify-center">
        <div className="w-2 h-2 rounded-full bg-accent-cyan pulse-dot" />
      </div>
    );
  }
  if (!user) return null;

  const goToStep = (s: Step) => {
    setStep(s);
    router.replace(`/onboarding?step=${s}`);
  };

  return (
    <div className="min-h-screen bg-bg-base grid-overlay flex items-center justify-center px-4 sm:px-6 py-16 relative">
      <ThemeToggle className="absolute top-6 right-6" />

      <div className="w-full max-w-lg">
        <Link href="/" className="flex items-center gap-2.5 mb-8 w-fit group">
          <div className="w-8 h-8 rounded-xl bg-accent-cyan-soft border border-accent-cyan/30 flex items-center justify-center text-accent-cyan shadow-sm group-hover:scale-105 transition-transform">
            <ShieldCheck size={18} strokeWidth={2.2} />
          </div>
          <span className="font-display font-bold text-xl text-text-primary">
            PatchLine <span className="text-accent-cyan font-mono text-xs">AI</span>
          </span>
        </Link>

        {/* Sequential Stepper */}
        <div className="flex items-center gap-2 mb-8">
          {STEPS.map(({ step: s, label }, i) => (
            <div key={s} className="flex items-center gap-2 flex-1">
              <div
                className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-mono shrink-0 border transition-all ${
                  step > s
                    ? 'bg-accent-emerald-soft border-accent-emerald text-accent-emerald'
                    : step === s
                    ? 'bg-accent-cyan-soft border-accent-cyan text-accent-cyan font-bold ring-2 ring-accent-cyan/30'
                    : 'bg-bg-subtle border-border-default text-text-muted'
                }`}
              >
                {step > s ? <Check size={13} strokeWidth={2.5} /> : s}
              </div>
              <span className={`text-xs font-mono ${step >= s ? 'text-text-primary font-medium' : 'text-text-muted'}`}>
                {label}
              </span>
              {i < STEPS.length - 1 && (
                <div className={`flex-1 h-0.5 ${step > s ? 'bg-accent-emerald' : 'bg-border-default'}`} />
              )}
            </div>
          ))}
        </div>

        <Card className="p-8 shadow-2xl">
          {oauthError && (
            <Alert className="mb-6">Connection failed: {oauthError}</Alert>
          )}
          {justConnected && !oauthError && (
            <Alert tone="success" className="mb-6">
              {justConnected === 'github' ? 'GitHub' : 'Jira'} connected successfully.
            </Alert>
          )}

          {step === 1 && (
            <StepCard
              icon={GithubIcon}
              eyebrow="Step 1 of 2 · Integration"
              title="Connect GitHub Organization"
              description="Patchline scans your repositories, checks AST syntax, and opens tested pull requests once fixes are approved."
              connected={githubConnected}
              onConnect={async () => {
                const res = await githubApi.connect('/onboarding?step=2');
                window.location.href = res.data.url;
              }}
              connectLabel="Connect GitHub Account"
              onSkip={() => goToStep(2)}
              onContinue={() => goToStep(2)}
            />
          )}

          {step === 2 && (
            <StepCard
              icon={Workflow}
              eyebrow="Step 2 of 2 · Ticketing"
              title="Connect Atlassian Jira"
              description="Optional — Patchline automatically creates tracked Jira issue tickets for discovered high-severity vulnerabilities."
              connected={jiraConnected}
              onConnect={async () => {
                const res = await jiraApi.connect('/onboarding?step=3');
                window.location.href = res.data.url;
              }}
              connectLabel="Connect Jira Cloud"
              onSkip={() => goToStep(3)}
              onContinue={() => goToStep(3)}
            />
          )}

          {step === 3 && (
            <div className="space-y-6">
              <div className="w-12 h-12 rounded-xl bg-accent-emerald-soft border border-accent-emerald/30 flex items-center justify-center text-accent-emerald shadow-sm">
                <Check size={22} strokeWidth={2.5} />
              </div>
              <div>
                <h1 className="font-display text-2xl font-bold text-text-primary">Workspace Ready</h1>
                <p className="text-xs text-text-secondary mt-1 leading-relaxed">
                  {githubConnected ? 'GitHub is active.' : "GitHub isn't connected yet — you can link repositories anytime from settings."}{' '}
                  {jiraConnected ? 'Jira integration is enabled.' : 'Jira can be connected later if desired.'}
                </p>
              </div>
              <Button onClick={() => setLaunching(true)} className="w-full py-2.5 font-mono text-xs gap-2">
                Launch Security Dashboard <ArrowRight size={14} />
              </Button>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function StepCard({
  icon: Icon,
  eyebrow,
  title,
  description,
  connected,
  connectHref,
  connectLabel,
  onSkip,
  onContinue,
  onConnect,
}: {
  icon: typeof GithubIcon;
  eyebrow: string;
  title: string;
  description: string;
  connected: boolean;
  connectLabel: string;
  onConnect: () => Promise<void>;
  onSkip: () => void;
  onContinue: () => void;
}) {
  const [connecting, setConnecting] = useState(false);
  const handleConnect = async () => {
    setConnecting(true);
    try { await onConnect(); } finally { setConnecting(false); }
  };
  return (
    <div className="space-y-6">
      <div>
        <span className="font-mono text-xs uppercase tracking-wider text-accent-cyan font-semibold">
          {eyebrow}
        </span>
        <h1 className="font-display text-2xl font-bold text-text-primary mt-1">{title}</h1>
        <p className="text-xs text-text-secondary mt-1.5 leading-relaxed">{description}</p>
      </div>

      {connected ? (
        <div className="flex items-center gap-2 text-xs font-mono text-accent-emerald bg-accent-emerald-soft p-3 rounded-lg border border-accent-emerald/30">
          <Check size={14} strokeWidth={2.5} /> Integration Active
        </div>
      ) : (
        <Button
          className="w-full py-2.5 text-xs font-mono gap-2"
          disabled={connecting}
          onClick={handleConnect}
        >
          <Icon size={16} /> {connecting ? 'Redirecting…' : connectLabel}
        </Button>
      )}

      {connected ? (
        <Button variant="secondary" onClick={onContinue} className="w-full py-2.5 text-xs font-mono">
          Continue to Next Step
        </Button>
      ) : (
        <button
          type="button"
          onClick={onSkip}
          className="text-xs font-mono text-text-muted hover:text-text-primary transition-colors w-full text-center py-2"
        >
          Skip for now →
        </button>
      )}
    </div>
  );
}

export default function OnboardingPage() {
  return (
    <Suspense fallback={null}>
      <OnboardingInner />
    </Suspense>
  );
}
