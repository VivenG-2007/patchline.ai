import Link from 'next/link';
import {
  ArrowRight,
  ShieldCheck,
  GitPullRequest,
  Radar,
  Sparkles,
  Lock,
  Cpu,
  ShieldAlert,
  FileCheck2,
  Check,
} from 'lucide-react';
import ServiceStatus from '@/components/ServiceStatus';
import TopNav from '@/components/TopNav';
import { GradientButton } from '@/components/ui/gradient-button';

const PILLARS = [
  {
    icon: Radar,
    title: 'Find it',
    body: 'Point it at any repository. 8-stage deterministic SAST + AI analysis returns CWE-tagged findings with exact coordinates.',
  },
  {
    icon: ShieldCheck,
    title: 'Fix it',
    body: 'Every fix is synthesized on an isolated branch and gated for human review with a 3-attempt safety threshold.',
  },
  {
    icon: Sparkles,
    title: 'Verify it',
    body: 'The generated patch undergoes deterministic AST re-scanning and test execution to certify 0 regressions.',
  },
  {
    icon: GitPullRequest,
    title: 'Ship it',
    body: 'One-click human approval triggers a direct Pull Request dispatch on GitHub, ready for team merge.',
  },
];

const SOLUTIONS = [
  {
    icon: ShieldAlert,
    title: 'Security Teams',
    body: 'Triage every finding against a deterministic, versioned risk score instead of raw severity. Prioritize the SQL injection on an internet-facing service over the hardcoded test credential in a sandbox repo.',
  },
  {
    icon: Cpu,
    title: 'Platform Engineering',
    body: 'Wire PatchLine into CI with GitHub webhooks. Every push triggers an incremental rescan, and verified fixes arrive as ordinary pull requests your team already knows how to review and merge.',
  },
  {
    icon: FileCheck2,
    title: 'Compliance & Audit',
    body: 'Every verified remediation carries initial risk, final risk, and risk-reduction percentage — plus a full attempt history, including failed strategies — as durable evidence for SOC 2 and ISO 27001 audits.',
  },
];

const PRICING_TIERS = [
  {
    name: 'Starter',
    price: 'Free',
    cadence: '',
    description: 'For individual developers evaluating PatchLine on a single repository.',
    features: ['1 connected repository', 'Deterministic SAST scanning', 'Manual scan triggers', 'Community support'],
    cta: 'Start scanning',
    highlighted: false,
  },
  {
    name: 'Team',
    price: '$79',
    cadence: '/ month',
    description: 'For engineering teams running continuous remediation across active repositories.',
    features: [
      'Unlimited repositories up to 300 files',
      'AI root-cause analysis & RAG-ranked fixes',
      'Independent Codex verification',
      'GitHub webhook auto-rescan',
      'Jira ticket sync',
    ],
    cta: 'Start free trial',
    highlighted: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    cadence: '',
    description: 'For organizations with compliance, scale, and dedicated support requirements.',
    features: [
      'Unlimited repository size',
      'SOC 2 audit-ready remediation history',
      'SSO & role-based access control',
      'Dedicated support & onboarding',
    ],
    cta: 'Talk to sales',
    highlighted: false,
  },
];

const JSON_LD = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'PatchLine',
  applicationCategory: 'SecurityApplication',
  operatingSystem: 'Web',
  description:
    'AI-powered autonomous application-security platform combining deterministic SAST scanning, AI root-cause analysis, quantitative risk assessment, and verified GitHub pull-request remediation.',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
};

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-bg-base transition-colors duration-300">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }} />
      <TopNav />

      {/* Hero section */}
      <section className="relative overflow-hidden grid-overlay pt-16">
        <div className="max-w-6xl mx-auto px-6 pt-20 pb-24 text-center">
          <div className="inline-flex items-center gap-2 font-mono text-xs text-accent-cyan border border-accent-cyan/30 bg-accent-cyan-soft rounded-full px-3.5 py-1.5 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-accent-cyan pulse-dot" />
            PatchLine Autonomous Remediation Engine v2.0 Live
          </div>

          <h1 className="font-display text-5xl md:text-6xl lg:text-7xl font-bold leading-[1.05] tracking-tight mt-6 text-text-primary">
            Find it. <span className="text-accent-cyan">Fix it.</span> Verify it.{' '}
            <span className="text-accent-emerald">Ship it.</span>
          </h1>

          <p className="mt-6 text-text-secondary text-lg leading-relaxed max-w-2xl mx-auto font-sans">
            Autonomous vulnerability discovery, GPT-4.1 mini isolated patch synthesis, and deterministic regression verification for modern engineering teams.
          </p>

          <div className="mt-9 flex items-center justify-center gap-4 flex-wrap">
            <Link href="/login?mode=register">
              <GradientButton className="text-xs font-mono py-3 px-6 gap-2">
                Launch Free Scanner <ArrowRight size={15} />
              </GradientButton>
            </Link>
            <Link
              href="/login"
              className="inline-flex items-center gap-2 border border-border-default hover:border-border-hover bg-bg-card text-text-primary font-semibold rounded-xl px-6 py-3 text-xs font-mono hover:bg-bg-subtle transition-all shadow-sm active:scale-95"
            >
              Sign In to Console
            </Link>
          </div>

          {/* Interactive Console Teaser */}
          <div className="relative mt-16 max-w-3xl mx-auto">
            <div className="relative bg-bg-card border border-border-default rounded-2xl overflow-hidden shadow-2xl text-left transition-all">
              <div className="scanline" />
              <div className="grid sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-border-default">
                <div className="p-4 space-y-2">
                  <div className="font-mono text-[10px] text-accent-cyan uppercase tracking-wider font-semibold">
                    8-Stage Pipeline
                  </div>
                  <div className="text-xs text-text-secondary space-y-1.5">
                    <div className="flex items-center gap-1.5 font-mono">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald" /> AST Syntax Tree Built
                    </div>
                    <div className="flex items-center gap-1.5 font-mono">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald" /> Semgrep SAST Executed
                    </div>
                    <div className="flex items-center gap-1.5 font-mono text-accent-rose font-semibold">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-rose pulse-dot" /> CWE-89 Flaw Caught
                    </div>
                  </div>
                </div>

                <div className="p-4 space-y-1.5">
                  <div className="font-mono text-[10px] text-accent-rose uppercase tracking-wider font-semibold">
                    Discovered Flaw
                  </div>
                  <div className="text-xs text-text-primary font-mono font-bold">SQL Injection in Controller</div>
                  <div className="text-xs text-text-secondary leading-relaxed">Raw string template in db.query</div>
                  <div className="text-[11px] font-mono text-accent-rose bg-accent-rose-soft/80 px-2 py-0.5 rounded inline-block">
                    − const q = `SELECT * WHERE id = &apos;${'${userId}'}&apos;`
                  </div>
                </div>

                <div className="p-4 space-y-1.5">
                  <div className="font-mono text-[10px] text-accent-emerald uppercase tracking-wider font-semibold">
                    Synthesized Patch
                  </div>
                  <div className="text-xs text-text-primary font-mono font-bold">Parameterized Query</div>
                  <div className="text-xs text-text-secondary leading-relaxed">0 Regressions Certified</div>
                  <div className="text-[11px] font-mono text-accent-emerald bg-accent-emerald-soft/80 px-2 py-0.5 rounded inline-block">
                    + const q = &apos;SELECT * WHERE id = $1&apos;
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Pillars */}
      <section id="product" className="border-t border-border-default py-20 bg-bg-card/40">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="font-mono text-xs uppercase tracking-widest text-accent-cyan">Autonomous Architecture</span>
            <h2 className="font-display text-3xl md:text-4xl font-bold text-text-primary mt-2">
              Trusted engineering workflow with human-in-the-loop gates
            </h2>
          </div>

          <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-6">
            {PILLARS.map(({ icon: Icon, title, body }) => (
              <div key={title} className="p-6 rounded-2xl border border-border-default bg-bg-card hover:border-border-hover transition-all group">
                <div className="w-10 h-10 rounded-xl bg-accent-cyan-soft border border-accent-cyan/30 flex items-center justify-center text-accent-cyan mb-4 group-hover:scale-110 transition-transform">
                  <Icon size={18} strokeWidth={2} />
                </div>
                <h3 className="font-display text-lg font-bold text-text-primary mb-2">{title}</h3>
                <p className="text-text-secondary text-xs leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Solutions */}
      <section id="solutions" className="border-t border-border-default py-20">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="font-mono text-xs uppercase tracking-widest text-accent-cyan">Built For Your Team</span>
            <h2 className="font-display text-3xl md:text-4xl font-bold text-text-primary mt-2">
              One remediation engine, three ways to use it
            </h2>
          </div>

          <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-6">
            {SOLUTIONS.map(({ icon: Icon, title, body }) => (
              <div key={title} className="p-6 rounded-2xl border border-border-default bg-bg-card hover:border-border-hover transition-all group">
                <div className="w-10 h-10 rounded-xl bg-accent-emerald-soft border border-accent-emerald/30 flex items-center justify-center text-accent-emerald mb-4 group-hover:scale-110 transition-transform">
                  <Icon size={18} strokeWidth={2} />
                </div>
                <h3 className="font-display text-lg font-bold text-text-primary mb-2">{title}</h3>
                <p className="text-text-secondary text-xs leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture & Services Status */}
      <section id="architecture" className="border-t border-border-default py-20">
        <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-2 gap-12 items-start">
          <div className="space-y-6">
            <div>
              <span className="font-mono text-xs tracking-widest text-accent-cyan uppercase font-semibold">
                Architecture Blueprint
              </span>
              <h2 className="font-display text-3xl font-bold mt-2 text-text-primary">
                Multi-service isolation, zero-trust boundary
              </h2>
            </div>

            <div className="space-y-4 font-mono text-xs">
              {[
                ['auth-service', 'RS256 asymmetric JWT rotation, httpOnly secure cookies, refresh rotation.'],
                ['main-service', 'High-throughput Node.js gateway with local JWT verification & Redis BullMQ queue.'],
                ['ai-storage-service', 'FastAPI Python daemon with AST Tree-sitter, Semgrep engine, and Azure Blob storage.'],
              ].map(([name, desc]) => (
                <div key={name} className="p-4 rounded-xl border border-border-default bg-bg-card flex items-start gap-3">
                  <Cpu size={16} className="text-accent-cyan mt-0.5 shrink-0" />
                  <div>
                    <div className="font-semibold text-text-primary">{name}</div>
                    <div className="text-text-secondary text-xs mt-1 leading-relaxed font-sans">{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <ServiceStatus />
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="border-t border-border-default py-20 bg-bg-card/40">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="font-mono text-xs uppercase tracking-widest text-accent-cyan">Predictable Pricing</span>
            <h2 className="font-display text-3xl md:text-4xl font-bold text-text-primary mt-2">
              Scale from solo developer to enterprise fleet
            </h2>
          </div>

          <div className="grid md:grid-cols-3 gap-6 items-stretch">
            {PRICING_TIERS.map((tier) => (
              <div
                key={tier.name}
                className={`relative flex flex-col p-6 rounded-2xl border transition-all ${tier.highlighted
                    ? 'border-accent-cyan bg-bg-card shadow-lg scale-[1.02]'
                    : 'border-border-default bg-bg-card hover:border-border-hover'
                  }`}
              >
                {tier.highlighted && (
                  <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-accent-cyan text-white text-[10px] font-mono font-semibold px-3 py-1 rounded-full shadow-sm">
                    Most Popular
                  </span>
                )}
                <h3 className="font-display text-lg font-bold text-text-primary">{tier.name}</h3>
                <div className="mt-2 flex items-baseline gap-1">
                  <span className="font-display text-3xl font-bold text-text-primary">{tier.price}</span>
                  {tier.cadence && <span className="text-xs text-text-muted font-mono">{tier.cadence}</span>}
                </div>
                <p className="text-text-secondary text-xs leading-relaxed mt-3 min-h-[48px]">{tier.description}</p>

                <ul className="mt-4 space-y-2.5 flex-1">
                  {tier.features.map((f) => (
                    <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                      <Check size={14} className="text-accent-emerald shrink-0 mt-0.5" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>

                <Link href="/login?mode=register" className="mt-6 block">
                  <button
                    type="button"
                    className={
                      tier.highlighted
                        ? 'pl-btn-primary w-full justify-center'
                        : 'pl-btn-secondary w-full justify-center'
                    }
                  >
                    {tier.cta}
                  </button>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border-default py-14 bg-bg-card/60">
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-8 pb-10">
            <div className="space-y-3 col-span-2 md:col-span-1">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-accent-cyan-soft border border-accent-cyan/30 flex items-center justify-center text-accent-cyan">
                  <ShieldCheck size={15} strokeWidth={2.2} />
                </div>
                <span className="font-display font-bold text-sm text-text-primary">PatchLine AI</span>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed max-w-[220px]">
                Autonomous vulnerability detection, risk-aware remediation, and verified pull requests.
              </p>
            </div>

            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-text-muted mb-3">Product</div>
              <ul className="space-y-2 text-xs text-text-secondary">
                <li><a href="#product" className="hover:text-text-primary transition-colors">Product overview</a></li>
                <li><a href="#solutions" className="hover:text-text-primary transition-colors">Solutions</a></li>
                <li><a href="#architecture" className="hover:text-text-primary transition-colors">Architecture</a></li>
                <li><a href="#pricing" className="hover:text-text-primary transition-colors">Pricing</a></li>
              </ul>
            </div>

            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-text-muted mb-3">Account</div>
              <ul className="space-y-2 text-xs text-text-secondary">
                <li><Link href="/login" className="hover:text-text-primary transition-colors">Sign in</Link></li>
                <li><Link href="/login?mode=register" className="hover:text-text-primary transition-colors">Create account</Link></li>
                <li><Link href="/dashboard" className="hover:text-text-primary transition-colors">Dashboard</Link></li>
              </ul>
            </div>

            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-text-muted mb-3">Company</div>
              <ul className="space-y-2 text-xs text-text-secondary">
                <li><a href="mailto:hello@patchline.ai" className="hover:text-text-primary transition-colors">Contact</a></li>
                <li><a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-text-primary transition-colors">GitHub</a></li>
              </ul>
            </div>
          </div>

          <div className="pt-6 border-t border-border-default flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-text-muted">
            <span>© {new Date().getFullYear()} PatchLine AI Technologies. All rights reserved.</span>
            <span className="flex items-center gap-2">
              <Lock size={12} className="text-accent-emerald" /> Enterprise Grade · SOC2 Type II Certified
            </span>
          </div>
        </div>
      </footer>
    </main>
  );
}
