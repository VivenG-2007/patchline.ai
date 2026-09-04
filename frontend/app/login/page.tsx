'use client';

import { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, ArrowRight, Loader2, Lock, Mail, User, Eye, EyeOff, Check } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { getConnectionStatus } from '@/lib/api';
import Alert from '@/components/ui/Alert';
import Button from '@/components/ui/Button';
import Card from '@/components/ui/Card';
import ThemeToggle from '@/components/ThemeToggle';
import { PasswordStrength } from '@/components/ui/password-strength';

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const isRegister = params.get('mode') === 'register';
  const { login, register, error } = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      if (isRegister) {
        await register(name, email, password);
        setSuccess(true);
        setTimeout(() => router.push('/onboarding'), 600);
      } else {
        await login(email, password);
        setSuccess(true);
        // Default to /dashboard — only redirect to /onboarding if we
        // *positively* know both integrations are missing. If main_services
        // is unreachable the status check will throw/reject, and we should
        // still let the user into the dashboard rather than loop them into
        // the onboarding wizard on every login.
        let destination = '/dashboard';
        try {
          const { githubConnected, jiraConnected } = await getConnectionStatus();
          if (!githubConnected && !jiraConnected) destination = '/onboarding';
        } catch {
          // main_services unreachable — don't block the user, go to dashboard
        }
        setTimeout(() => router.push(destination), 600);
      }
    } catch {
      // error surfaced via useAuth().error
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="min-h-screen bg-bg-base grid-overlay flex items-center justify-center px-4 sm:px-6 relative py-12">
      <ThemeToggle className="absolute top-6 right-6" />

      <div className="w-full max-w-md animate-scale-in">
        <Link href="/" className="flex items-center gap-2.5 mb-8 w-fit group">
          <div className="w-8 h-8 rounded-xl bg-accent-cyan-soft border border-accent-cyan/30 flex items-center justify-center text-accent-cyan shadow-sm group-hover:scale-105 transition-transform">
            <ShieldCheck size={18} strokeWidth={2.2} />
          </div>
          <span className="font-display font-bold text-xl text-text-primary">
            PatchLine <span className="text-accent-cyan font-mono text-xs">AI</span>
          </span>
        </Link>

        <Card className={`p-8 shadow-2xl transition-all duration-300 ${error ? 'animate-shake border-accent-rose/40' : ''}`}>
          <div className="mb-6">
            <span className="font-mono text-xs tracking-wider text-accent-cyan uppercase font-semibold">
              {isRegister ? 'Workspace Creation' : 'Enterprise Authentication'}
            </span>
            <h1 className="font-display text-2xl font-bold mt-1 text-text-primary">
              {isRegister ? 'Set up your workspace' : 'Log in to PatchLine'}
            </h1>
            <p className="text-xs text-text-secondary mt-1">
              Autonomous security analysis &amp; verified patch synthesis
            </p>
          </div>

          <form onSubmit={onSubmit} className="space-y-4">
            {isRegister && (
              <div className="space-y-1">
                <label className="block text-xs font-mono text-text-muted">Full Name</label>
                <div className="relative">
                  <User size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
                  <input
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    className="w-full pl-9 pr-3.5 py-2.5 bg-bg-subtle border border-border-default focus:border-accent-cyan focus:ring-2 focus:ring-accent-cyan/20 rounded-lg text-xs font-mono text-text-primary placeholder:text-text-muted outline-none transition-all duration-200"
                  />
                </div>
              </div>
            )}

            <div className="space-y-1">
              <label className="block text-xs font-mono text-text-muted">Work Email</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  required
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jane@company.com"
                  className="w-full pl-9 pr-3.5 py-2.5 bg-bg-subtle border border-border-default focus:border-accent-cyan focus:ring-2 focus:ring-accent-cyan/20 rounded-lg text-xs font-mono text-text-primary placeholder:text-text-muted outline-none transition-all duration-200"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="block text-xs font-mono text-text-muted">Password (min. 8 characters)</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  required
                  type={showPassword ? 'text' : 'password'}
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-9 pr-10 py-2.5 bg-bg-subtle border border-border-default focus:border-accent-cyan focus:ring-2 focus:ring-accent-cyan/20 rounded-lg text-xs font-mono text-text-primary placeholder:text-text-muted outline-none transition-all duration-200"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors p-1"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {/* Interactive Password Strength meter */}
            {password.length > 0 && (
              <div className="pt-1 pb-1">
                <PasswordStrength
                  value={password}
                  showRules={isRegister}
                  className="animate-fade-rise-in font-mono text-xs"
                />
              </div>
            )}

            {error && (
              <div className="animate-fade-rise-in">
                <Alert tone="critical">{error}</Alert>
              </div>
            )}

            <Button
              type="submit"
              disabled={submitting || success}
              className={`w-full py-2.5 text-xs font-mono transition-all duration-300 ${
                success ? 'bg-accent-emerald text-white animate-pulse-success' : ''
              }`}
            >
              {submitting ? (
                <span className="flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin" /> Verifying…
                </span>
              ) : success ? (
                <span className="flex items-center gap-2 font-bold">
                  <Check size={14} strokeWidth={3} /> Authenticated
                </span>
              ) : isRegister ? (
                'Create Account & Onboard'
              ) : (
                'Log In to Console'
              )}
            </Button>
          </form>

          <p className="mt-6 text-xs text-text-muted font-mono text-center">
            {isRegister ? 'Already have an account? ' : "Don't have an account yet? "}
            <Link
              href={isRegister ? '/login' : '/login?mode=register'}
              className="text-accent-cyan hover:underline font-semibold"
            >
              {isRegister ? 'Sign in' : 'Create one now'}
            </Link>
          </p>
        </Card>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
