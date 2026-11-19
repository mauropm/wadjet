import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, ShieldAlert } from 'lucide-react';
import { WadjetEye } from '@/components/logo';
import { Button } from '@/components/ui/button';
import { Field, Input } from '@/components/ui/input';
import { useAuth } from '@/lib/auth';
import { ApiError } from '@/api/client';

export default function LoginPage() {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'login') {
        await login(email.trim(), password);
      } else {
        await register(email.trim(), name.trim(), password);
      }
      navigate('/', { replace: true });
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? 'Invalid email or password 👁️ The eye sees all, but not that combo.'
          : err instanceof Error
            ? err.message
            : 'Authentication failed',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base px-4">
      {/* ambient glows */}
      <div
        aria-hidden
        className="pointer-events-none absolute -top-40 left-1/2 h-96 w-[42rem] -translate-x-1/2 rounded-full bg-accent/10 blur-3xl"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -bottom-48 right-10 h-80 w-80 rounded-full bg-gold/5 blur-3xl"
      />

      <div className="relative w-full max-w-md animate-fade-in">
        <div className="mb-8 flex flex-col items-center text-center">
          <WadjetEye className="h-16 text-accent" title="WADJET — the eye sees everything" />
          <h1 className="mt-4 text-3xl font-bold tracking-[0.28em] text-ink">WADJET</h1>
          <p className="mt-2 text-sm text-mute">
            👁️ We see what your assets are hiding.
          </p>
        </div>

        <div className="rounded-2xl border border-line bg-raised/95 p-6 shadow-glow backdrop-blur sm:p-7">
          <div className="mb-5 flex items-center gap-2 text-[13px] font-semibold text-ink">
            <Eye className="h-4 w-4 text-accent" aria-hidden />
            {mode === 'login' ? 'Sign in to continue' : 'Create your account'}
          </div>

          <form onSubmit={submit} className="space-y-4" noValidate>
            {mode === 'register' && (
              <Field label="Name" required>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Ada Lovelace"
                  autoComplete="name"
                  required
                />
              </Field>
            )}
            <Field label="Email" required>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
                required
              />
            </Field>
            <Field
              label="Password"
              required
              hint={mode === 'register' ? 'min 10 chars' : undefined}
            >
              <div className="relative">
                <Input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••"
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  className="pr-16"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPw((s) => !s)}
                  className="absolute inset-y-0 right-2 my-auto h-fit rounded px-1.5 py-1 text-[11px] font-medium text-mute hover:text-ink"
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? 'hide' : 'show'}
                </button>
              </div>
            </Field>

            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-xl border border-sev-critical/30 bg-sev-critical/10 px-3 py-2.5 text-[13px] text-sev-critical"
              >
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                {error}
              </div>
            )}

            <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy}>
              {mode === 'login' ? '👁️ Enter the eye' : 'Create account'}
            </Button>
          </form>

          <p className="mt-5 text-center text-[13px] text-mute">
            {mode === 'login' ? (
              <>
                No account yet?{' '}
                <button
                  type="button"
                  className="font-medium text-accent-soft hover:underline"
                  onClick={() => {
                    setMode('register');
                    setError(null);
                  }}
                >
                  Register
                </button>
              </>
            ) : (
              <>
                Already have an account?{' '}
                <button
                  type="button"
                  className="font-medium text-accent-soft hover:underline"
                  onClick={() => {
                    setMode('login');
                    setError(null);
                  }}
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </div>

        <p className="mt-6 text-center text-[11.5px] text-mute/60">
          Open-source vulnerability intelligence · self-hosted · no telemetry
        </p>
      </div>
    </div>
  );
}
