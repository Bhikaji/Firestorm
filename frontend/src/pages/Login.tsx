import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import api, { ApiError } from '../services/api'
import { useAuth } from '../services/auth'

function formatWait(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`
  const minutes = Math.ceil(seconds / 60)
  return `${minutes} minute${minutes === 1 ? '' : 's'}`
}

export default function LoginPage() {
  const { user, signIn, loading } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfa, setMfa] = useState('')
  const [needsMfa, setNeedsMfa] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [errorRef, setErrorRef] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [apiReachable, setApiReachable] = useState<boolean | null>(null)
  const devEmail = import.meta.env.VITE_DEV_LOGIN_EMAIL
  const devPassword = import.meta.env.VITE_DEV_LOGIN_PASSWORD

  useEffect(() => {
    api
      .readiness()
      .then(() => setApiReachable(true))
      .catch(() => setApiReachable(false))
  }, [])

  if (!loading && user) return <Navigate to="/" replace />

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setErrorRef(null)
    try {
      await signIn(email.trim(), password, mfa.trim() || undefined)
      navigate('/', { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        const ref = err.requestId
          ? `HTTP ${err.status} · ${err.code} · ref ${err.requestId.slice(0, 8)}`
          : `HTTP ${err.status} · ${err.code}`
        setErrorRef(ref)
        if (err.message.toLowerCase().includes('multi-factor')) {
          setNeedsMfa(true)
          setError('Enter the six-digit code from your authenticator app.')
        } else if (err.status === 429) {
          const wait = Number(err.details?.retry_after_seconds ?? 0)
          setError(
            wait > 0
              ? `Too many sign-in attempts from this network. Try again in ${formatWait(wait)}.`
              : 'Too many sign-in attempts from this network. Try again shortly.',
          )
        } else {
          setError(err.message)
        }
      } else if (err instanceof Error && err.message) {
        setError(err.message)
        setErrorRef('client-side error (see browser console)')
      } else {
        setError('Sign-in failed. The API did not respond — check that the backend is running.')
        setErrorRef('network error (no HTTP response)')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_0.9fr]">
      <section className="relative hidden flex-col justify-between overflow-hidden border-r border-white/[0.06] bg-graphite-950 p-10 lg:flex">
        <div className="absolute inset-0 bg-grid-faint opacity-[0.35]" aria-hidden />
        <div className="relative">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 text-lg font-bold text-neon-cyan">
              F
            </span>
            <div>
              <p className="text-sm font-semibold tracking-[0.22em] text-slate-100">FIRESTORM</p>
              <p className="text-[10px] uppercase tracking-[0.28em] text-neon-cyan/70">Command center</p>
            </div>
          </div>
        </div>

        <div className="relative max-w-lg">
          <h1 className="text-3xl font-semibold leading-tight tracking-tight text-slate-100">
            Layered defence for networks you are authorised to protect.
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-slate-400">
            Network visibility, device identity, endpoint posture, intrusion detection and policy-driven containment
            in one auditable workflow. Every score is explainable and every response action is attributed.
          </p>
          <ul className="mt-8 space-y-3 text-sm text-slate-400">
            {[
              'Authorised asset inventory with multi-signal identity',
              'Explainable 0–100 risk scoring with signal breakdown',
              'Containment with human approval and reversibility',
              'Tamper-evident audit trail and chain-of-custody evidence',
            ].map((item) => (
              <li key={item} className="flex items-start gap-3">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-neon-cyan" aria-hidden />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="relative flex items-center gap-3 text-[11px] text-slate-600">
          <span className="chip border-white/10 bg-white/[0.03] text-slate-400">defensive use only</span>
          <span>Authorisation must be documented before monitoring a network.</span>
        </div>
      </section>

      <section className="flex items-center justify-center p-6 sm:p-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <p className="text-sm font-semibold tracking-[0.22em] text-slate-100">FIRESTORM</p>
            <p className="text-[10px] uppercase tracking-[0.28em] text-neon-cyan/70">Command center</p>
          </div>

          <h2 className="text-xl font-semibold text-slate-100">Sign in</h2>
          <p className="mt-1 text-xs text-slate-500">
            Use your FIRESTORM account. Access tokens are short-lived and renewed automatically; every sign-in is
            recorded in the audit trail.
          </p>

          <form className="mt-6 space-y-4" onSubmit={submit}>
            <div>
              <label htmlFor="email" className="label">
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                className="input"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <div>
              <label htmlFor="password" className="label">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="input"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            {needsMfa && (
              <div>
                <label htmlFor="mfa" className="label">
                  Authenticator code
                </label>
                <input
                  id="mfa"
                  name="mfa"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={8}
                  className="input font-mono tracking-[0.4em]"
                  value={mfa}
                  onChange={(event) => setMfa(event.target.value.replace(/\D/g, ''))}
                  autoFocus
                />
              </div>
            )}

            {error && (
              <div
                className="rounded-lg border border-threat-critical/30 bg-threat-critical/10 px-3 py-2 text-xs text-threat-high"
                role="alert"
              >
                <p>{error}</p>
                {errorRef && <p className="mt-1 font-mono text-[10px] text-slate-500">{errorRef}</p>}
              </div>
            )}

            <button type="submit" className="btn btn-primary w-full py-2" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          {devEmail && devPassword && (
            <div className="mt-4 rounded-lg border border-neon-cyan/25 bg-neon-cyan/[0.06] p-3 text-[11px] leading-relaxed text-slate-400">
              <p className="font-medium text-neon-cyan/90">Local development account</p>
              <p className="mt-1 font-mono text-slate-300">
                {devEmail}
                <span className="text-slate-600"> / </span>
                {devPassword}
              </p>
              <button
                type="button"
                className="mt-2 text-[11px] font-medium text-neon-cyan underline decoration-neon-cyan/40 underline-offset-2 hover:text-neon-cyan/80"
                onClick={() => {
                  setEmail(devEmail)
                  setPassword(devPassword)
                  setError(null)
                }}
              >
                Fill these details
              </button>
            </div>
          )}

          <div className="mt-6 rounded-lg border border-white/[0.07] bg-white/[0.02] p-3 text-[11px] leading-relaxed text-slate-500">
            <p className="font-medium text-slate-400">First run</p>
            <p className="mt-1">
              The bootstrap administrator password is printed once by{' '}
              <code className="font-mono text-slate-400">python scripts/bootstrap.py</code>. It must be changed at first
              sign-in. Demo role accounts (analyst / responder / viewer) are seeded only when{' '}
              <code className="font-mono text-slate-400">FIRESTORM_DEMO_DATA=true</code>.
            </p>
            {apiReachable === false && (
              <p className="mt-2 text-amber-300">
                The API does not appear to be reachable. Start the backend or confirm the proxy target.
              </p>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
