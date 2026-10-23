import type { ReactNode } from 'react'
import { useEffect, useRef, useState } from 'react'

/* ------------------------------------------------------------------ panels */

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = '',
  bodyClassName = '',
}: {
  title?: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          <div className="min-w-0">
            {title && <h2 className="panel-title">{title}</h2>}
            {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName || 'p-4'}>{children}</div>
    </section>
  )
}

/* ------------------------------------------------------------------ badges */

const severityStyles: Record<string, string> = {
  critical: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
  high: 'border-orange-400/40 bg-orange-400/10 text-orange-300',
  medium: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  low: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
  info: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
}

const statusStyles: Record<string, string> = {
  open: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
  acknowledged: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  investigating: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
  suppressed: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
  closed: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  new: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
  triage: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  containment: 'border-orange-400/40 bg-orange-400/10 text-orange-300',
  contained: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  eradication: 'border-teal-400/30 bg-teal-400/10 text-teal-300',
  recovery: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
  pending_approval: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  approved: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
  executing: 'border-cyan-400/40 bg-cyan-400/10 text-cyan-300',
  succeeded: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  failed: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
  rejected: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
  reverted: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  trusted: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  unknown: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  noncompliant: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  quarantined: 'border-orange-400/40 bg-orange-400/10 text-orange-300',
  compromised: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
  healthy: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  degraded: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  unavailable: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
  simulated: 'border-violet-400/40 bg-violet-400/10 text-violet-300',
  not_configured: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
  partial: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`chip ${severityStyles[severity] ?? severityStyles.info}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {severity}
    </span>
  )
}

export function StatusBadge({ status, label }: { status: string; label?: string }) {
  return (
    <span className={`chip ${statusStyles[status] ?? statusStyles.info}`}>
      {label ?? status.replace(/_/g, ' ')}
    </span>
  )
}

export function RoleBadge({ role }: { role: string }) {
  const styles: Record<string, string> = {
    admin: 'border-threat-critical/40 bg-threat-critical/10 text-threat-high',
    responder: 'border-cyan-400/40 bg-cyan-400/10 text-cyan-300',
    analyst: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
    viewer: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  }
  return <span className={`chip normal-case ${styles[role] ?? styles.viewer}`}>{role}</span>
}

/* ------------------------------------------------------------------ states */

export function LoadingBlock({ label = 'Loading', rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div className="space-y-2" role="status" aria-live="polite" aria-label={label}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-8 w-full" style={{ opacity: 1 - index * 0.15 }} />
      ))}
      <span className="sr-only">{label}</span>
    </div>
  )
}

export function EmptyState({
  title,
  description,
  action,
  icon = '◇',
}: {
  title: string
  description: string
  action?: ReactNode
  icon?: string
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/10 px-6 py-10 text-center">
      <div className="text-2xl text-slate-600" aria-hidden>
        {icon}
      </div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      <p className="max-w-md text-xs leading-relaxed text-slate-500">{description}</p>
      {action}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-lg border border-threat-critical/30 bg-threat-critical/5 p-4" role="alert">
      <div>
        <p className="text-sm font-medium text-threat-high">Unable to load data</p>
        <p className="mt-1 text-xs text-slate-400">{message}</p>
      </div>
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}

export function StaleBadge({ stale, lastEventAt }: { stale: boolean | null; lastEventAt: string | null }) {
  if (stale === null) return null
  if (!stale) {
    return (
      <span className="chip border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
        telemetry current
      </span>
    )
  }
  return (
    <span className="chip border-amber-400/40 bg-amber-400/10 text-amber-300" title={lastEventAt ?? 'no events'}>
      <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse-soft" aria-hidden />
      stale data
    </span>
  )
}

/* ------------------------------------------------------------------ stats */

export function StatCard({
  label,
  value,
  hint,
  tone = 'default',
  footer,
}: {
  label: string
  value: ReactNode
  hint?: string
  tone?: 'default' | 'critical' | 'warning' | 'ok' | 'accent'
  footer?: ReactNode
}) {
  const tones: Record<string, string> = {
    default: 'text-slate-100',
    critical: 'text-threat-high',
    warning: 'text-amber-300',
    ok: 'text-emerald-300',
    accent: 'text-neon-cyan',
  }
  return (
    <div className="panel p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className={`mt-2 font-mono text-2xl font-semibold tabular-nums ${tones[tone]}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
      {footer && <div className="mt-2">{footer}</div>}
    </div>
  )
}

export function RiskMeter({ score, size = 'md' }: { score: number; size?: 'sm' | 'md' }) {
  const color =
    score >= 80 ? 'bg-threat-critical' : score >= 60 ? 'bg-orange-400' : score >= 40 ? 'bg-amber-400' : score >= 20 ? 'bg-sky-400' : 'bg-slate-500'
  return (
    <div className={`flex items-center gap-2 ${size === 'sm' ? 'min-w-[86px]' : 'min-w-[120px]'}`}>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.max(3, Math.min(100, score))}%` }} />
      </div>
      <span className="w-7 text-right font-mono text-xs tabular-nums text-slate-300">{score}</span>
    </div>
  )
}

export function Metric({ label, value, tone = '' }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
      <p className={`mt-1 font-mono text-sm tabular-nums ${tone || 'text-slate-200'}`}>{value}</p>
    </div>
  )
}

/* ------------------------------------------------------------------ table */

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number
  pageSize: number
  total: number
  onPage: (page: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] px-4 py-3 text-xs text-slate-500">
      <span>
        {total === 0
          ? 'No rows'
          : `Showing ${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}`}
      </span>
      <div className="flex items-center gap-1">
        <button className="btn px-2 py-1" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          ‹
        </button>
        <span className="px-2 font-mono">
          {page} / {pages}
        </span>
        <button className="btn px-2 py-1" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          ›
        </button>
      </div>
    </div>
  )
}

export function Select({
  value,
  onChange,
  options,
  ariaLabel,
  className = '',
}: {
  value: string
  onChange: (value: string) => void
  options: Array<{ value: string; label: string }>
  ariaLabel: string
  className?: string
}) {
  return (
    <select
      aria-label={ariaLabel}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={`input max-w-[180px] py-1.5 text-xs ${className}`}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value} className="bg-graphite-900">
          {option.label}
        </option>
      ))}
    </select>
  )
}

/* ------------------------------------------------------------------ modal */

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = 'max-w-lg',
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  width?: string
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    ref.current?.focus()
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-sm sm:items-center">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={`panel my-8 w-full ${width} animate-slide-in`}
      >
        <div className="panel-header">
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          <button type="button" className="btn-ghost btn px-2 py-1" onClick={onClose} aria-label="Close dialog">
            ✕
          </button>
        </div>
        <div className="space-y-4 p-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-white/[0.06] px-4 py-3">{footer}</div>}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ toast */

export interface ToastMessage {
  id: number
  kind: 'success' | 'error' | 'info'
  text: string
}

export function useToasts() {
  const [toasts, setToasts] = useState<ToastMessage[]>([])
  const push = (kind: ToastMessage['kind'], text: string) => {
    const id = Date.now() + Math.random()
    setToasts((current) => [...current, { id, kind, text }])
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 5000)
  }
  const remove = (id: number) => setToasts((current) => current.filter((item) => item.id !== id))
  return { toasts, push, remove }
}

export function ToastStack({ toasts, onDismiss }: { toasts: ToastMessage[]; onDismiss: (id: number) => void }) {
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2" aria-live="polite">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`pointer-events-auto flex items-start justify-between gap-3 rounded-lg border px-3 py-2 text-sm shadow-panel backdrop-blur ${
            toast.kind === 'error'
              ? 'border-threat-critical/40 bg-threat-critical/10 text-threat-high'
              : toast.kind === 'success'
                ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200'
                : 'border-white/10 bg-graphite-900/90 text-slate-200'
          }`}
        >
          <span>{toast.text}</span>
          <button className="text-xs opacity-60 hover:opacity-100" onClick={() => onDismiss(toast.id)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ misc */

export function formatTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function relativeTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value).getTime()
  if (Number.isNaN(date)) return '—'
  const diff = Math.round((Date.now() - date) / 1000)
  if (diff < 60) return `${Math.max(diff, 0)}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`
  return `${Math.round(diff / 86400)}d ago`
}

export function DemoBadge() {
  return (
    <span className="chip border-violet-400/40 bg-violet-400/10 text-violet-300" title="Synthetic lab data">
      demo data
    </span>
  )
}

export function SectionTitle({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <div className="mb-3 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-slate-100">{children}</h1>
        {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
      </div>
    </div>
  )
}
