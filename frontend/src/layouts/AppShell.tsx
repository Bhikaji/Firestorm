import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../services/auth'
import { useNow } from '../hooks/useAsync'
import { RoleBadge, ToastStack, useToasts } from '../components/ui'

interface NavItem {
  to: string
  label: string
  icon: string
  permission?: string
}

const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Operations',
    items: [
      { to: '/', label: 'Executive overview', icon: '◎', permission: 'dashboard:view' },
      { to: '/topology', label: 'Live threat map', icon: '⬡', permission: 'dashboard:view' },
      { to: '/events', label: 'Event stream', icon: '≋', permission: 'event:read' },
      { to: '/alerts', label: 'Alerts', icon: '▲', permission: 'alert:read' },
      { to: '/incidents', label: 'Incidents', icon: '⬢', permission: 'incident:read' },
    ],
  },
  {
    label: 'Defence',
    items: [
      { to: '/devices', label: 'Device security', icon: '⌗', permission: 'asset:read' },
      { to: '/layers', label: 'Protection layers', icon: '⛨', permission: 'dashboard:view' },
      { to: '/policies', label: 'Policies', icon: '⚖', permission: 'policy:read' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { to: '/reports', label: 'Reports', icon: '◫', permission: 'report:read' },
      { to: '/audit', label: 'Audit trail', icon: '≡', permission: 'audit:read' },
      { to: '/users', label: 'Users & access', icon: '☰', permission: 'user:admin' },
      { to: '/account', label: 'My account', icon: '☉' },
    ],
  },
]

export function AppShell({ toasts, push, dismiss }: { toasts: ReturnType<typeof useToasts>['toasts']; push: ReturnType<typeof useToasts>['push']; dismiss: (id: number) => void }) {
  const { user, permissions, signOut } = useAuth()
  const navigate = useNavigate()
  const now = useNow(1000)
  const [collapsed, setCollapsed] = useState(() => sessionStorage.getItem('firestorm.nav') === 'collapsed')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [counts, setCounts] = useState<{ open_alerts: number; active_incidents: number; pending_approvals: number } | null>(null)
  const [health, setHealth] = useState<'ok' | 'degraded' | 'unknown'>('unknown')
  const [live, setLive] = useState(false)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const overview = await api.overview()
        if (!active) return
        setCounts({
          open_alerts: overview.counts.open_alerts,
          active_incidents: overview.counts.active_incidents,
          pending_approvals: overview.counts.pending_approvals,
        })
      } catch {
        if (active) setHealth('degraded')
      }
      try {
        const readiness = await api.readiness()
        if (active) setHealth(readiness.status === 'ok' ? 'ok' : 'degraded')
      } catch {
        if (active) setHealth('degraded')
      }
    }
    load()
    const timer = window.setInterval(load, 30_000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  useEffect(() => {
    let socket: WebSocket | null = null
    let closedByUs = false
    const token = sessionStorage.getItem('firestorm.access')
    if (!token) return
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      socket = new WebSocket(`${protocol}://${window.location.host}/api/v1/ws/live?token=${encodeURIComponent(token)}`)
      socket.onopen = () => setLive(true)
      socket.onclose = () => {
        setLive(false)
        if (!closedByUs) setLive(false)
      }
      socket.onerror = () => setLive(false)
    } catch {
      setLive(false)
    }
    return () => {
      closedByUs = true
      socket?.close()
    }
  }, [])

  const groups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => !item.permission || permissions.includes(item.permission)),
      })).filter((group) => group.items.length > 0),
    [permissions],
  )

  const toggle = () => {
    const next = !collapsed
    setCollapsed(next)
    sessionStorage.setItem('firestorm.nav', next ? 'collapsed' : 'expanded')
  }

  const handleSignOut = async () => {
    await signOut()
    push('info', 'Signed out')
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-white/[0.06] bg-graphite-950/95 backdrop-blur transition-[width,transform] duration-200 ${
          collapsed ? 'w-[76px]' : 'w-[248px]'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}
        aria-label="Primary navigation"
      >
        <div className={`flex h-14 items-center gap-3 border-b border-white/[0.06] px-4 ${collapsed ? 'justify-center' : ''}`}>
          <span className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-neon-cyan/30 bg-neon-cyan/10">
            <span className="text-sm font-bold text-neon-cyan">F</span>
          </span>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-[13px] font-semibold tracking-[0.16em] text-slate-100">FIRESTORM</p>
              <p className="truncate text-[10px] uppercase tracking-[0.18em] text-neon-cyan/70">Command</p>
            </div>
          )}
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {groups.map((group) => (
            <div key={group.label} className="mb-4">
              {!collapsed && (
                <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
                  {group.label}
                </p>
              )}
              <ul className="space-y-0.5">
                {group.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.to === '/'}
                      onClick={() => setMobileOpen(false)}
                      title={collapsed ? item.label : undefined}
                      className={({ isActive }) =>
                        `group flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors ${
                          isActive
                            ? 'bg-neon-cyan/10 text-neon-cyan shadow-[inset_0_0_0_1px_rgba(34,211,238,0.22)]'
                            : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
                        } ${collapsed ? 'justify-center' : ''}`
                      }
                    >
                      <span className="w-4 text-center text-base leading-none" aria-hidden>
                        {item.icon}
                      </span>
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/[0.06] p-2">
          <button type="button" className="btn btn-ghost w-full justify-start gap-2 px-2 py-1.5 text-xs" onClick={toggle}>
            <span aria-hidden>{collapsed ? '»' : '«'}</span>
            {!collapsed && 'Collapse'}
          </button>
          {!collapsed && (
            <p className="mt-2 px-2 text-[10px] leading-relaxed text-slate-600">
              Authorised use only. All actions are audited.
            </p>
          )}
        </div>
      </aside>

      {mobileOpen && (
        <button
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main column */}
      <div className={`flex min-w-0 flex-1 flex-col transition-[margin] duration-200 ${collapsed ? 'lg:ml-[76px]' : 'lg:ml-[248px]'}`}>
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-white/[0.06] bg-graphite-950/85 px-3 backdrop-blur sm:px-4">
          <button
            className="btn btn-ghost px-2 py-1 lg:hidden"
            onClick={() => setMobileOpen((value) => !value)}
            aria-label="Toggle navigation"
          >
            ☰
          </button>

          <div className="flex items-center gap-2">
            <span
              className={`chip ${
                health === 'ok'
                  ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300'
                  : health === 'degraded'
                    ? 'border-amber-400/40 bg-amber-400/10 text-amber-300'
                    : 'border-slate-500/40 bg-slate-500/10 text-slate-400'
              }`}
              title="Platform health from /ready"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
              {health === 'ok' ? 'systems nominal' : health === 'degraded' ? 'degraded' : 'checking'}
            </span>
            <span
              className={`chip hidden sm:inline-flex ${
                live ? 'border-neon-cyan/40 bg-neon-cyan/10 text-neon-cyan' : 'border-slate-500/40 bg-slate-500/10 text-slate-400'
              }`}
              title={live ? 'Live WebSocket connected' : 'Live socket disconnected; polling continues'}
            >
              <span className={`h-1.5 w-1.5 rounded-full bg-current ${live ? 'animate-pulse-soft' : ''}`} aria-hidden />
              {live ? 'live' : 'polling'}
            </span>
          </div>

          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            <NavLink
              to="/alerts"
              className="hidden items-center gap-1.5 rounded-lg border border-white/10 px-2 py-1 text-xs text-slate-300 hover:bg-white/5 sm:flex"
              title="Open alerts"
            >
              <span className="text-threat-high">▲</span>
              <span className="font-mono tabular-nums">{counts?.open_alerts ?? '—'}</span>
              <span className="text-slate-500">alerts</span>
            </NavLink>
            <NavLink
              to="/incidents"
              className="hidden items-center gap-1.5 rounded-lg border border-white/10 px-2 py-1 text-xs text-slate-300 hover:bg-white/5 md:flex"
              title="Active incidents"
            >
              <span className="text-amber-300">⬢</span>
              <span className="font-mono tabular-nums">{counts?.active_incidents ?? '—'}</span>
              <span className="text-slate-500">incidents</span>
            </NavLink>
            {(counts?.pending_approvals ?? 0) > 0 && (
              <NavLink
                to="/incidents"
                className="chip border-amber-400/50 bg-amber-400/10 text-amber-200"
                title="Response actions awaiting approval"
              >
                {counts?.pending_approvals} to approve
              </NavLink>
            )}
            <time className="hidden font-mono text-xs tabular-nums text-slate-400 sm:block" dateTime={now.toISOString()}>
              {now.toLocaleTimeString(undefined, { hour12: false })} UTC
              {now.getTimezoneOffset() !== 0 ? '±' : ''}
            </time>
            <div className="flex items-center gap-2 border-l border-white/10 pl-2 sm:pl-3">
              <div className="hidden text-right sm:block">
                <p className="max-w-[160px] truncate text-xs font-medium text-slate-200">{user?.full_name}</p>
                <p className="max-w-[160px] truncate text-[10px] text-slate-500">{user?.email}</p>
              </div>
              {user && <RoleBadge role={user.role} />}
              <button type="button" className="btn btn-ghost px-2 py-1 text-xs" onClick={handleSignOut}>
                Sign out
              </button>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 px-3 py-4 sm:px-5 sm:py-6">
          <Outlet context={{ push }} />
        </main>

        <footer className="border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-600">
          FIRESTORM · defensive platform for authorised networks · enforcement mode:{' '}
          <span className="font-mono text-slate-500">simulated unless configured</span>
        </footer>
      </div>

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
