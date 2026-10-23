import { useState } from 'react'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../services/auth'
import { useNotify } from '../hooks/useNotify'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Panel,
  SectionTitle,
  StatusBadge,
  formatTime,
} from '../components/ui'

export default function LayersPage() {
  const { can } = useAuth()
  const notify = useNotify()
  const layers = useAsync(() => api.layers(), [])
  const info = useAsync(() => api.systemInfo(), [])
  const notifications = useAsync(() => api.notificationStatus(), [])
  const [testing, setTesting] = useState(false)

  const runTests = async () => {
    setTesting(true)
    try {
      await api.testIntegrations()
      notify('success', 'Connectivity checks completed; results below')
      layers.refresh()
      notifications.refresh()
    } catch {
      notify('error', 'Connectivity checks could not be completed')
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle hint="Every adapter reports its true state. Simulated adapters are labelled and never presented as live protection.">
          Protection layers
        </SectionTitle>
        {can('integration:test') && (
          <button className="btn px-3 py-1.5 text-xs" onClick={runTests} disabled={testing}>
            {testing ? 'Testing…' : 'Test connectivity'}
          </button>
        )}
      </div>

      {layers.error && <ErrorState message={layers.error} onRetry={layers.refresh} />}

      <div className="grid gap-4 xl:grid-cols-2">
        {layers.loading ? (
          <div className="panel p-4">
            <LoadingBlock rows={6} />
          </div>
        ) : (
          (layers.data ?? []).map((layer) => (
            <Panel
              key={layer.id}
              title={layer.name}
              subtitle={layer.description}
              actions={<StatusBadge status={layer.status} />}
              bodyClassName="p-0"
            >
              {layer.components.length === 0 ? (
                <div className="p-4">
                  <EmptyState
                    title="No components configured"
                    description="Configure this layer's endpoint or log path to enable it. Absence of a control is surfaced here rather than assumed healthy."
                  />
                </div>
              ) : (
                <ul className="divide-y divide-white/[0.05]">
                  {layer.components.map((component) => (
                    <li key={component.name} className="px-4 py-2.5">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="text-xs text-slate-200">{component.name}</p>
                          <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{component.detail}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <span className="chip border-white/10 bg-white/[0.03] text-slate-400 normal-case">
                            {component.mode}
                          </span>
                          <StatusBadge status={component.status} />
                        </div>
                      </div>
                      <p className="mt-1 font-mono text-[10px] text-slate-600">
                        kind: {component.kind}
                        {component.latency_ms != null ? ` · ${component.latency_ms} ms` : ''} · checked {formatTime(component.checked_at)}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          ))
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Notification delivery" subtitle="Status reflects provider confirmation, never optimistic assumption">
          {notifications.loading ? (
            <LoadingBlock rows={3} />
          ) : (
            <div className="space-y-2 text-[11px] text-slate-400">
              <p>
                <span className="text-slate-500">In-app:</span> {String(notifications.data?.in_app ?? 'unknown')}
              </p>
              <p>
                <span className="text-slate-500">Email configured:</span>{' '}
                {notifications.data?.email_configured ? 'yes' : 'no'}
              </p>
              <p className="leading-relaxed">{String(notifications.data?.detail ?? '')}</p>
              <p className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-[10px] leading-relaxed text-slate-500">
                Critical severity escalates to the on-call team and opens an incident. Notification bodies never contain
                credentials or unnecessary personal data.
              </p>
            </div>
          )}
        </Panel>

        <Panel title="Platform capabilities" subtitle="What this deployment can actually do">
          {info.loading ? (
            <LoadingBlock rows={4} />
          ) : (
            <ul className="grid grid-cols-2 gap-2 text-[11px]">
              {Object.entries(info.data?.capabilities ?? {}).map(([key, value]) => (
                <li key={key} className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-1.5">
                  <span className="capitalize text-slate-400">{key.replace(/_/g, ' ')}</span>
                  <span className={value ? 'text-emerald-300' : 'text-slate-500'}>{value ? 'enabled' : 'off'}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-slate-500">
            Environment: <span className="font-mono">{info.data?.app.environment ?? '—'}</span> · enforcement mode:{' '}
            <span className="font-mono">{info.data?.app.enforcement_mode ?? '—'}</span>
          </p>
        </Panel>
      </div>
    </div>
  )
}
