import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import api, { ApiError } from '../services/api'
import { useAsync, useDebounced } from '../hooks/useAsync'
import { useNotify } from '../hooks/useNotify'
import { useAuth } from '../services/auth'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Pagination,
  Panel,
  RiskMeter,
  SectionTitle,
  Select,
  SeverityBadge,
  StatusBadge,
  formatTime,
  relativeTime,
} from '../components/ui'

export default function AlertsPage() {
  const { can } = useAuth()
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [minRisk, setMinRisk] = useState('')
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(params.get('alert'))
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [containmentOpen, setContainmentOpen] = useState(false)
  const [containTarget, setContainTarget] = useState('')
  const [containReason, setContainReason] = useState('')
  const debounced = useDebounced(search, 350)
  const notify = useNotify()

  const alerts = useAsync(
    () =>
      api.alerts({
        page,
        page_size: 25,
        status: status || undefined,
        severity: severity || undefined,
        min_risk: minRisk || undefined,
        q: debounced || undefined,
        sort: 'risk_score',
      }),
    [page, status, severity, minRisk, debounced],
  )

  const detail = useAsync(() => (selectedId ? api.alert(selectedId) : Promise.resolve(null)), [selectedId], {
    enabled: Boolean(selectedId),
  })

  useEffect(() => {
    if (params.get('alert')) setSelectedId(params.get('alert'))
  }, [params])

  const close = () => {
    setSelectedId(null)
    setNote('')
    params.delete('alert')
    setParams(params, { replace: true })
  }

  const open = (id: string) => {
    setSelectedId(id)
    setParams({ alert: id }, { replace: true })
  }

  const refreshAll = () => {
    alerts.refresh()
    detail.refresh()
  }

  const triage = async (payload: Record<string, unknown>, successMessage: string) => {
    if (!selectedId) return
    setBusy(true)
    try {
      await api.triageAlert(selectedId, payload)
      notify('success', successMessage)
      refreshAll()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Triage action failed')
    } finally {
      setBusy(false)
    }
  }

  const requestContainment = async () => {
    if (!detail.data) return
    setBusy(true)
    try {
      const alert = detail.data.alert
      const action = await api.requestAction({
        action_type: 'quarantine_asset',
        target: containTarget || alert.src_ip || alert.dst_ip,
        reason: containReason || `Containment requested from alert ${alert.id} (${alert.rule_id})`,
        alert_id: alert.id,
        incident_id: alert.incident_id,
        asset_id: alert.asset_id,
      })
      notify('success', `Action ${action.status.replace('_', ' ')}. Approvals appear in the incident workspace.`)
      setContainmentOpen(false)
      setContainReason('')
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Containment request failed')
    } finally {
      setBusy(false)
    }
  }

  const severityCounts = useMemo(() => {
    const items = alerts.data?.items ?? []
    return {
      critical: items.filter((item) => item.severity === 'critical').length,
      unassigned: items.filter((item) => !item.assignee_id).length,
    }
  }, [alerts.data])

  return (
    <div className="space-y-4">
      <SectionTitle hint="Alerts carry rule version, confidence and a signal-by-signal explanation. Severity and confidence are separate values.">
        Alerts
      </SectionTitle>

      <Panel title="Filters" bodyClassName="p-3">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <input
            className="input py-1.5 text-xs lg:col-span-2"
            placeholder="Search title, source or destination"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
            aria-label="Search alerts"
          />
          <Select
            ariaLabel="Filter by status"
            value={status}
            onChange={(value) => {
              setStatus(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All statuses' },
              ...['open', 'acknowledged', 'investigating', 'suppressed', 'closed'].map((item) => ({ value: item, label: item })),
            ]}
            className="max-w-none"
          />
          <Select
            ariaLabel="Filter by severity"
            value={severity}
            onChange={(value) => {
              setSeverity(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All severities' },
              ...['critical', 'high', 'medium', 'low', 'info'].map((item) => ({ value: item, label: item })),
            ]}
            className="max-w-none"
          />
          <Select
            ariaLabel="Filter by minimum risk"
            value={minRisk}
            onChange={(value) => {
              setMinRisk(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'Any risk' },
              { value: '80', label: 'Critical 80+' },
              { value: '60', label: 'High 60+' },
              { value: '40', label: 'Medium 40+' },
            ]}
            className="max-w-none"
          />
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          On this page: <span className="text-threat-high">{severityCounts.critical} critical</span> ·{' '}
          {severityCounts.unassigned} unassigned
        </p>
      </Panel>

      {alerts.error && <ErrorState message={alerts.error} onRetry={alerts.refresh} />}

      <div className="panel overflow-hidden">
        {alerts.loading ? (
          <div className="p-4">
            <LoadingBlock rows={8} />
          </div>
        ) : alerts.data && alerts.data.items.length > 0 ? (
          <>
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Alert</th>
                    <th className="px-2 py-2">Rule</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-2 py-2 w-32">Risk</th>
                    <th className="px-2 py-2">Status</th>
                    <th className="px-2 py-2 text-right">Seen</th>
                    <th className="px-4 py-2 text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.items.map((alert) => (
                    <tr
                      key={alert.id}
                      className={`row-hover cursor-pointer border-t border-white/[0.04] ${selectedId === alert.id ? 'bg-white/[0.05]' : ''}`}
                      onClick={() => open(alert.id)}
                      tabIndex={0}
                      onKeyDown={(event) => event.key === 'Enter' && open(alert.id)}
                    >
                      <td className="px-4 py-2">
                        <p className="line-clamp-1 max-w-[380px] text-slate-200">{alert.title}</p>
                        <p className="mt-0.5 font-mono text-[10px] text-slate-600">
                          {alert.src_ip ?? '—'} → {alert.dst_ip ?? '—'}
                          {alert.dst_port ? `:${alert.dst_port}` : ''}
                        </p>
                      </td>
                      <td className="px-2 py-2 font-mono text-[11px] text-slate-400">{alert.rule_id}</td>
                      <td className="px-2 py-2">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-2 py-2">
                        <RiskMeter score={alert.risk_score} size="sm" />
                      </td>
                      <td className="px-2 py-2">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="whitespace-nowrap px-2 py-2 text-right text-[11px] text-slate-400">{relativeTime(alert.last_seen)}</td>
                      <td className="px-4 py-2 text-right font-mono text-[11px] text-slate-400">{alert.occurrence_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={alerts.data.page} pageSize={alerts.data.page_size} total={alerts.data.total} onPage={setPage} />
          </>
        ) : (
          <div className="p-6">
            <EmptyState
              title="No alerts"
              description="No alerts match the current filters. An empty queue is not proof of safety: verify sensor coverage on the protection-layers page."
            />
          </div>
        )}
      </div>

      <Modal
        open={Boolean(selectedId)}
        onClose={close}
        title="Alert investigation"
        width="max-w-4xl"
        footer={
          <div className="flex w-full flex-wrap items-center justify-between gap-2">
            <span className="text-[11px] text-slate-500">
              {detail.data ? `Rule ${detail.data.alert.rule_id} v${detail.data.alert.rule_version}` : ''}
            </span>
            <div className="flex flex-wrap gap-2">
              {can('alert:triage') && (
                <>
                  <button className="btn" disabled={busy} onClick={() => triage({ status: 'acknowledged', note }, 'Alert acknowledged')}>
                    Acknowledge
                  </button>
                  <button className="btn" disabled={busy} onClick={() => triage({ status: 'investigating', note }, 'Alert moved to investigation')}>
                    Investigate
                  </button>
                  <button
                    className="btn"
                    disabled={busy}
                    onClick={() => triage({ status: 'closed', false_positive: true, note }, 'Alert closed as false positive')}
                  >
                    False positive
                  </button>
                </>
              )}
              {can('action:request') && (
                <button
                  className="btn btn-danger"
                  disabled={busy}
                  onClick={() => {
                    setContainTarget(detail.data?.alert.src_ip ?? '')
                    setContainmentOpen(true)
                  }}
                >
                  Request containment
                </button>
              )}
              <button className="btn btn-ghost" onClick={close}>
                Close
              </button>
            </div>
          </div>
        }
      >
        {detail.loading ? (
          <LoadingBlock rows={6} />
        ) : detail.data ? (
          <div className="space-y-4">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={detail.data.alert.severity} />
                <StatusBadge status={detail.data.alert.status} />
                <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">
                  confidence {Math.round(detail.data.alert.confidence * 100)}%
                </span>
                <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">
                  {detail.data.alert.detection_source}
                </span>
              </div>
              <h3 className="mt-2 text-sm font-semibold text-slate-100">{detail.data.alert.title}</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{detail.data.alert.description}</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Risk explanation</p>
                <div className="mt-2">
                  <RiskMeter score={detail.data.alert.risk_score} />
                </div>
                <ul className="mt-3 space-y-1.5">
                  {detail.data.alert.signals.map((signal) => (
                    <li key={signal.key} className="text-[11px] text-slate-400">
                      <span className="font-mono text-slate-300">+{signal.weight}</span> {signal.label}
                      <span className="block text-slate-600">{signal.detail} · {signal.source}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-[11px]">
                <Row label="First seen" value={formatTime(detail.data.alert.first_seen)} />
                <Row label="Last seen" value={formatTime(detail.data.alert.last_seen)} />
                <Row label="Occurrences" value={String(detail.data.alert.occurrence_count)} />
                <Row label="Source" value={detail.data.alert.src_ip ?? '—'} />
                <Row label="Destination" value={`${detail.data.alert.dst_ip ?? '—'}${detail.data.alert.dst_port ? `:${detail.data.alert.dst_port}` : ''}`} />
                <Row label="DNS query" value={detail.data.alert.dns_query ?? '—'} />
                <Row label="MITRE" value={detail.data.alert.ttps.join(', ') || '—'} />
                <Row label="Incident" value={detail.data.alert.incident_id ?? '—'} />
                <Row label="Suggested" value={detail.data.alert.recommended_actions.join(', ') || '—'} />
              </div>
            </div>

            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Linked events</p>
              {detail.data.events.length > 0 ? (
                <div className="max-h-44 overflow-auto rounded-lg border border-white/[0.06]">
                  <table className="w-full text-[11px]">
                    <thead className="table-head">
                      <tr>
                        <th className="px-3 py-1.5">Time</th>
                        <th className="px-2 py-1.5">Type</th>
                        <th className="px-2 py-1.5">Path</th>
                        <th className="px-3 py-1.5 text-right">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.data.events.map((event) => (
                        <tr key={event.id} className="border-t border-white/[0.04]">
                          <td className="px-3 py-1.5 font-mono text-slate-500">{formatTime(event.ts)}</td>
                          <td className="px-2 py-1.5 font-mono text-slate-300">{event.event_type}</td>
                          <td className="px-2 py-1.5 font-mono text-slate-400">
                            {event.src_ip ?? '—'} → {event.dst_ip ?? '—'}
                            {event.dst_port ? `:${event.dst_port}` : ''}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-slate-300">{event.risk_score}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-[11px] text-slate-500">No individual events are linked to this alert.</p>
              )}
            </div>

            {can('alert:triage') && (
              <div>
                <label className="label" htmlFor="alert-note">
                  Analyst note
                </label>
                <textarea
                  id="alert-note"
                  className="input min-h-[70px]"
                  maxLength={4000}
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="Record what you verified. Notes are audited and visible to responders."
                />
              </div>
            )}

            <p className="rounded-lg border border-amber-400/20 bg-amber-400/[0.06] p-2 text-[11px] leading-relaxed text-amber-200/80">
              {detail.data.explanation.caveat} Detections describe observed behaviour, not proof of an attacker's
              identity.
            </p>
          </div>
        ) : (
          <p className="text-xs text-slate-500">Alert not found.</p>
        )}
      </Modal>

      <Modal
        open={containmentOpen}
        onClose={() => setContainmentOpen(false)}
        title="Request containment"
        footer={
          <>
            <button className="btn" onClick={() => setContainmentOpen(false)}>
              Cancel
            </button>
            <button className="btn btn-danger" disabled={busy} onClick={requestContainment}>
              Submit request
            </button>
          </>
        }
      >
        <p className="text-xs leading-relaxed text-slate-400">
          Requests are recorded, then require administrator approval unless policy explicitly permits automatic
          execution. In simulated mode no production change occurs; the action is labelled as simulated everywhere.
        </p>
        <div>
          <label className="label" htmlFor="contain-target">
            Target (IP, MAC or hostname)
          </label>
          <input id="contain-target" className="input" value={containTarget} onChange={(event) => setContainTarget(event.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="contain-reason">
            Justification
          </label>
          <textarea
            id="contain-reason"
            className="input min-h-[80px]"
            value={containReason}
            onChange={(event) => setContainReason(event.target.value)}
            placeholder="Evidence reviewed, scope of impact, business justification"
          />
        </div>
      </Modal>

    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-slate-500">{label}</span>
      <span className="max-w-[60%] break-words text-right font-mono text-slate-300">{value}</span>
    </div>
  )
}
