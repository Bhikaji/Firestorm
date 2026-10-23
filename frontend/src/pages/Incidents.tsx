import { useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
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

export default function IncidentsPage() {
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const incidents = useAsync(
    () =>
      api.incidents({
        page,
        page_size: 25,
        status: status || undefined,
        severity: severity || undefined,
      }),
    [page, status, severity],
  )
  const actions = useAsync(() => api.actions({ page_size: 25 }), [])
  const enforcement = useAsync(() => api.enforcement(), [])
  const stats = useAsync(() => api.incidentStats(30), [])

  const pending = (actions.data?.items ?? []).filter((action) => action.status === 'pending_approval')

  return (
    <div className="space-y-4">
      <SectionTitle hint="Containment, evidence and approvals in one workspace. Facts and hypotheses are stored separately.">
        Incident management
      </SectionTitle>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="panel p-4">
          <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Open incidents</p>
          <p className="mt-1 font-mono text-2xl text-slate-100">{String(stats.data?.open ?? '—')}</p>
        </div>
        <div className="panel p-4">
          <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Closed (30d)</p>
          <p className="mt-1 font-mono text-2xl text-emerald-300">{String(stats.data?.closed ?? '—')}</p>
        </div>
        <div className="panel p-4">
          <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Mean time to resolve</p>
          <p className="mt-1 font-mono text-2xl text-slate-100">
            {stats.data?.mttr_minutes != null ? `${stats.data.mttr_minutes}m` : '—'}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Pending approvals</p>
          <p className={`mt-1 font-mono text-2xl ${pending.length > 0 ? 'text-amber-300' : 'text-slate-100'}`}>
            {pending.length}
          </p>
        </div>
      </div>

      {pending.length > 0 && (
        <Panel
          title="Approval queue"
          subtitle="Only administrators can approve; the requester cannot approve their own action"
          bodyClassName="p-0"
        >
          <ul className="divide-y divide-white/[0.05]">
            {pending.map((action) => (
              <li key={action.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="text-xs text-slate-200">
                    <span className="font-mono text-slate-300">{action.action_type}</span> → {action.target}
                  </p>
                  <p className="mt-0.5 truncate text-[11px] text-slate-500">{action.reason}</p>
                  <p className="mt-0.5 text-[10px] text-slate-600">
                    {action.mode} mode · requested {relativeTime(action.created_at)}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <StatusBadge status={action.status} />
                  {action.incident_id ? (
                    <Link to={`/incidents/${action.incident_id}`} className="btn px-2 py-1 text-xs">
                      Review
                    </Link>
                  ) : (
                    <span className="text-[11px] text-slate-500">No incident linked</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Filters" bodyClassName="p-3">
        <div className="flex flex-wrap gap-2">
          <Select
            ariaLabel="Filter by status"
            value={status}
            onChange={(value) => {
              setStatus(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All statuses' },
              ...['new', 'triage', 'containment', 'contained', 'eradication', 'recovery', 'closed'].map((item) => ({
                value: item,
                label: item,
              })),
            ]}
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
              ...['critical', 'high', 'medium', 'low'].map((item) => ({ value: item, label: item })),
            ]}
          />
        </div>
      </Panel>

      {incidents.error && <ErrorState message={incidents.error} onRetry={incidents.refresh} />}

      <div className="panel overflow-hidden">
        {incidents.loading ? (
          <div className="p-4">
            <LoadingBlock rows={6} />
          </div>
        ) : incidents.data && incidents.data.items.length > 0 ? (
          <>
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Reference</th>
                    <th className="px-2 py-2">Title</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-2 py-2 w-32">Risk</th>
                    <th className="px-2 py-2">Status</th>
                    <th className="px-2 py-2 text-right">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.data.items.map((incident) => (
                    <tr key={incident.id} className="row-hover border-t border-white/[0.04]">
                      <td className="px-4 py-2 font-mono text-[11px]">
                        <Link className="link" to={`/incidents/${incident.id}`}>
                          {incident.reference}
                        </Link>
                      </td>
                      <td className="max-w-[360px] px-2 py-2">
                        <Link to={`/incidents/${incident.id}`} className="line-clamp-1 text-slate-200 hover:text-neon-cyan">
                          {incident.title}
                        </Link>
                      </td>
                      <td className="px-2 py-2">
                        <SeverityBadge severity={incident.severity} />
                      </td>
                      <td className="px-2 py-2">
                        <RiskMeter score={incident.risk_score} size="sm" />
                      </td>
                      <td className="px-2 py-2">
                        <StatusBadge status={incident.status} />
                      </td>
                      <td className="whitespace-nowrap px-2 py-2 text-right text-[11px] text-slate-400">
                        {formatTime(incident.detected_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={incidents.data.page}
              pageSize={incidents.data.page_size}
              total={incidents.data.total}
              onPage={setPage}
            />
          </>
        ) : (
          <div className="p-6">
            <EmptyState
              title="No incidents"
              description="Incidents are opened automatically when a critical-risk alert fires, or manually during triage."
            />
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Response actions" subtitle="Every request, approval and execution is audited" bodyClassName="p-0">
          {actions.loading ? (
            <div className="p-4">
              <LoadingBlock rows={4} />
            </div>
          ) : actions.data && actions.data.items.length > 0 ? (
            <ul className="max-h-[320px] divide-y divide-white/[0.05] overflow-y-auto">
              {actions.data.items.map((action) => (
                <li key={action.id} className="px-4 py-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-[11px] text-slate-200">
                        <span className="font-mono">{action.action_type}</span> → {action.target}
                      </p>
                      <p className="mt-0.5 text-[10px] text-slate-500">
                        {action.integration} · {action.mode} · {relativeTime(action.created_at)}
                      </p>
                    </div>
                    <StatusBadge status={action.status} />
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="p-4">
              <EmptyState title="No response actions" description="No containment has been requested yet." />
            </div>
          )}
        </Panel>

        <Panel title="Active enforcement" subtitle="Applied state is stored so containment stays reversible" bodyClassName="p-0">
          {enforcement.loading ? (
            <div className="p-4">
              <LoadingBlock rows={3} />
            </div>
          ) : enforcement.data && enforcement.data.length > 0 ? (
            <ul className="max-h-[320px] divide-y divide-white/[0.05] overflow-y-auto">
              {enforcement.data.map((record) => (
                <li key={record.id} className="px-4 py-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-[11px] text-slate-200">
                        <span className="font-mono">{record.kind}</span> → {record.target}
                      </p>
                      <p className="mt-0.5 truncate text-[10px] text-slate-500">{record.detail}</p>
                    </div>
                    <StatusBadge status={record.mode === 'simulated' ? 'simulated' : 'approved'} label={record.mode} />
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="p-4">
              <EmptyState title="No active enforcement" description="Nothing is currently blocked, quarantined or isolated." icon="✓" />
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}
