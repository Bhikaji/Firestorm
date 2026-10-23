import { useState } from 'react'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Pagination,
  Panel,
  SectionTitle,
  StatusBadge,
  formatTime,
} from '../components/ui'

export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [action, setAction] = useState('')
  const audit = useAsync(() => api.audit({ page, page_size: 50, action: action || undefined }), [page, action])
  const integrity = useAsync(() => api.verifyAudit(), [])
  const [expanded, setExpanded] = useState<string | null>(null)

  const actions = Array.from(new Set((audit.data?.items ?? []).map((item) => item.action))).sort()

  return (
    <div className="space-y-4">
      <SectionTitle hint="Append-only audit trail with a SHA-256 hash chain. Editing or deleting an entry breaks verification.">
        Audit trail
      </SectionTitle>

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <Panel title="Integrity" subtitle="Chain verification across stored entries">
          {integrity.loading ? (
            <LoadingBlock rows={2} />
          ) : (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <StatusBadge
                  status={integrity.data?.valid ? 'healthy' : 'unavailable'}
                  label={integrity.data?.valid ? 'chain intact' : 'integrity failure'}
                />
                <p className="mt-1 text-[11px] text-slate-500">
                  {integrity.data?.checked ?? 0} entries checked · {integrity.data?.message ?? ''}
                </p>
              </div>
              <button className="btn px-2 py-1 text-xs" onClick={integrity.refresh}>
                Re-verify
              </button>
            </div>
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-slate-500">
            The chain protects against casual tampering inside this database. It does not replace off-host log shipping
            or WORM storage, which are required for evidentiary use.
          </p>
        </Panel>

        <Panel title="Filter" bodyClassName="p-3">
          <label className="label" htmlFor="audit-action">
            Action
          </label>
          <select
            id="audit-action"
            className="input py-1.5 text-xs"
            value={action}
            onChange={(event) => {
              setAction(event.target.value)
              setPage(1)
            }}
          >
            <option value="">All actions</option>
            {actions.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </Panel>
      </div>

      {audit.error && <ErrorState message={audit.error} onRetry={audit.refresh} />}

      <div className="panel overflow-hidden">
        {audit.loading ? (
          <div className="p-4">
            <LoadingBlock rows={8} />
          </div>
        ) : audit.data && audit.data.items.length > 0 ? (
          <>
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Timestamp</th>
                    <th className="px-2 py-2">Actor</th>
                    <th className="px-2 py-2">Action</th>
                    <th className="px-2 py-2">Object</th>
                    <th className="px-2 py-2">Outcome</th>
                    <th className="px-4 py-2 text-right">Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.data.items.map((entry) => (
                    <>
                      <tr
                        key={entry.id}
                        className="row-hover cursor-pointer border-t border-white/[0.04]"
                        onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                      >
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-400">{formatTime(entry.ts)}</td>
                        <td className="px-2 py-2 text-[11px] text-slate-300">
                          {entry.actor_email}
                          <span className="block text-[10px] text-slate-600">{entry.actor_role}</span>
                        </td>
                        <td className="px-2 py-2 font-mono text-[11px] text-slate-300">{entry.action}</td>
                        <td className="px-2 py-2 text-[11px] text-slate-500">
                          {entry.object_type}
                          {entry.object_id ? ` · ${entry.object_id.slice(0, 8)}` : ''}
                        </td>
                        <td className="px-2 py-2">
                          <StatusBadge status={entry.outcome === 'success' ? 'healthy' : 'unavailable'} label={entry.outcome} />
                        </td>
                        <td className="px-4 py-2 text-right font-mono text-[10px] text-slate-600">
                          {entry.entry_hash.slice(0, 12)}
                        </td>
                      </tr>
                      {expanded === entry.id && (
                        <tr key={`${entry.id}-detail`} className="border-t border-white/[0.04] bg-white/[0.02]">
                          <td colSpan={6} className="px-4 py-2">
                            <pre className="max-h-48 overflow-auto text-[10px] leading-relaxed text-slate-500">
{JSON.stringify({ detail: entry.detail, client_ip: entry.client_ip, entry_hash: entry.entry_hash }, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={audit.data.page} pageSize={audit.data.page_size} total={audit.data.total} onPage={setPage} />
          </>
        ) : (
          <div className="p-6">
            <EmptyState title="No audit entries" description="Administrative and response actions will be recorded here." />
          </div>
        )}
      </div>
    </div>
  )
}
