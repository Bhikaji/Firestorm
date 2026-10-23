import { useState } from 'react'
import api, { ApiError } from '../services/api'
import { useAsync, useDebounced } from '../hooks/useAsync'
import { useAuth } from '../services/auth'
import { useNotify } from '../hooks/useNotify'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Pagination,
  Panel,
  SectionTitle,
  Select,
  StatusBadge,
  formatTime,
  relativeTime,
} from '../components/ui'

export default function DevicesPage() {
  const { can } = useAuth()
  const notify = useNotify()
  const [page, setPage] = useState(1)
  const [trust, setTrust] = useState('')
  const [segment, setSegment] = useState('')
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [quarantineReason, setQuarantineReason] = useState('')
  const debounced = useDebounced(search, 350)

  const assets = useAsync(
    () => api.assets({ page, page_size: 25, trust_state: trust || undefined, segment_id: segment || undefined, q: debounced || undefined }),
    [page, trust, segment, debounced],
  )
  const segments = useAsync(() => api.segments(), [])
  const context = useAsync(() => (selectedId ? api.assetContext(selectedId) : Promise.resolve(null)), [selectedId], {
    enabled: Boolean(selectedId),
  })

  const run = async (fn: () => Promise<unknown>, message: string) => {
    setBusy(true)
    try {
      await fn()
      notify('success', message)
      assets.refresh()
      context.refresh()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Action failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <SectionTitle hint="Identity is multi-signal: IP and MAC alone are never treated as proof of identity. Unassessed devices are restricted, not trusted.">
        Device security
      </SectionTitle>

      <Panel title="Filters" bodyClassName="p-3">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <input
            className="input py-1.5 text-xs"
            placeholder="Search hostname, IP, MAC or owner"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
            aria-label="Search devices"
          />
          <Select
            ariaLabel="Filter by trust state"
            value={trust}
            onChange={(value) => {
              setTrust(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All trust states' },
              ...['trusted', 'unknown', 'noncompliant', 'quarantined', 'compromised'].map((item) => ({ value: item, label: item })),
            ]}
            className="max-w-none"
          />
          <Select
            ariaLabel="Filter by segment"
            value={segment}
            onChange={(value) => {
              setSegment(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All segments' },
              ...(segments.data ?? []).map((item) => ({ value: item.id, label: `${item.name} (${item.cidr})` })),
            ]}
            className="max-w-none"
          />
          <div className="flex items-center text-[11px] text-slate-500">
            {(segments.data ?? []).length} authorised segment(s) monitored
          </div>
        </div>
      </Panel>

      {assets.error && <ErrorState message={assets.error} onRetry={assets.refresh} />}

      <div className="panel overflow-hidden">
        {assets.loading ? (
          <div className="p-4">
            <LoadingBlock rows={8} />
          </div>
        ) : assets.data && assets.data.items.length > 0 ? (
          <>
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Device</th>
                    <th className="px-2 py-2">Type / OS</th>
                    <th className="px-2 py-2">Owner</th>
                    <th className="px-2 py-2">Trust</th>
                    <th className="px-2 py-2">Posture</th>
                    <th className="px-2 py-2">EDR / patch</th>
                    <th className="px-2 py-2 text-right">Criticality</th>
                    <th className="px-4 py-2 text-right">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.data.items.map((asset) => (
                    <tr
                      key={asset.id}
                      className="row-hover cursor-pointer border-t border-white/[0.04]"
                      onClick={() => setSelectedId(asset.id)}
                      tabIndex={0}
                      onKeyDown={(event) => event.key === 'Enter' && setSelectedId(asset.id)}
                    >
                      <td className="px-4 py-2">
                        <p className="text-slate-200">{asset.hostname}</p>
                        <p className="font-mono text-[10px] text-slate-500">
                          {asset.ip_address} {asset.mac_address ? `· ${asset.mac_address}` : ''}
                        </p>
                      </td>
                      <td className="px-2 py-2 text-[11px] text-slate-400">
                        {asset.device_type}
                        <span className="block text-[10px] text-slate-600">{asset.os_name ?? 'unknown OS'}</span>
                      </td>
                      <td className="px-2 py-2 text-[11px] text-slate-400">
                        {asset.owner ?? '—'}
                        <span className="block text-[10px] text-slate-600">{asset.department ?? ''}</span>
                      </td>
                      <td className="px-2 py-2">
                        <StatusBadge status={asset.trust_state} />
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-14 overflow-hidden rounded-full bg-white/10">
                            <div
                              className={`h-full rounded-full ${
                                asset.posture_score >= 80
                                  ? 'bg-emerald-400'
                                  : asset.posture_score >= 60
                                    ? 'bg-cyan-400'
                                    : asset.posture_score >= 40
                                      ? 'bg-amber-400'
                                      : 'bg-rose-500'
                              }`}
                              style={{ width: `${Math.max(2, asset.posture_score)}%` }}
                            />
                          </div>
                          <span className="font-mono text-[10px] text-slate-400">{Math.round(asset.posture_score)}</span>
                        </div>
                      </td>
                      <td className="px-2 py-2 text-[11px]">
                        <span className={asset.edr_status === 'active' ? 'text-emerald-300' : 'text-amber-300'}>
                          {asset.edr_status}
                        </span>
                        <span className="block text-[10px] text-slate-500">{asset.patch_level}</span>
                      </td>
                      <td className="px-2 py-2 text-right font-mono text-[11px] text-slate-300">{asset.criticality}/5</td>
                      <td className="whitespace-nowrap px-4 py-2 text-right text-[11px] text-slate-500">
                        {relativeTime(asset.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={assets.data.page} pageSize={assets.data.page_size} total={assets.data.total} onPage={setPage} />
          </>
        ) : (
          <div className="p-6">
            <EmptyState
              title="No devices match"
              description="Inventory is populated by discovery, endpoint agents or manual registration. Unregistered hosts appear as unknown devices when they are observed."
            />
          </div>
        )}
      </div>

      <Modal
        open={Boolean(selectedId)}
        onClose={() => setSelectedId(null)}
        title="Device detail"
        width="max-w-3xl"
        footer={
          <button className="btn" onClick={() => setSelectedId(null)}>
            Close
          </button>
        }
      >
        {context.loading ? (
          <LoadingBlock rows={6} />
        ) : context.data ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-slate-100">{context.data.asset.hostname}</p>
                <p className="font-mono text-[11px] text-slate-500">
                  {context.data.asset.ip_address} · {context.data.asset.mac_address ?? 'no MAC'}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge status={context.data.asset.trust_state} />
                {context.data.admission.outcome && (
                  <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">
                    admission: {context.data.admission.outcome}
                  </span>
                )}
              </div>
            </div>

            <div className="grid gap-2 text-[11px] sm:grid-cols-2">
              <Row label="Device type" value={context.data.asset.device_type} />
              <Row label="Operating system" value={`${context.data.asset.os_name ?? '—'} ${context.data.asset.os_version ?? ''}`} />
              <Row label="Owner / department" value={`${context.data.asset.owner ?? '—'} / ${context.data.asset.department ?? '—'}`} />
              <Row label="Enrolled" value={context.data.asset.enrolled ? 'yes' : 'no'} />
              <Row label="Endpoint protection" value={context.data.asset.edr_status} />
              <Row label="Patch level" value={context.data.asset.patch_level} />
              <Row label="Firewall / disk encryption" value={`${context.data.asset.firewall_enabled ?? 'unknown'} / ${context.data.asset.disk_encrypted ?? 'unknown'}`} />
              <Row label="Posture score" value={`${context.data.asset.posture_score} / 100`} />
              <Row label="Last posture report" value={formatTime(context.data.asset.last_posture_at)} />
              <Row label="Last seen" value={formatTime(context.data.asset.last_seen_at)} />
            </div>

            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Admission decision</p>
              <p className="mt-1 text-[11px] text-slate-300">{context.data.admission.outcome_label}</p>
              <p className="mt-1 text-[11px] text-slate-500">{context.data.admission.reason}</p>
              {context.data.admission.matched_rule && (
                <p className="mt-1 font-mono text-[10px] text-slate-600">matched rule: {context.data.admission.matched_rule}</p>
              )}
            </div>

            {context.data.asset.quarantine_reason && (
              <p className="rounded-lg border border-orange-400/25 bg-orange-400/[0.06] p-2 text-[11px] text-orange-200">
                Quarantined: {context.data.asset.quarantine_reason} (since {formatTime(context.data.asset.quarantined_at)})
              </p>
            )}

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">Recent alerts</p>
                {context.data.alerts.length === 0 ? (
                  <p className="text-[11px] text-slate-500">No alerts on record.</p>
                ) : (
                  <ul className="space-y-1">
                    {context.data.alerts.slice(0, 5).map((alert) => (
                      <li key={alert.id} className="rounded border border-white/[0.06] px-2 py-1 text-[10px] text-slate-400">
                        <span className="text-slate-200">{alert.title}</span>
                        <span className="block">risk {alert.risk_score} · {alert.status}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">Related incidents</p>
                {context.data.incidents.length === 0 ? (
                  <p className="text-[11px] text-slate-500">No linked incidents.</p>
                ) : (
                  <ul className="space-y-1">
                    {context.data.incidents.map((incident) => (
                      <li key={incident.id} className="text-[11px] text-slate-400">
                        <span className="font-mono text-slate-500">{incident.reference}</span> {incident.title}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            {can('asset:write') && (
              <div className="space-y-2 border-t border-white/[0.06] pt-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Authorised remediation actions</p>
                <div className="flex flex-wrap gap-2">
                  <button
                    className="btn px-2 py-1 text-[11px]"
                    disabled={busy}
                    onClick={() =>
                      run(
                        () => api.evaluateAdmission(context.data!.asset.id),
                        'Admission re-evaluated',
                      )
                    }
                  >
                    Re-evaluate admission
                  </button>
                  <button
                    className="btn px-2 py-1 text-[11px]"
                    disabled={busy}
                    onClick={() => run(() => api.setTrust(context.data!.asset.id, 'trusted', 'Analyst verified device identity'), 'Device marked trusted')}
                  >
                    Mark trusted
                  </button>
                </div>
                {can('action:request') && (
                  <div className="flex flex-wrap gap-2">
                    <input
                      className="input flex-1 py-1.5 text-xs"
                      placeholder="Quarantine justification (required)"
                      value={quarantineReason}
                      onChange={(event) => setQuarantineReason(event.target.value)}
                    />
                    <button
                      className="btn btn-danger px-2 py-1 text-[11px]"
                      disabled={busy || quarantineReason.trim().length < 5}
                      onClick={() =>
                        run(async () => {
                          await api.quarantineAsset(context.data!.asset.id, quarantineReason)
                          setQuarantineReason('')
                        }, 'Quarantine requested; approval may be required')
                      }
                    >
                      Request quarantine
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-500">Device unavailable.</p>
        )}
      </Modal>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-1.5">
      <span className="text-slate-500">{label}</span>
      <span className="max-w-[60%] break-words text-right font-mono text-slate-300">{value}</span>
    </div>
  )
}
