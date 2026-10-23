import { useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { TopologyGraph } from '../topology/TopologyGraph'
import {
  DemoBadge,
  EmptyState,
  ErrorState,
  LoadingBlock,
  Panel,
  RiskMeter,
  SectionTitle,
  SeverityBadge,
  StatusBadge,
  formatTime,
  relativeTime,
} from '../components/ui'

export default function TopologyPage() {
  const topology = useAsync(() => api.topology(), [])
  const feed = useAsync(() => api.feed(25), [])
  const [selected, setSelected] = useState<string | null>(null)
  const assetContext = useAsync(() => (selected ? api.assetContext(selected) : Promise.resolve(null)), [selected], {
    enabled: Boolean(selected),
  })

  const suspicious = (topology.data?.links ?? []).filter((link) => link.suspicious)

  return (
    <div className="space-y-4">
      <SectionTitle hint="Authorised segments only. External addresses appear as indicators; geolocation is approximate and never proves identity.">
        Live threat map
      </SectionTitle>

      {topology.error && <ErrorState message={topology.error} onRetry={topology.refresh} />}

      <div className="grid gap-4 xl:grid-cols-[1.65fr_1fr]">
        <Panel
          title="Network topology"
          subtitle="Segments, devices and suspicious paths from open alerts"
          actions={
            <div className="flex items-center gap-2">
              {topology.data?.demo && <DemoBadge />}
              <button className="btn px-2 py-1 text-xs" onClick={topology.refresh}>
                Refresh
              </button>
            </div>
          }
        >
          {topology.loading ? (
            <LoadingBlock rows={6} />
          ) : topology.data && topology.data.nodes.length > 0 ? (
            <TopologyGraph data={topology.data} activeAssetId={selected} onSelectAsset={setSelected} />
          ) : (
            <EmptyState
              title="No segments configured"
              description="Add a monitored segment and inventory devices before the topology can be drawn."
              action={
                <Link to="/devices" className="btn mt-2">
                  Open device inventory
                </Link>
              }
            />
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="Selected device" subtitle="Click any node in the topology">
            {!selected ? (
              <p className="text-xs text-slate-500">No device selected.</p>
            ) : assetContext.loading ? (
              <LoadingBlock rows={3} />
            ) : assetContext.data ? (
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-medium text-slate-100">{assetContext.data.asset.hostname}</p>
                  <p className="font-mono text-[11px] text-slate-500">
                    {assetContext.data.asset.ip_address} · {assetContext.data.asset.device_type}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={assetContext.data.asset.trust_state} />
                  <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">
                    criticality {assetContext.data.asset.criticality}/5
                  </span>
                  <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">
                    posture {assetContext.data.asset.posture_score}
                  </span>
                </div>
                <dl className="space-y-1 text-[11px] text-slate-400">
                  <div className="flex justify-between gap-3">
                    <dt>Endpoint protection</dt>
                    <dd className="font-mono text-slate-300">{assetContext.data.asset.edr_status}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt>Patch level</dt>
                    <dd className="font-mono text-slate-300">{assetContext.data.asset.patch_level}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt>Last seen</dt>
                    <dd className="font-mono text-slate-300">{relativeTime(assetContext.data.asset.last_seen_at)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt>Admission decision</dt>
                    <dd className="font-mono text-slate-300">{assetContext.data.admission.outcome}</dd>
                  </div>
                </dl>
                <p className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-[11px] leading-relaxed text-slate-500">
                  {assetContext.data.admission.reason}
                </p>
                <Link to="/devices" className="link text-[11px]">
                  Open device security →
                </Link>
              </div>
            ) : (
              <p className="text-xs text-slate-500">Device details unavailable.</p>
            )}
          </Panel>

          <Panel title="Suspicious paths" subtitle={`${suspicious.length} path(s) from open alerts`} bodyClassName="p-0">
            {suspicious.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No suspicious paths" description="No open alerts currently map to known source and destination assets." icon="✓" />
              </div>
            ) : (
              <ul className="max-h-[320px] divide-y divide-white/[0.05] overflow-y-auto">
                {suspicious.slice(0, 12).map((link) => (
                  <li key={link.id} className="px-4 py-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="line-clamp-2 text-[11px] text-slate-200">{link.label}</p>
                        <p className="mt-1 font-mono text-[10px] text-slate-500">
                          {link.source.slice(0, 12)} → {link.target.slice(0, 12)}
                        </p>
                      </div>
                      <SeverityBadge severity={link.severity} />
                    </div>
                    <div className="mt-2">
                      <RiskMeter score={link.risk_score} size="sm" />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <Panel title="Recent telemetry" subtitle="Latest 25 events across all sensors" bodyClassName="p-0">
        {feed.loading ? (
          <div className="p-4">
            <LoadingBlock rows={5} />
          </div>
        ) : feed.data && feed.data.length > 0 ? (
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full text-xs">
              <thead className="table-head">
                <tr>
                  <th className="px-4 py-2">Time</th>
                  <th className="px-2 py-2">Sensor</th>
                  <th className="px-2 py-2">Event</th>
                  <th className="px-2 py-2">Path</th>
                  <th className="px-2 py-2">Severity</th>
                  <th className="px-4 py-2 text-right">Risk</th>
                </tr>
              </thead>
              <tbody>
                {feed.data.map((event) => (
                  <tr key={event.id} className="row-hover border-t border-white/[0.04]">
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-500">{formatTime(event.ts)}</td>
                    <td className="px-2 py-2 text-[11px] text-slate-400">{event.source}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-slate-300">{event.event_type}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-slate-400">
                      {event.src_ip ?? '—'} → {event.dst_ip ?? '—'}
                      {event.dst_port ? `:${event.dst_port}` : ''}
                    </td>
                    <td className="px-2 py-2">
                      <SeverityBadge severity={event.severity} />
                    </td>
                    <td className="px-4 py-2 text-right font-mono text-[11px] text-slate-300">
                      {event.risk_score || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4">
            <EmptyState title="No events" description="Telemetry will appear here once a sensor posts to the ingestion endpoint." />
          </div>
        )}
      </Panel>
    </div>
  )
}
