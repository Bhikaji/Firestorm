import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../services/auth'
import { PostureRing, SeverityBars, TrendChart, TrustDonut } from '../components/charts'
import {
  DemoBadge,
  EmptyState,
  ErrorState,
  LoadingBlock,
  Panel,
  RiskMeter,
  SectionTitle,
  SeverityBadge,
  StaleBadge,
  StatCard,
  StatusBadge,
  formatTime,
  relativeTime,
} from '../components/ui'

export default function OverviewPage() {
  const { user } = useAuth()
  const overview = useAsync(() => api.overview(), [])
  const severity = useAsync(() => api.severity(24), [])
  const trend = useAsync(() => api.trend(7), [])
  const trust = useAsync(() => api.trust(), [])
  const feed = useAsync(() => api.feed(12), [])
  const risky = useAsync(() => api.riskyAssets(6), [])
  const attention = useAsync(() => api.attention(), [])
  const layers = useAsync(() => api.layers(), [])

  const counts = overview.data?.counts
  const degradedLayers = useMemo(
    () => (layers.data ?? []).filter((layer) => ['degraded', 'not_configured'].includes(layer.status)),
    [layers.data],
  )

  return (
    <div className="space-y-4">
      <SectionTitle hint={`Signed in as ${user?.full_name} · ${user?.role}. Figures are derived from ingested telemetry only.`}>
        Executive overview
      </SectionTitle>

      {overview.error && <ErrorState message={overview.error} onRetry={overview.refresh} />}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Security posture"
          value={overview.loading ? '—' : `${overview.data?.posture.score ?? 0}%`}
          tone={
            (overview.data?.posture.score ?? 0) >= 80
              ? 'ok'
              : (overview.data?.posture.score ?? 0) >= 60
                ? 'accent'
                : 'warning'
          }
          hint={overview.data?.posture.label ?? 'awaiting telemetry'}
          footer={
            <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
              <StaleBadge stale={overview.data?.freshness.stale ?? null} lastEventAt={overview.data?.freshness.last_event_at ?? null} />
              {overview.data?.demo && <DemoBadge />}
            </div>
          }
        />
        <StatCard
          label="Open alerts"
          value={overview.loading ? '—' : counts?.open_alerts ?? 0}
          tone={(counts?.critical_alerts ?? 0) > 0 ? 'critical' : 'default'}
          hint={`${counts?.critical_alerts ?? 0} critical · ${counts?.events_24h ?? 0} events in 24h`}
          footer={
            <Link to="/alerts" className="link text-[11px]">
              Triage queue →
            </Link>
          }
        />
        <StatCard
          label="Active incidents"
          value={overview.loading ? '—' : counts?.active_incidents ?? 0}
          tone={(counts?.active_incidents ?? 0) > 0 ? 'warning' : 'ok'}
          hint={`${counts?.pending_approvals ?? 0} response action(s) awaiting approval`}
          footer={
            <Link to="/incidents" className="link text-[11px]">
              Incident command →
            </Link>
          }
        />
        <StatCard
          label="Devices"
          value={overview.loading ? '—' : counts?.assets ?? 0}
          hint={`${counts?.unknown_assets ?? 0} unassessed · ${counts?.high_risk_assets ?? 0} non-compliant/compromised`}
          footer={
            <Link to="/devices" className="link text-[11px]">
              Device inventory →
            </Link>
          }
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Security posture"
          subtitle="Enrolled and compliant device share"
          className="xl:col-span-1"
          actions={<Link className="link text-[11px]" to="/devices">details</Link>}
        >
          {overview.loading ? (
            <LoadingBlock rows={3} />
          ) : (
            <PostureRing score={overview.data?.posture.score ?? 0} label={overview.data?.posture.label ?? 'Unknown'} />
          )}
          <dl className="mt-4 grid grid-cols-3 gap-2 text-center">
            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-2">
              <dt className="text-[10px] uppercase tracking-wider text-slate-500">Trusted</dt>
              <dd className="font-mono text-sm text-emerald-300">{overview.data?.posture.trusted ?? 0}</dd>
            </div>
            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-2">
              <dt className="text-[10px] uppercase tracking-wider text-slate-500">Unknown</dt>
              <dd className="font-mono text-sm text-slate-300">{overview.data?.posture.unknown ?? 0}</dd>
            </div>
            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-2">
              <dt className="text-[10px] uppercase tracking-wider text-slate-500">Quarantined</dt>
              <dd className="font-mono text-sm text-orange-300">{overview.data?.posture.quarantined ?? 0}</dd>
            </div>
          </dl>
        </Panel>

        <Panel title="Severity distribution" subtitle="Alerts created in the last 24 hours">
          {severity.loading ? <LoadingBlock rows={5} /> : <SeverityBars data={severity.data ?? []} />}
        </Panel>

        <Panel title="Device trust" subtitle="Admission state across the inventory">
          {trust.loading ? <LoadingBlock rows={4} /> : <TrustDonut data={trust.data ?? []} />}
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Live event stream"
          subtitle="Most recent normalised telemetry"
          className="xl:col-span-2"
          actions={
            <Link className="link text-[11px]" to="/events">
              full stream
            </Link>
          }
          bodyClassName="p-0"
        >
          {feed.loading ? (
            <div className="p-4">
              <LoadingBlock rows={6} />
            </div>
          ) : feed.data && feed.data.length > 0 ? (
            <div className="max-h-[320px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Time</th>
                    <th className="px-2 py-2">Type</th>
                    <th className="px-2 py-2">Source → destination</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-4 py-2 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {feed.data.map((event) => (
                    <tr key={event.id} className="row-hover border-t border-white/[0.04]">
                      <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-500">
                        {formatTime(event.ts)}
                      </td>
                      <td className="px-2 py-2">
                        <span className="font-mono text-[11px] text-slate-300">{event.event_type}</span>
                        <span className="ml-2 text-[10px] text-slate-600">{event.source}</span>
                      </td>
                      <td className="px-2 py-2 font-mono text-[11px] text-slate-400">
                        {event.src_ip ?? '—'}
                        {event.dst_port ? ` → ${event.dst_ip ?? '—'}:${event.dst_port}` : event.dst_ip ? ` → ${event.dst_ip}` : ''}
                        {event.dns_query && <span className="block truncate text-slate-600">{event.dns_query}</span>}
                      </td>
                      <td className="px-2 py-2">
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td className="px-4 py-2 text-right">
                        {event.alert_id ? (
                          <Link to={`/alerts?alert=${event.alert_id}`} className="link font-mono text-[11px]">
                            {event.risk_score}
                          </Link>
                        ) : (
                          <span className="font-mono text-[11px] text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-4">
              <EmptyState
                title="No telemetry received yet"
                description="Sensors post to /api/v1/telemetry/events with the X-API-Key header. Until an event arrives, this panel and every metric above will be empty."
                action={
                  <Link to="/layers" className="btn mt-2">
                    Review sensor configuration
                  </Link>
                }
              />
            </div>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="Attention required" subtitle="Highest-risk open alerts" bodyClassName="p-0">
            {attention.loading ? (
              <div className="p-4">
                <LoadingBlock rows={4} />
              </div>
            ) : attention.data && attention.data.length > 0 ? (
              <ul className="divide-y divide-white/[0.05]">
                {attention.data.slice(0, 5).map((item) => (
                  <li key={item.id} className="px-4 py-2.5">
                    <Link to={`/alerts?alert=${item.id}`} className="block">
                      <p className="line-clamp-2 text-xs text-slate-200">{item.title}</p>
                      <div className="mt-1.5 flex items-center gap-2 text-[10px] text-slate-500">
                        <SeverityBadge severity={item.severity} />
                        <span className="font-mono">risk {item.risk_score}</span>
                        <span>· {relativeTime(item.first_seen)}</span>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4">
                <EmptyState title="Nothing needs attention" description="No open high or critical alerts in the current dataset." icon="✓" />
              </div>
            )}
          </Panel>

          <Panel title="Highest-risk assets" subtitle="Ranked by open alert risk" bodyClassName="p-0">
            {risky.loading ? (
              <div className="p-4">
                <LoadingBlock rows={3} />
              </div>
            ) : risky.data && risky.data.length > 0 ? (
              <ul className="divide-y divide-white/[0.05]">
                {risky.data.map((asset) => (
                  <li key={asset.asset_id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                    <div className="min-w-0">
                      <Link to="/devices" className="truncate text-xs text-slate-200 hover:text-neon-cyan">
                        {asset.hostname}
                      </Link>
                      <p className="font-mono text-[10px] text-slate-600">
                        {asset.ip_address} · {asset.open_alerts} alert(s)
                      </p>
                    </div>
                    <div className="w-24 shrink-0">
                      <RiskMeter score={asset.risk_score} size="sm" />
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4">
                <EmptyState title="No risky assets" description="No asset currently has open alerts." icon="✓" />
              </div>
            )}
          </Panel>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="7-day alert trend" subtitle="High-severity volume per day (policy default bands)" className="xl:col-span-2">
          {trend.loading ? <LoadingBlock rows={3} /> : <TrendChart data={trend.data ?? []} />}
        </Panel>

        <Panel title="Protection layer health" subtitle="Independent controls; one failure must not blind you">
          {layers.loading ? (
            <LoadingBlock rows={5} />
          ) : (
            <ul className="space-y-2">
              {(layers.data ?? []).map((layer) => (
                <li key={layer.id} className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
                  <span className="truncate text-[11px] text-slate-300">{layer.name}</span>
                  <StatusBadge status={layer.status} />
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-slate-500">
            {degradedLayers.length > 0
              ? `${degradedLayers.length} layer(s) are degraded or unconfigured: ${degradedLayers.map((l) => l.name).join(', ')}.`
              : 'All configured layers report healthy. Simulated adapters are labelled and never presented as live protection.'}
          </p>
          <Link to="/layers" className="link mt-2 inline-block text-[11px]">
            Layer detail →
          </Link>
        </Panel>
      </div>
    </div>
  )
}
