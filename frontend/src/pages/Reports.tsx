import { useState } from 'react'
import api from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { SeverityBars } from '../components/charts'
import { EmptyState, ErrorState, LoadingBlock, Panel, SectionTitle } from '../components/ui'

export default function ReportsPage() {
  const [period, setPeriod] = useState<'daily' | 'monthly'>('daily')
  const report = useAsync(
    () => (period === 'daily' ? api.dailyReport() : api.monthlyReport()),
    [period],
  )

  const data = report.data

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle hint="Reports are computed from ingested telemetry. A low count is not evidence of a low-risk environment.">
          Reports
        </SectionTitle>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-lg border border-white/10">
            {(['daily', 'monthly'] as const).map((item) => (
              <button
                key={item}
                className={`px-3 py-1.5 text-xs ${period === item ? 'bg-neon-cyan/15 text-neon-cyan' : 'text-slate-400 hover:bg-white/5'}`}
                onClick={() => setPeriod(item)}
              >
                {item === 'daily' ? 'Daily' : 'Monthly'}
              </button>
            ))}
          </div>
          <button className="btn px-2 py-1 text-xs" onClick={report.refresh}>
            Refresh
          </button>
        </div>
      </div>

      {report.error && <ErrorState message={report.error} onRetry={report.refresh} />}
      {report.loading && <LoadingBlock rows={6} />}

      {data && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Metric label="Events ingested" value={data.events_ingested} />
            <Metric label="Alerts" value={data.alerts.total} hint={`${data.alerts.open} open`} />
            <Metric label="False positives" value={`${data.alerts.false_positive_rate}%`} hint={`${data.alerts.false_positives} flagged`} />
            <Metric label="Mean time to resolve" value={data.incidents.mttr_minutes != null ? `${data.incidents.mttr_minutes} min` : '—'} />
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Alert severity" subtitle={data.label}>
              {Object.keys(data.alerts.by_severity).length > 0 ? (
                <SeverityBars
                  data={['critical', 'high', 'medium', 'low', 'info'].map((severity) => ({
                    severity,
                    count: data.alerts.by_severity[severity] ?? 0,
                  }))}
                />
              ) : (
                <EmptyState title="No alerts in window" description="No alerts were created in this reporting period." />
              )}
            </Panel>

            <Panel title="Top detection rules" subtitle="Volume by rule identifier">
              {Object.keys(data.alerts.by_rule).length > 0 ? (
                <ul className="space-y-1.5 text-[11px]">
                  {Object.entries(data.alerts.by_rule).map(([rule, count]) => (
                    <li key={rule} className="flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-400">{rule}</span>
                      <span className="font-mono text-slate-300">{count}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No detections" description="No rules fired in this period." />
              )}
            </Panel>

            <Panel title="Device compliance" subtitle="Enrolled and posture-compliant">
              <div className="space-y-2 text-[11px]">
                <Row label="Total assets" value={String(data.device_compliance.total_assets)} />
                <Row label="Compliant" value={String(data.device_compliance.compliant)} />
                <Row label="Unknown / unassessed" value={String(data.device_compliance.unknown)} />
                <Row label="Quarantined" value={String(data.device_compliance.quarantined)} />
                <Row label="Compliance" value={`${data.device_compliance.compliance_percent}%`} />
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title="Sensor coverage" subtitle="Monitored segments and enrolment">
              <div className="overflow-auto">
                <table className="w-full text-[11px]">
                  <thead className="table-head">
                    <tr>
                      <th className="px-2 py-1.5">Segment</th>
                      <th className="px-2 py-1.5">CIDR</th>
                      <th className="px-2 py-1.5 text-right">Devices</th>
                      <th className="px-2 py-1.5 text-right">Enrolled</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sensor_coverage.per_segment.map((segment) => (
                      <tr key={segment.cidr} className="border-t border-white/[0.04]">
                        <td className="px-2 py-1.5 text-slate-300">
                          {segment.segment}
                          {!segment.monitored && <span className="ml-1 text-amber-300">(unmonitored)</span>}
                        </td>
                        <td className="px-2 py-1.5 font-mono text-slate-500">{segment.cidr}</td>
                        <td className="px-2 py-1.5 text-right font-mono text-slate-300">{segment.devices}</td>
                        <td className="px-2 py-1.5 text-right font-mono text-slate-300">{segment.enrolled_percent}%</td>
                      </tr>
                    ))}
                    {data.sensor_coverage.per_segment.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-2 py-3 text-center text-slate-500">
                          No segments configured.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel title="Administrative & response activity" subtitle="Audited events in this window">
              {data.administrative_activity.length > 0 ? (
                <ul className="space-y-1.5 text-[11px]">
                  {data.administrative_activity.map((item) => (
                    <li key={item.action} className="flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-400">{item.action}</span>
                      <span className="font-mono text-slate-300">{item.count}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No administrative activity" description="No audited actions were recorded in this window." />
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <a className="btn px-2 py-1 text-[11px]" href="/api/v1/reports/daily/export" download>
                  Download daily markdown
                </a>
              </div>
            </Panel>
          </div>

          <Panel title="Caveats" subtitle="Read any report with these limitations in mind">
            <ul className="list-disc space-y-1 pl-5 text-[11px] leading-relaxed text-slate-400">
              {data.caveats.map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
              <li>Figures exclude telemetry from segments that are not monitored or instruments that are not integrated.</li>
              <li>Attacker identity is never inferred from an IP address or geolocation alone.</li>
            </ul>
            <p className="mt-3 text-[10px] text-slate-600">
              Generated {new Date(data.generated_at).toLocaleString()} · window {new Date(data.window.start).toLocaleString()} →{' '}
              {new Date(data.window.end).toLocaleString()}
            </p>
          </Panel>
        </>
      )}
    </div>
  )
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="panel p-4">
      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-1 font-mono text-2xl text-slate-100">{value}</p>
      {hint && <p className="mt-0.5 text-[10px] text-slate-500">{hint}</p>}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-1.5">
      <span className="text-slate-500">{label}</span>
      <span className="font-mono text-slate-300">{value}</span>
    </div>
  )
}
