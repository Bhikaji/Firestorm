import { useState } from 'react'
import api from '../services/api'
import { useAsync, useDebounced } from '../hooks/useAsync'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Pagination,
  Panel,
  SectionTitle,
  Select,
  SeverityBadge,
  formatTime,
} from '../components/ui'
import type { SecurityEvent } from '../types'

const SOURCE_OPTIONS = [
  'zeek',
  'suricata',
  'wazuh',
  'osquery',
  'antivirus',
  'firewall',
  'firestorm',
]

export default function EventsPage() {
  const [page, setPage] = useState(1)
  const [source, setSource] = useState('')
  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')
  const [eventId, setEventId] = useState<string | null>(null)
  const debounced = useDebounced(search, 350)

  const events = useAsync(
    () =>
      api.events({
        page,
        page_size: 50,
        source: source || undefined,
        severity: severity || undefined,
        q: debounced || undefined,
      }),
    [page, source, severity, debounced],
  )
  const sources = useAsync(() => api.eventSources(), [])
  const detail = useAsync(() => (eventId ? api.event(eventId) : Promise.resolve(null)), [eventId], {
    enabled: Boolean(eventId),
  })

  return (
    <div className="space-y-4">
      <SectionTitle hint="Normalised events from all authorised sensors. Duplicate deliveries are collapsed by fingerprint.">
        Real-time event stream
      </SectionTitle>

      <Panel
        title="Filters"
        bodyClassName="p-3"
        actions={
          <button className="btn px-2 py-1 text-xs" onClick={events.refresh}>
            Refresh
          </button>
        }
      >
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <input
            className="input py-1.5 text-xs"
            placeholder="Search hostname, DNS query or signature"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
            aria-label="Search events"
          />
          <Select
            ariaLabel="Filter by source"
            value={source}
            onChange={(value) => {
              setSource(value)
              setPage(1)
            }}
            options={[
              { value: '', label: 'All sources' },
              ...SOURCE_OPTIONS.map((item) => ({ value: item, label: item })),
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
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            {(sources.data ?? []).slice(0, 3).map((item) => (
              <span key={item.source} className="chip border-white/10 bg-white/[0.03] text-slate-400 normal-case">
                {item.source} {item.events}
              </span>
            ))}
            {(sources.data ?? []).length === 0 && <span>No sensor reports yet.</span>}
          </div>
        </div>
      </Panel>

      {events.error && <ErrorState message={events.error} onRetry={events.refresh} />}

      <div className="panel overflow-hidden">
        {events.loading ? (
          <div className="p-4">
            <LoadingBlock rows={8} />
          </div>
        ) : events.data && events.data.items.length > 0 ? (
          <>
            <div className="max-h-[620px] overflow-auto">
              <table className="w-full text-xs">
                <thead className="table-head">
                  <tr>
                    <th className="px-4 py-2">Timestamp</th>
                    <th className="px-2 py-2">Source</th>
                    <th className="px-2 py-2">Event type</th>
                    <th className="px-2 py-2">Source → destination</th>
                    <th className="px-2 py-2">Indicator</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-2 py-2 text-right">Risk</th>
                    <th className="px-4 py-2 text-right">Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {events.data.items.map((event) => (
                    <tr
                      key={event.id}
                      className="row-hover cursor-pointer border-t border-white/[0.04]"
                      onClick={() => setEventId(event.id)}
                      tabIndex={0}
                      onKeyDown={(keyEvent) => keyEvent.key === 'Enter' && setEventId(event.id)}
                    >
                      <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-400">{formatTime(event.ts)}</td>
                      <td className="px-2 py-2 text-[11px] text-slate-300">{event.source}</td>
                      <td className="px-2 py-2 font-mono text-[11px] text-slate-300">{event.event_type}</td>
                      <td className="px-2 py-2 font-mono text-[11px] text-slate-400">
                        {event.src_ip ?? '—'} → {event.dst_ip ?? '—'}
                        {event.dst_port ? `:${event.dst_port}` : ''}
                      </td>
                      <td className="max-w-[220px] truncate px-2 py-2 text-[11px] text-slate-400">
                        {event.dns_query ?? event.signature ?? event.hostname ?? '—'}
                      </td>
                      <td className="px-2 py-2">
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td className="px-2 py-2 text-right font-mono text-[11px] text-slate-300">{event.risk_score || '—'}</td>
                      <td className="px-4 py-2 text-right">
                        {event.alert_id ? (
                          <span className="chip border-threat-critical/40 bg-threat-critical/10 text-threat-high">linked</span>
                        ) : (
                          <span className="text-[11px] text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={events.data.page}
              pageSize={events.data.page_size}
              total={events.data.total}
              onPage={setPage}
            />
          </>
        ) : (
          <div className="p-6">
            <EmptyState
              title="No events match these filters"
              description="Adjust the filters, or confirm that a sensor is posting to /api/v1/telemetry/events with a valid X-API-Key."
            />
          </div>
        )}
      </div>

      <Modal
        open={Boolean(eventId)}
        onClose={() => setEventId(null)}
        title="Event detail"
        width="max-w-3xl"
        footer={
          <button className="btn" onClick={() => setEventId(null)}>
            Close
          </button>
        }
      >
        {detail.loading ? (
          <LoadingBlock rows={5} />
        ) : detail.data ? (
          <EventDetailBody event={detail.data} />
        ) : (
          <p className="text-xs text-slate-500">Event not found.</p>
        )}
      </Modal>
    </div>
  )
}

function EventDetailBody({ event }: { event: SecurityEvent }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={event.severity} />
        <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">{event.source}</span>
        <span className="chip border-white/10 bg-white/[0.03] text-slate-300 normal-case">{event.event_type}</span>
        {event.processed && <span className="chip border-emerald-400/30 bg-emerald-400/10 text-emerald-300">processed</span>}
      </div>

      <dl className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-3">
        {[
          ['Timestamp', formatTime(event.ts)],
          ['Sensor', event.sensor ?? '—'],
          ['Hostname', event.hostname ?? '—'],
          ['Source IP', event.src_ip ?? '—'],
          ['Destination', `${event.dst_ip ?? '—'}${event.dst_port ? `:${event.dst_port}` : ''}`],
          ['Protocol', event.protocol ?? '—'],
          ['Bytes in/out', `${event.bytes_in ?? 0} / ${event.bytes_out ?? 0}`],
          ['Risk score', String(event.risk_score)],
          ['Fingerprint', (event.fingerprint ?? '').slice(0, 16) || '—'],
        ].map(([label, value]) => (
          <div key={label} className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 py-1.5">
            <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
            <dd className="mt-0.5 truncate font-mono text-[11px] text-slate-300" title={value}>
              {value}
            </dd>
          </div>
        ))}
      </dl>

      {(event.signature || event.dns_query || event.file_hash) && (
        <div className="space-y-1 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-xs">
          {event.signature && <p><span className="text-slate-500">Signature:</span> {event.signature}</p>}
          {event.dns_query && <p><span className="text-slate-500">DNS query:</span> <span className="font-mono">{event.dns_query}</span></p>}
          {event.file_hash && <p className="break-all"><span className="text-slate-500">File hash:</span> <span className="font-mono">{event.file_hash}</span></p>}
        </div>
      )}

      <div>
        <p className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Raw payload (normalised)</p>
        <pre className="max-h-64 overflow-auto rounded-lg border border-white/[0.06] bg-graphite-950 p-3 text-[11px] leading-relaxed text-slate-400">
{JSON.stringify(event.raw ?? {}, null, 2)}
        </pre>
      </div>
    </div>
  )
}
