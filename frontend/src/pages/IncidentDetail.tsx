import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import api, { ApiError } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../services/auth'
import { useNotify } from '../hooks/useNotify'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Panel,
  RiskMeter,
  SectionTitle,
  SeverityBadge,
  StatusBadge,
  formatTime,
  relativeTime,
} from '../components/ui'

const TRANSITIONS: Record<string, string[]> = {
  new: ['triage', 'closed'],
  triage: ['containment', 'closed', 'new'],
  containment: ['contained', 'eradication', 'triage'],
  contained: ['eradication', 'recovery'],
  eradication: ['recovery'],
  recovery: ['closed'],
  closed: [],
}

export default function IncidentDetailPage() {
  const { incidentId = '' } = useParams()
  const { can, user } = useAuth()
  const notify = useNotify()
  const incident = useAsync(() => api.incident(incidentId), [incidentId])
  const correlations = useAsync(() => api.correlations(incidentId), [incidentId])
  const [note, setNote] = useState('')
  const [hypothesis, setHypothesis] = useState('')
  const [busy, setBusy] = useState(false)
  const [actionOpen, setActionOpen] = useState(false)
  const [actionType, setActionType] = useState('quarantine_asset')
  const [actionTarget, setActionTarget] = useState('')
  const [actionReason, setActionReason] = useState('')
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [evidenceKind, setEvidenceKind] = useState('event_bundle')
  const [evidenceLabel, setEvidenceLabel] = useState('')
  const [evidenceNote, setEvidenceNote] = useState('')

  const refresh = () => {
    incident.refresh()
    correlations.refresh()
  }

  const handle = async (fn: () => Promise<unknown>, message: string) => {
    setBusy(true)
    try {
      await fn()
      notify('success', message)
      refresh()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Action failed')
    } finally {
      setBusy(false)
    }
  }

  if (incident.error) return <ErrorState message={incident.error} onRetry={incident.refresh} />
  if (incident.loading || !incident.data) return <LoadingBlock rows={10} label="Loading incident" />

  const data = incident.data
  const transitions = TRANSITIONS[data.status] ?? []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-500">{data.reference}</p>
          <SectionTitle hint={`Detected ${formatTime(data.detected_at)} · ${data.observed_facts.length} observed fact(s) · ${data.hypotheses.length} hypothesis(es)`}>
            {data.title}
          </SectionTitle>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={data.severity} />
          <StatusBadge status={data.status} />
          <Link to="/incidents" className="btn px-2 py-1 text-xs">
            Back to incidents
          </Link>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.6fr_1fr]">
        <div className="space-y-4">
          <Panel title="Summary" subtitle="Facts are separate from hypotheses by design">
            <p className="text-xs leading-relaxed text-slate-300">{data.summary}</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div>
                <p className="mb-1 text-[10px] uppercase tracking-wider text-emerald-300/80">Observed facts</p>
                <ul className="space-y-1.5">
                  {data.observed_facts.length === 0 && <li className="text-[11px] text-slate-500">No facts recorded.</li>}
                  {data.observed_facts.map((fact, index) => (
                    <li key={index} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-[11px] text-slate-400">
                      <span className="text-slate-200">{String(fact.fact ?? '')}</span>
                      {fact.detail && <span className="block text-slate-500">{String(fact.detail)}</span>}
                      {fact.source && <span className="block font-mono text-[10px] text-slate-600">source: {String(fact.source)}</span>}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="mb-1 text-[10px] uppercase tracking-wider text-amber-300/80">Hypotheses (unverified)</p>
                <ul className="space-y-1.5">
                  {data.hypotheses.length === 0 && <li className="text-[11px] text-slate-500">No hypotheses recorded.</li>}
                  {data.hypotheses.map((item, index) => (
                    <li key={index} className="rounded-lg border border-amber-400/15 bg-amber-400/[0.04] p-2 text-[11px] text-slate-400">
                      <span className="text-slate-200">{String(item.hypothesis ?? '')}</span>
                      <span className="block text-[10px] text-slate-500">
                        confidence {String(item.confidence ?? '—')} · {String(item.status ?? 'unverified')}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            {can('incident:write') && (
              <div className="mt-3 flex flex-wrap gap-2">
                <input
                  className="input flex-1 py-1.5 text-xs"
                  placeholder="Add a hypothesis (recorded as unverified)"
                  value={hypothesis}
                  onChange={(event) => setHypothesis(event.target.value)}
                />
                <button
                  className="btn px-2 py-1 text-xs"
                  disabled={busy || hypothesis.trim().length < 3}
                  onClick={() =>
                    handle(async () => {
                      await api.updateIncident(incidentId, { hypothesis })
                      setHypothesis('')
                    }, 'Hypothesis recorded')
                  }
                >
                  Add
                </button>
              </div>
            )}
          </Panel>

          <Panel title="Incident timeline" subtitle="Append-only record of detection, evidence, actions and notes" bodyClassName="p-0">
            <ol className="relative max-h-[420px] space-y-0 overflow-y-auto px-4 py-3">
              {data.timeline.map((entry) => (
                <li key={entry.id} className="relative border-l border-white/10 pb-4 pl-4 last:pb-0">
                  <span className="absolute -left-[5px] top-1 h-2.5 w-2.5 rounded-full border border-white/20 bg-graphite-900" />
                  <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
                    <span className="font-mono">{formatTime(entry.ts)}</span>
                    <span className="chip border-white/10 bg-white/[0.03] text-slate-400 normal-case">{entry.kind}</span>
                    <span>{entry.actor}</span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-slate-300">{entry.message}</p>
                </li>
              ))}
              {data.timeline.length === 0 && <li className="text-[11px] text-slate-500">No timeline entries.</li>}
            </ol>
            {can('incident:write') && (
              <div className="flex flex-wrap gap-2 border-t border-white/[0.06] p-3">
                <input
                  className="input flex-1 py-1.5 text-xs"
                  placeholder="Add an investigation note (audited)"
                  value={note}
                  maxLength={4000}
                  onChange={(event) => setNote(event.target.value)}
                />
                <button
                  className="btn px-2 py-1 text-xs"
                  disabled={busy || note.trim().length < 2}
                  onClick={() =>
                    handle(async () => {
                      await api.addIncidentNote(incidentId, note)
                      setNote('')
                    }, 'Note added')
                  }
                >
                  Add note
                </button>
              </div>
            )}
          </Panel>

          <Panel title="Evidence" subtitle="SHA-256 hashed, chain-of-custody recorded" bodyClassName="p-0">
            {data.evidence.length === 0 ? (
              <div className="p-4">
                <EmptyState
                  title="No evidence collected"
                  description="Collect event bundles, file hashes or analyst notes to preserve an investigation record."
                  action={
                    can('evidence:collect') ? (
                      <button className="btn mt-2" onClick={() => setEvidenceOpen(true)}>
                        Collect evidence
                      </button>
                    ) : undefined
                  }
                />
              </div>
            ) : (
              <ul className="divide-y divide-white/[0.05]">
                {data.evidence.map((item) => (
                  <li key={item.id} className="px-4 py-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-[11px] text-slate-200">{item.label}</p>
                        <p className="mt-0.5 truncate font-mono text-[10px] text-slate-500">sha256 {item.sha256}</p>
                        <p className="text-[10px] text-slate-600">
                          {item.kind} · {item.collected_by} · {relativeTime(item.collected_at)}
                        </p>
                      </div>
                      <button
                        className="btn px-2 py-1 text-[10px]"
                        onClick={() =>
                          handle(async () => {
                            const result = await api.verifyEvidence(item.id)
                            notify(
                              result.verified === false ? 'error' : 'success',
                              result.verified === null ? result.detail : result.verified ? 'Hash verified' : 'Hash mismatch',
                            )
                          }, 'Integrity check complete')
                        }
                      >
                        Verify
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {can('evidence:collect') && data.evidence.length > 0 && (
              <div className="border-t border-white/[0.06] p-3">
                <button className="btn px-2 py-1 text-xs" onClick={() => setEvidenceOpen(true)}>
                  Collect more evidence
                </button>
              </div>
            )}
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Risk & status" subtitle="Automated score; analyst decisions remain explicit">
            <RiskMeter score={data.risk_score} />
            <dl className="mt-3 space-y-1 text-[11px]">
              <Row label="Owner" value={data.owner_id ?? 'unassigned'} />
              <Row label="Detected" value={formatTime(data.detected_at)} />
              <Row label="Contained" value={data.contained_at ? formatTime(data.contained_at) : '—'} />
              <Row label="Closed" value={data.closed_at ? formatTime(data.closed_at) : '—'} />
              <Row label="MITRE" value={data.mitre_tactics.join(', ') || '—'} />
              <Row label="Accounts" value={data.affected_accounts.join(', ') || '—'} />
            </dl>
            {can('incident:write') && transitions.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {transitions.map((status) => (
                  <button
                    key={status}
                    className="btn px-2 py-1 text-[11px]"
                    disabled={busy}
                    onClick={() => handle(() => api.updateIncident(incidentId, { status }), `Incident moved to ${status}`)}
                  >
                    → {status}
                  </button>
                ))}
              </div>
            )}
          </Panel>

          <Panel title="Related alerts" bodyClassName="p-0">
            {data.alerts.length === 0 ? (
              <p className="p-4 text-[11px] text-slate-500">No alerts linked.</p>
            ) : (
              <ul className="divide-y divide-white/[0.05]">
                {data.alerts.map((alert) => (
                  <li key={alert.id} className="px-4 py-2">
                    <Link to={`/alerts?alert=${alert.id}`} className="block">
                      <p className="line-clamp-2 text-[11px] text-slate-200">{alert.title}</p>
                      <p className="mt-0.5 text-[10px] text-slate-500">
                        {alert.rule_id} · risk {alert.risk_score} · {alert.status}
                      </p>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title="Response actions"
            actions={
              can('action:request') ? (
                <button className="btn px-2 py-1 text-[11px]" onClick={() => setActionOpen(true)}>
                  Request action
                </button>
              ) : undefined
            }
            bodyClassName="p-0"
          >
            {data.actions.length === 0 ? (
              <p className="p-4 text-[11px] text-slate-500">No response actions requested.</p>
            ) : (
              <ul className="divide-y divide-white/[0.05]">
                {data.actions.map((action) => (
                  <li key={action.id} className="space-y-1.5 px-4 py-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-[11px] text-slate-200">
                          <span className="font-mono">{action.action_type}</span> → {action.target}
                        </p>
                        <p className="text-[10px] text-slate-500">
                          {action.integration} · {action.mode} · {relativeTime(action.created_at)}
                        </p>
                      </div>
                      <StatusBadge status={action.status} />
                    </div>
                    {action.result && <p className="text-[10px] text-slate-500">{action.result}</p>}
                    <div className="flex flex-wrap gap-1.5">
                      {can('action:approve') && action.status === 'pending_approval' && (
                        <>
                          <button
                            className="btn px-2 py-0.5 text-[10px]"
                            disabled={busy}
                            onClick={() => handle(() => api.approveAction(action.id, 'Approved in incident workspace'), 'Action approved')}
                          >
                            Approve
                          </button>
                          <button
                            className="btn px-2 py-0.5 text-[10px]"
                            disabled={busy}
                            onClick={() => handle(() => api.rejectAction(action.id, 'Rejected by approver'), 'Action rejected')}
                          >
                            Reject
                          </button>
                        </>
                      )}
                      {can('action:execute') && action.status === 'approved' && (
                        <button
                          className="btn px-2 py-0.5 text-[10px]"
                          disabled={busy}
                          onClick={() => handle(() => api.executeAction(action.id), 'Action executed')}
                        >
                          Execute
                        </button>
                      )}
                      {can('action:execute') && action.status === 'succeeded' && action.reversible && (
                        <button
                          className="btn px-2 py-0.5 text-[10px]"
                          disabled={busy}
                          onClick={() => handle(() => api.revertAction(action.id, 'Reverted by responder'), 'Action reverted')}
                        >
                          Revert
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Suggested correlations" subtitle="Alerts that may belong to this incident" bodyClassName="p-0">
            {correlations.loading ? (
              <div className="p-4">
                <LoadingBlock rows={2} />
              </div>
            ) : correlations.data && correlations.data.length > 0 ? (
              <ul className="max-h-56 divide-y divide-white/[0.05] overflow-y-auto">
                {correlations.data.map((item) => (
                  <li key={item.alert_id} className="px-4 py-2">
                    <p className="line-clamp-1 text-[11px] text-slate-300">{item.title}</p>
                    <p className="text-[10px] text-slate-500">
                      risk {item.risk_score} · {item.reason} · {relativeTime(item.first_seen)}
                    </p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="p-4 text-[11px] text-slate-500">No additional alerts correlate within the window.</p>
            )}
          </Panel>

          {user?.role === 'admin' && can('action:approve') && (
            <div className="panel border-white/[0.06] p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Emergency recovery</p>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                Releases every applied containment action. Use only during an authorised recovery procedure.
              </p>
              <Link to="/incidents" className="btn mt-2 w-full justify-center px-2 py-1 text-[11px]">
                Manage enforcement from incident list
              </Link>
            </div>
          )}
        </div>
      </div>

      <Modal
        open={actionOpen}
        onClose={() => setActionOpen(false)}
        title="Request response action"
        footer={
          <>
            <button className="btn" onClick={() => setActionOpen(false)}>
              Cancel
            </button>
            <button
              className="btn btn-danger"
              disabled={busy || actionReason.trim().length < 10}
              onClick={() =>
                handle(async () => {
                  await api.requestAction({
                    action_type: actionType,
                    target: actionTarget,
                    reason: actionReason,
                    incident_id: incidentId,
                    asset_id: data.affected_asset_ids[0],
                  })
                  setActionOpen(false)
                  setActionReason('')
                }, 'Action requested')
              }
            >
              Submit request
            </button>
          </>
        }
      >
        <div>
          <label className="label" htmlFor="action-type">
            Action
          </label>
          <select id="action-type" className="input" value={actionType} onChange={(event) => setActionType(event.target.value)}>
            <option value="quarantine_asset">Quarantine asset (NAC VLAN move)</option>
            <option value="isolate_endpoint">Isolate endpoint (EDR)</option>
            <option value="block_ip">Block IP (firewall)</option>
            <option value="sinkhole_domain">Sinkhole domain (DNS)</option>
            <option value="disable_account">Disable account (identity)</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="action-target">
            Target
          </label>
          <input
            id="action-target"
            className="input"
            value={actionTarget}
            onChange={(event) => setActionTarget(event.target.value)}
            placeholder="IP, MAC, hostname or account principal"
          />
        </div>
        <div>
          <label className="label" htmlFor="action-reason">
            Justification (min 10 characters)
          </label>
          <textarea
            id="action-reason"
            className="input min-h-[80px]"
            value={actionReason}
            onChange={(event) => setActionReason(event.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={evidenceOpen}
        onClose={() => setEvidenceOpen(false)}
        title="Collect evidence"
        footer={
          <>
            <button className="btn" onClick={() => setEvidenceOpen(false)}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              disabled={busy || evidenceLabel.trim().length < 3}
              onClick={() =>
                handle(async () => {
                  await api.collectEvidence(incidentId, {
                    kind: evidenceKind,
                    label: evidenceLabel,
                    content: evidenceNote || undefined,
                    metadata: { collected_from: 'dashboard', analyst: user?.email },
                  })
                  setEvidenceOpen(false)
                  setEvidenceLabel('')
                  setEvidenceNote('')
                }, 'Evidence collected and hashed')
              }
            >
              Collect
            </button>
          </>
        }
      >
        <div>
          <label className="label" htmlFor="evidence-kind">
            Kind
          </label>
          <select id="evidence-kind" className="input" value={evidenceKind} onChange={(event) => setEvidenceKind(event.target.value)}>
            <option value="event_bundle">Event bundle</option>
            <option value="file_hash">File hash record</option>
            <option value="email_header">Email metadata</option>
            <option value="analyst_note">Analyst note</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="evidence-label">
            Label
          </label>
          <input
            id="evidence-label"
            className="input"
            value={evidenceLabel}
            onChange={(event) => setEvidenceLabel(event.target.value)}
            placeholder="Endpoint telemetry bundle 2026-10-23"
          />
        </div>
        <div>
          <label className="label" htmlFor="evidence-note">
            Content / observation (optional, hashed)
          </label>
          <textarea
            id="evidence-note"
            className="input min-h-[80px]"
            value={evidenceNote}
            onChange={(event) => setEvidenceNote(event.target.value)}
          />
        </div>
        <p className="text-[11px] leading-relaxed text-slate-500">
          Only metadata and hashes are stored by default. Do not paste credentials, personal data or payload content
          unless your evidence-handling policy requires it.
        </p>
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
