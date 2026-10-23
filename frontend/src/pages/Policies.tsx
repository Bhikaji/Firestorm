import { useEffect, useState } from 'react'
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
  SectionTitle,
  StatusBadge,
} from '../components/ui'

export default function PoliciesPage() {
  const { can } = useAuth()
  const notify = useNotify()
  const policies = useAsync(() => api.policies(), [])
  const rules = useAsync(() => api.admissionRules(), [])
  const suppressions = useAsync(() => api.suppressions(), [])
  const [editing, setEditing] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [draftError, setDraftError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (editing) {
      const policy = policies.data?.find((item) => item.id === editing)
      setDraft(JSON.stringify(policy?.config ?? {}, null, 2))
      setDraftError(null)
    }
  }, [editing, policies.data])

  const save = async () => {
    if (!editing) return
    const policy = policies.data?.find((item) => item.id === editing)
    if (!policy) return
    setBusy(true)
    setDraftError(null)
    try {
      const parsed = JSON.parse(draft) as Record<string, unknown>
      await api.updatePolicy(policy.key, { config: parsed })
      notify('success', `Policy ${policy.key} updated (version incremented)`)
      setEditing(null)
      policies.refresh()
    } catch (err) {
      if (err instanceof SyntaxError) setDraftError('Invalid JSON: ' + err.message)
      else setDraftError(err instanceof ApiError ? err.message : 'Update failed')
    } finally {
      setBusy(false)
    }
  }

  const toggleRule = async (id: string, enabled: boolean) => {
    try {
      await api.updateAdmissionRule(id, { enabled })
      notify('success', `Rule ${enabled ? 'enabled' : 'disabled'}`)
      rules.refresh()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Update failed')
    }
  }

  return (
    <div className="space-y-4">
      <SectionTitle hint="Policy is configuration-as-data: adjustable, versioned and audited. Defaults are starting points, not universal standards.">
        Policy management
      </SectionTitle>

      {policies.error && <ErrorState message={policies.error} onRetry={policies.refresh} />}

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Policies" subtitle="Risk bands, response approval, escalation, retention" bodyClassName="p-0">
          {policies.loading ? (
            <div className="p-4">
              <LoadingBlock rows={5} />
            </div>
          ) : (
            <ul className="divide-y divide-white/[0.05]">
              {(policies.data ?? []).map((policy) => (
                <li key={policy.id} className="px-4 py-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-slate-200">{policy.name}</p>
                      <p className="mt-0.5 text-[11px] text-slate-500">{policy.description}</p>
                      <p className="mt-1 font-mono text-[10px] text-slate-600">
                        {policy.key} · v{policy.version} · {policy.category}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <StatusBadge status={policy.enabled ? 'healthy' : 'unavailable'} label={policy.enabled ? 'enabled' : 'disabled'} />
                      {can('policy:write') && (
                        <button className="btn px-2 py-1 text-[10px]" onClick={() => setEditing(policy.id)}>
                          Edit config
                        </button>
                      )}
                    </div>
                  </div>
                  <pre className="mt-2 max-h-32 overflow-auto rounded-lg border border-white/[0.06] bg-graphite-950 p-2 text-[10px] leading-relaxed text-slate-500">
{JSON.stringify(policy.config, null, 2)}
                  </pre>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="Device admission rules" subtitle="Evaluated in priority order; first match wins" bodyClassName="p-0">
            {rules.loading ? (
              <div className="p-4">
                <LoadingBlock rows={4} />
              </div>
            ) : rules.data && rules.data.length > 0 ? (
              <ul className="divide-y divide-white/[0.05]">
                {rules.data.map((rule) => (
                  <li key={rule.id} className="px-4 py-2.5">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-[11px] text-slate-200">
                          <span className="mr-1 font-mono text-slate-500">{rule.priority}</span>
                          {rule.name}
                        </p>
                        <p className="mt-0.5 text-[10px] text-slate-500">{rule.description}</p>
                        <p className="mt-1 font-mono text-[10px] text-slate-600">
                          outcome: {rule.outcome} · {rule.outcome_reason || 'no reason recorded'}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <StatusBadge status={rule.enabled ? 'healthy' : 'unavailable'} label={rule.enabled ? 'on' : 'off'} />
                        {can('policy:write') && (
                          <button
                            className="btn px-2 py-0.5 text-[10px]"
                            onClick={() => toggleRule(rule.id, !rule.enabled)}
                            aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`}
                          >
                            {rule.enabled ? 'Disable' : 'Enable'}
                          </button>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4">
                <EmptyState title="No admission rules" description="Without rules, admission fails closed to restricted access." />
              </div>
            )}
          </Panel>

          <Panel title="Active suppressions" subtitle="Time-boxed; all expire automatically" bodyClassName="p-0">
            {suppressions.loading ? (
              <div className="p-4">
                <LoadingBlock rows={2} />
              </div>
            ) : suppressions.data && suppressions.data.length > 0 ? (
              <ul className="divide-y divide-white/[0.05]">
                {suppressions.data.map((item) => (
                  <li key={item.id} className="flex items-start justify-between gap-2 px-4 py-2">
                    <div className="min-w-0">
                      <p className="text-[11px] text-slate-300">
                        {item.rule_id ?? item.fingerprint?.slice(0, 12) ?? item.asset_id ?? 'scope'}
                      </p>
                      <p className="truncate text-[10px] text-slate-500">{item.reason}</p>
                      <p className="text-[10px] text-slate-600">expires {new Date(item.expires_at).toLocaleString()}</p>
                    </div>
                    {can('policy:write') && (
                      <button
                        className="btn px-2 py-0.5 text-[10px]"
                        onClick={async () => {
                          await api.revokeSuppression(item.id)
                          notify('success', 'Suppression revoked')
                          suppressions.refresh()
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4">
                <EmptyState title="No active suppressions" description="Nothing is being suppressed right now." icon="✓" />
              </div>
            )}
          </Panel>
        </div>
      </div>

      <Panel title="How approval is decided" subtitle="Fail-safe order of evaluation">
        <ol className="list-decimal space-y-1.5 pl-5 text-[11px] leading-relaxed text-slate-400">
          <li>Account suspension always requires human approval.</li>
          <li>If the global containment policy requires approval, no action executes automatically.</li>
          <li>Business-critical assets require approval unless explicitly allowed in policy.</li>
          <li>Actions below the configured risk threshold always require approval.</li>
          <li>Allowlisted hosts and services are refused automated action entirely.</li>
          <li>The requester can never approve their own action (four-eyes principle).</li>
        </ol>
      </Panel>

      <Modal
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        title="Edit policy configuration"
        width="max-w-2xl"
        footer={
          <>
            <button className="btn" onClick={() => setEditing(null)}>
              Cancel
            </button>
            <button className="btn btn-primary" onClick={save} disabled={busy}>
              {busy ? 'Saving…' : 'Save configuration'}
            </button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-slate-500">
          Configuration is validated as JSON. Changes increment the policy version and are written to the audit trail.
          Loosening containment thresholds takes effect immediately - review with your security lead.
        </p>
        <textarea
          className="input min-h-[280px] font-mono text-[11px] leading-relaxed"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          spellCheck={false}
          aria-label="Policy configuration JSON"
        />
        {draftError && <p className="text-[11px] text-threat-high">{draftError}</p>}
      </Modal>
    </div>
  )
}
