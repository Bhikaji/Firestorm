import { useState } from 'react'
import api, { ApiError } from '../services/api'
import { useAuth } from '../services/auth'
import { useNotify } from '../hooks/useNotify'
import { Modal, Panel, RoleBadge, SectionTitle, StatusBadge } from '../components/ui'

export default function AccountPage() {
  const { user, refreshMe, can } = useAuth()
  const notify = useNotify()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; provisioning_uri: string } | null>(null)
  const [mfaCode, setMfaCode] = useState('')

  const changePassword = async () => {
    setBusy(true)
    try {
      await api.changePassword(current, next)
      notify('success', 'Password changed; all sessions revoked')
      setCurrent('')
      setNext('')
      await refreshMe()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Password change failed')
    } finally {
      setBusy(false)
    }
  }

  const enableMfa = async () => {
    setBusy(true)
    try {
      await api.enableMfa(mfaCode)
      notify('success', 'Multi-factor authentication enabled')
      setMfaSetup(null)
      setMfaCode('')
      await refreshMe()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Could not enable MFA')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <SectionTitle hint="Account security settings. Sessions are short-lived and refresh tokens rotate on every use.">
        My account
      </SectionTitle>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Profile">
          <dl className="space-y-2 text-[11px]">
            <div className="flex items-center justify-between gap-2">
              <dt className="text-slate-500">Name</dt>
              <dd className="text-slate-200">{user?.full_name}</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-slate-500">Email</dt>
              <dd className="font-mono text-slate-300">{user?.email}</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-slate-500">Role</dt>
              <dd>{user && <RoleBadge role={user.role} />}</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-slate-500">MFA</dt>
              <dd>
                <StatusBadge status={user?.mfa_enabled ? 'healthy' : 'unknown'} label={user?.mfa_enabled ? 'enabled' : 'not enabled'} />
              </dd>
            </div>
          </dl>
          {user?.must_change_password && (
            <p className="mt-3 rounded-lg border border-amber-400/30 bg-amber-400/[0.06] p-2 text-[11px] text-amber-200">
              Your account is flagged for a password change. Change it now.
            </p>
          )}
          {!user?.mfa_enabled && (
            <button
              className="btn mt-4 px-2 py-1 text-xs"
              onClick={async () => {
                try {
                  setMfaSetup(await api.setupMfa())
                } catch (err) {
                  notify('error', err instanceof ApiError ? err.message : 'MFA setup failed')
                }
              }}
            >
              Enable multi-factor authentication
            </button>
          )}
        </Panel>

        <Panel title="Change password" subtitle="Minimum 12 characters with mixed case, digit and symbol">
          <div className="space-y-3">
            <div>
              <label className="label" htmlFor="current">Current password</label>
              <input id="current" type="password" className="input" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" />
            </div>
            <div>
              <label className="label" htmlFor="next">New password</label>
              <input id="next" type="password" className="input" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" />
            </div>
            <button className="btn btn-primary px-3 py-1.5 text-xs" disabled={busy || next.length < 12} onClick={changePassword}>
              Update password
            </button>
            <p className="text-[10px] leading-relaxed text-slate-500">
              Changing your password revokes every refresh token for this account, including other devices.
            </p>
          </div>
        </Panel>
      </div>

      <Panel title="Your permissions" subtitle="Granted by role and enforced by the API">
        <div className="flex flex-wrap gap-1.5">
          {[
            'dashboard:view',
            'asset:read',
            'asset:write',
            'event:read',
            'event:ingest',
            'alert:read',
            'alert:triage',
            'incident:read',
            'incident:write',
            'evidence:collect',
            'action:request',
            'action:approve',
            'action:execute',
            'policy:read',
            'policy:write',
            'report:read',
            'audit:read',
            'user:admin',
            'integration:read',
            'integration:test',
          ].map((permission) => (
            <span
              key={permission}
              className={`chip normal-case ${
                can(permission)
                  ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300'
                  : 'border-white/10 bg-white/[0.02] text-slate-600'
              }`}
            >
              {permission}
            </span>
          ))}
        </div>
      </Panel>

      <Modal
        open={Boolean(mfaSetup)}
        onClose={() => setMfaSetup(null)}
        title="Enable multi-factor authentication"
        footer={
          <>
            <button className="btn" onClick={() => setMfaSetup(null)}>
              Cancel
            </button>
            <button className="btn btn-primary" disabled={busy || mfaCode.length < 6} onClick={enableMfa}>
              Verify and enable
            </button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-slate-400">
          Add this secret to your authenticator app, then enter the current six-digit code. TOTP secrets are stored
          encrypted at rest at the database level; protect backups accordingly.
        </p>
        <code className="block break-all rounded-lg border border-white/10 bg-graphite-950 p-2 font-mono text-[11px] text-neon-cyan">
          {mfaSetup?.secret}
        </code>
        <p className="break-all text-[10px] text-slate-600">{mfaSetup?.provisioning_uri}</p>
        <div>
          <label className="label" htmlFor="mfa-code">One-time code</label>
          <input
            id="mfa-code"
            className="input font-mono tracking-[0.4em]"
            inputMode="numeric"
            maxLength={8}
            value={mfaCode}
            onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, ''))}
          />
        </div>
      </Modal>
    </div>
  )
}
