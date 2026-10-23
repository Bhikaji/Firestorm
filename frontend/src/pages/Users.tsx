import { useState } from 'react'
import api, { ApiError } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useNotify } from '../hooks/useNotify'
import {
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Panel,
  RoleBadge,
  SectionTitle,
  StatusBadge,
  formatTime,
} from '../components/ui'

export default function UsersPage() {
  const notify = useNotify()
  const users = useAsync(() => api.users(), [])
  const [createOpen, setCreateOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [role, setRole] = useState('analyst')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.createUser({ email, full_name: fullName, role, password })
      notify('success', 'User created; password change required at first sign-in')
      setCreateOpen(false)
      setEmail('')
      setFullName('')
      setPassword('')
      users.refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create user')
    } finally {
      setBusy(false)
    }
  }

  const setActive = async (id: string, isActive: boolean) => {
    try {
      await api.updateUser(id, { is_active: isActive })
      notify('success', `Account ${isActive ? 'activated' : 'deactivated'}`)
      users.refresh()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : 'Update failed')
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle hint="Four roles with separated capabilities: viewing, investigating, approving and executing.">
          Users & access
        </SectionTitle>
        <button className="btn btn-primary px-3 py-1.5 text-xs" onClick={() => setCreateOpen(true)}>
          Add user
        </button>
      </div>

      {users.error && <ErrorState message={users.error} onRetry={users.refresh} />}

      <div className="panel overflow-hidden">
        {users.loading ? (
          <div className="p-4">
            <LoadingBlock rows={5} />
          </div>
        ) : users.data && users.data.items.length > 0 ? (
          <table className="w-full text-xs">
            <thead className="table-head">
              <tr>
                <th className="px-4 py-2">User</th>
                <th className="px-2 py-2">Role</th>
                <th className="px-2 py-2">MFA</th>
                <th className="px-2 py-2">Status</th>
                <th className="px-2 py-2 text-right">Last login</th>
                <th className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.data.items.map((user) => (
                <tr key={user.id} className="row-hover border-t border-white/[0.04]">
                  <td className="px-4 py-2">
                    <p className="text-slate-200">{user.full_name}</p>
                    <p className="font-mono text-[10px] text-slate-500">{user.email}</p>
                  </td>
                  <td className="px-2 py-2">
                    <RoleBadge role={user.role} />
                  </td>
                  <td className="px-2 py-2 text-[11px] text-slate-400">{user.mfa_enabled ? 'enabled' : '—'}</td>
                  <td className="px-2 py-2">
                    <StatusBadge status={user.is_active ? 'healthy' : 'unavailable'} label={user.is_active ? 'active' : 'disabled'} />
                  </td>
                  <td className="px-2 py-2 text-right text-[11px] text-slate-500">
                    {user.last_login_at ? formatTime(user.last_login_at) : 'never'}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button className="btn px-2 py-0.5 text-[10px]" onClick={() => setActive(user.id, !user.is_active)}>
                      {user.is_active ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-6">
            <EmptyState title="No users" description="Create the first administrator account via scripts/bootstrap.py." />
          </div>
        )}
      </div>

      <Panel title="Role capabilities" subtitle="Enforced server-side on every request">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {['viewer', 'analyst', 'responder', 'admin'].map((roleName) => (
            <div key={roleName} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <RoleBadge role={roleName} />
              <ul className="mt-2 space-y-1 text-[10px] leading-relaxed text-slate-500">
                {roleName === 'viewer' && <li>Read dashboards, alerts, incidents and reports</li>}
                {roleName === 'analyst' && <li>Triage alerts, collect evidence, request containment</li>}
                {roleName === 'responder' && <li>Execute and revert approved containment; read audit</li>}
                {roleName === 'admin' && <li>Approve actions, manage users, policies and integrations</li>}
              </ul>
            </div>
          ))}
        </div>
      </Panel>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Add user"
        footer={
          <>
            <button className="btn" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
            <button className="btn btn-primary" onClick={create} disabled={busy || password.length < 12}>
              {busy ? 'Creating…' : 'Create user'}
            </button>
          </>
        }
      >
        <div>
          <label className="label" htmlFor="user-email">Email</label>
          <input id="user-email" className="input" type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="user-name">Full name</label>
          <input id="user-name" className="input" value={fullName} onChange={(event) => setFullName(event.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="user-role">Role</label>
          <select id="user-role" className="input" value={role} onChange={(event) => setRole(event.target.value)}>
            {['viewer', 'analyst', 'responder', 'admin'].map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="user-password">Initial password (min 12 chars, mixed case, digit, symbol)</label>
          <input
            id="user-password"
            className="input font-mono"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>
        {error && <p className="text-[11px] text-threat-high">{error}</p>}
        <p className="text-[11px] leading-relaxed text-slate-500">
          The user must change this password at first sign-in. Share it over an approved channel, never in chat or email
          bodies.
        </p>
      </Modal>
    </div>
  )
}
