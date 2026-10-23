import { Navigate, Route, Routes } from 'react-router-dom'
import type { ReactNode } from 'react'
import { AppShell } from './layouts/AppShell'
import { LoadingBlock, useToasts } from './components/ui'
import { useAuth } from './services/auth'
import LoginPage from './pages/Login'
import OverviewPage from './pages/Overview'
import TopologyPage from './pages/Topology'
import EventsPage from './pages/Events'
import AlertsPage from './pages/Alerts'
import IncidentsPage from './pages/Incidents'
import IncidentDetailPage from './pages/IncidentDetail'
import DevicesPage from './pages/Devices'
import LayersPage from './pages/Layers'
import PoliciesPage from './pages/Policies'
import ReportsPage from './pages/Reports'
import AuditPage from './pages/Audit'
import UsersPage from './pages/Users'
import AccountPage from './pages/Account'
import NotFoundPage from './pages/NotFound'

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <LoadingBlock label="Checking session" rows={3} />
        </div>
      </div>
    )
  }
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth()
  if (!can(permission)) {
    return (
      <div className="panel p-6">
        <h2 className="text-sm font-semibold text-slate-100">Access denied</h2>
        <p className="mt-2 text-xs text-slate-400">
          Your role does not include the <span className="font-mono text-slate-300">{permission}</span> permission.
          Ask an administrator to adjust your role if this is unexpected.
        </p>
      </div>
    )
  }
  return <>{children}</>
}

export default function App() {
  const toastState = useToasts()

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell toasts={toastState.toasts} push={toastState.push} dismiss={toastState.remove} />
          </RequireAuth>
        }
      >
        <Route
          index
          element={
            <RequirePermission permission="dashboard:view">
              <OverviewPage />
            </RequirePermission>
          }
        />
        <Route
          path="topology"
          element={
            <RequirePermission permission="dashboard:view">
              <TopologyPage />
            </RequirePermission>
          }
        />
        <Route
          path="events"
          element={
            <RequirePermission permission="event:read">
              <EventsPage />
            </RequirePermission>
          }
        />
        <Route
          path="alerts"
          element={
            <RequirePermission permission="alert:read">
              <AlertsPage />
            </RequirePermission>
          }
        />
        <Route
          path="incidents"
          element={
            <RequirePermission permission="incident:read">
              <IncidentsPage />
            </RequirePermission>
          }
        />
        <Route
          path="incidents/:incidentId"
          element={
            <RequirePermission permission="incident:read">
              <IncidentDetailPage />
            </RequirePermission>
          }
        />
        <Route
          path="devices"
          element={
            <RequirePermission permission="asset:read">
              <DevicesPage />
            </RequirePermission>
          }
        />
        <Route
          path="layers"
          element={
            <RequirePermission permission="dashboard:view">
              <LayersPage />
            </RequirePermission>
          }
        />
        <Route
          path="policies"
          element={
            <RequirePermission permission="policy:read">
              <PoliciesPage />
            </RequirePermission>
          }
        />
        <Route
          path="reports"
          element={
            <RequirePermission permission="report:read">
              <ReportsPage />
            </RequirePermission>
          }
        />
        <Route
          path="audit"
          element={
            <RequirePermission permission="audit:read">
              <AuditPage />
            </RequirePermission>
          }
        />
        <Route
          path="users"
          element={
            <RequirePermission permission="user:admin">
              <UsersPage />
            </RequirePermission>
          }
        />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
