/**
 * API client.
 *
 * - Tokens live in memory + sessionStorage (never localStorage) to limit the
 *   blast radius of XSS; refresh tokens stay in the httpOnly cookie set by the
 *   backend, but the login response also returns one for non-browser clients.
 * - All requests use relative URLs so the Vite proxy (development) or the
 *   reverse proxy (production) terminates TLS.
 */

import type {
  AdmissionRule,
  Alert,
  AlertDetail,
  Asset,
  AuditEntry,
  Evidence,
  Incident,
  IncidentDetail,
  IntegrationHealth,
  Notification,
  Overview,
  Page,
  Policy,
  ProtectionLayer,
  Report,
  ResponseAction,
  Segment,
  SecurityEvent,
  SystemInfo,
  TokenPair,
  Topology,
  User,
} from '../types'

const BASE = '/api/v1'
const ACCESS_KEY = 'firestorm.access'
const REFRESH_KEY = 'firestorm.refresh'

export class ApiError extends Error {
  status: number
  code: string
  details?: Record<string, unknown>
  /** Server-side correlation id (X-Request-ID) — quote it in a support request. */
  requestId?: string

  constructor(
    status: number,
    message: string,
    code = 'error',
    details?: Record<string, unknown>,
    requestId?: string,
  ) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }
}

export const tokenStore = {
  get access() {
    return sessionStorage.getItem(ACCESS_KEY)
  },
  get refresh() {
    return sessionStorage.getItem(REFRESH_KEY)
  },
  set(pair: TokenPair) {
    sessionStorage.setItem(ACCESS_KEY, pair.access_token)
    sessionStorage.setItem(REFRESH_KEY, pair.refresh_token)
  },
  clear() {
    sessionStorage.removeItem(ACCESS_KEY)
    sessionStorage.removeItem(REFRESH_KEY)
  },
}

let refreshing: Promise<boolean> | null = null

async function refreshSession(): Promise<boolean> {
  const refresh = tokenStore.refresh
  if (!refresh) return false
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const response = await fetch(`${BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ refresh_token: refresh }),
        })
        if (!response.ok) return false
        tokenStore.set((await response.json()) as TokenPair)
        return true
      } catch {
        return false
      } finally {
        refreshing = null
      }
    })()
  }
  return refreshing
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  retryOnUnauthorized?: boolean
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, retryOnUnauthorized = true, headers, ...rest } = options
  const access = tokenStore.access

  const response = await fetch(`${BASE}${path}`, {
    ...rest,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(access ? { Authorization: `Bearer ${access}` } : {}),
      ...(headers as Record<string, string> | undefined),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (response.status === 401 && retryOnUnauthorized) {
    const refreshed = await refreshSession()
    if (refreshed) {
      return request<T>(path, { ...options, retryOnUnauthorized: false })
    }
    tokenStore.clear()
    throw new ApiError(401, 'Your session expired. Sign in again.', 'unauthorized')
  }

  if (response.status === 204) return undefined as T

  const text = await response.text()
  const data = text ? safeParse(text) : null

  if (!response.ok) {
    const error = (data as { error?: { message?: string; code?: string; details?: Record<string, unknown> } })?.error
    throw new ApiError(
      response.status,
      error?.message || `Request failed (${response.status})`,
      error?.code || 'error',
      error?.details,
      response.headers.get('x-request-id') ?? undefined,
    )
  }
  return data as T
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return { raw: text }
  }
}

const qs = (params: Record<string, string | number | boolean | undefined | null>) => {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  })
  const query = search.toString()
  return query ? `?${query}` : ''
}

export const api = {
  // -- auth ---------------------------------------------------------
  login: (email: string, password: string, mfa_code?: string) =>
    request<TokenPair>('/auth/login', { method: 'POST', body: { email, password, mfa_code }, retryOnUnauthorized: false }),
  logout: () => request<{ message: string }>('/auth/logout', { method: 'POST', retryOnUnauthorized: false }),
  me: () => request<{ user: User; permissions: string[] }>('/auth/me'),
  changePassword: (current_password: string, new_password: string) =>
    request<{ message: string }>('/auth/password', { method: 'POST', body: { current_password, new_password } }),
  setupMfa: () => request<{ secret: string; provisioning_uri: string }>('/auth/mfa/setup', { method: 'POST' }),
  enableMfa: (code: string) => request<{ message: string }>('/auth/mfa/enable', { method: 'POST', body: { code } }),
  disableMfa: (password: string) =>
    request<{ message: string }>('/auth/mfa/disable', { method: 'POST', body: { password } }),

  // -- system -------------------------------------------------------
  systemInfo: () => request<SystemInfo>('/system/info'),
  readiness: () => request<{ status: string; checks: Record<string, { status: string; detail?: string }> }>('/ready'),

  // -- dashboard ----------------------------------------------------
  overview: () => request<Overview>('/dashboard/overview'),
  topology: () => request<Topology>('/dashboard/topology'),
  feed: (limit = 40) => request<SecurityEvent[]>(`/dashboard/feed?limit=${limit}`),
  severity: (hours = 24) => request<Array<{ severity: string; count: number }>>(`/dashboard/severity?hours=${hours}`),
  trend: (days = 7) => request<Array<Record<string, string | number>>>(`/dashboard/trend?days=${days}`),
  trust: () => request<Array<{ state: string; count: number }>>('/dashboard/trust'),
  riskyAssets: (limit = 8) =>
    request<
      Array<{
        asset_id: string
        hostname: string
        ip_address: string
        criticality: number
        trust_state: string
        risk_score: number
        open_alerts: number
      }>
    >(`/dashboard/risky-assets?limit=${limit}`),
  layers: () => request<ProtectionLayer[]>('/dashboard/layers'),
  attention: () =>
    request<
      Array<{
        id: string
        title: string
        severity: string
        risk_score: number
        status: string
        first_seen: string
        age_minutes: number
        assignee: string | null
      }>
    >('/dashboard/attention'),

  // -- assets -------------------------------------------------------
  assets: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<Asset>>(`/assets${qs(params)}`),
  asset: (id: string) => request<Asset>(`/assets/${id}`),
  assetContext: (id: string) =>
    request<{
      asset: Asset
      alerts: Array<{ id: string; title: string; severity: string; risk_score: number; status: string; last_seen: string }>
      incidents: Array<{ id: string; reference: string; title: string; status: string }>
      admission: {
        outcome: string
        reason: string
        matched_rule: string | null
        posture_score: number
        trust_state: string
        risk_score: number
        outcome_label: string
      }
    }>(`/assets/${id}/context`),
  segments: () => request<Segment[]>('/segments'),
  evaluateAdmission: (id: string) =>
    request<{ outcome: string; reason: string; matched_rule: string | null; posture_score: number; risk_score: number; outcome_label: string }>(
      `/assets/${id}/admission`,
      { method: 'POST' },
    ),
  quarantineAsset: (id: string, reason: string) =>
    request<{ message: string; detail?: string }>(`/assets/${id}/quarantine`, { method: 'POST', body: { reason } }),
  setTrust: (id: string, trust_state: string, reason: string) =>
    request<Asset>(`/assets/${id}/trust`, { method: 'POST', body: { trust_state, reason } }),

  // -- telemetry ----------------------------------------------------
  events: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<SecurityEvent>>(`/telemetry/events${qs(params)}`),
  event: (id: string) => request<SecurityEvent>(`/telemetry/events/${id}`),
  eventSources: () => request<Array<{ source: string; events: number; last_seen: string | null }>>('/telemetry/sources'),

  // -- alerts -------------------------------------------------------
  alerts: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<Alert>>(`/alerts${qs(params)}`),
  alert: (id: string) => request<AlertDetail>(`/alerts/${id}`),
  triageAlert: (
    id: string,
    payload: { status?: string; note?: string; false_positive?: boolean; suppress_minutes?: number; create_incident?: boolean },
  ) => request<Alert>(`/alerts/${id}`, { method: 'PATCH', body: payload }),
  suppressions: () =>
    request<
      Array<{
        id: string
        fingerprint: string | null
        rule_id: string | null
        asset_id: string | null
        reason: string
        created_by: string
        expires_at: string
        active: boolean
        created_at: string
      }>
    >('/alerts/suppressions/list'),
  revokeSuppression: (id: string) => request<void>(`/alerts/suppressions/${id}`, { method: 'DELETE' }),
  ruleCatalog: () =>
    request<Array<{ rule_id: string; code: string; version: string; description: string }>>('/alerts/rules/catalog'),

  // -- incidents ----------------------------------------------------
  incidents: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<Incident>>(`/incidents${qs(params)}`),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  updateIncident: (id: string, payload: Record<string, unknown>) =>
    request<Incident>(`/incidents/${id}`, { method: 'PATCH', body: payload }),
  addIncidentNote: (id: string, message: string) =>
    request<{ id: string }>(`/incidents/${id}/notes`, { method: 'POST', body: { message } }),
  correlations: (id: string) =>
    request<Array<{ alert_id: string; title: string; risk_score: number; first_seen: string; reason: string }>>(
      `/incidents/${id}/correlations`,
    ),
  collectEvidence: (id: string, payload: Record<string, unknown>) =>
    request<Evidence>(`/incidents/${id}/evidence`, { method: 'POST', body: payload }),
  verifyEvidence: (id: string) =>
    request<{ id: string; verified: boolean | null; detail: string; sha256: string; actual_sha256?: string }>(
      `/evidence/${id}/verify`,
    ),
  actions: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<ResponseAction>>(`/actions${qs(params)}`),
  requestAction: (payload: Record<string, unknown>) =>
    request<ResponseAction>('/actions', { method: 'POST', body: payload }),
  approveAction: (id: string, note?: string) =>
    request<ResponseAction>(`/actions/${id}/approve`, { method: 'POST', body: { note } }),
  rejectAction: (id: string, note?: string) =>
    request<ResponseAction>(`/actions/${id}/reject`, { method: 'POST', body: { note } }),
  executeAction: (id: string) => request<ResponseAction>(`/actions/${id}/execute`, { method: 'POST' }),
  revertAction: (id: string, note?: string) =>
    request<ResponseAction>(`/actions/${id}/revert`, { method: 'POST', body: { note } }),
  emergencyRelease: (note: string) =>
    request<{ message: string; detail?: string }>('/actions/emergency-release', { method: 'POST', body: { note } }),
  enforcement: () =>
    request<
      Array<{
        id: string
        kind: string
        target: string
        integration: string
        mode: string
        state: string
        detail: string
        created_at: string
        action_id: string | null
      }>
    >('/enforcement'),

  // -- policies -----------------------------------------------------
  policies: () => request<Policy[]>('/policies'),
  updatePolicy: (key: string, payload: Record<string, unknown>) =>
    request<Policy>(`/policies/${key}`, { method: 'PATCH', body: payload }),
  admissionRules: () => request<AdmissionRule[]>('/admission-rules'),
  createAdmissionRule: (payload: Record<string, unknown>) =>
    request<AdmissionRule>('/admission-rules', { method: 'POST', body: payload }),
  updateAdmissionRule: (id: string, payload: Record<string, unknown>) =>
    request<AdmissionRule>(`/admission-rules/${id}`, { method: 'PATCH', body: payload }),
  deleteAdmissionRule: (id: string) => request<{ message: string }>(`/admission-rules/${id}`, { method: 'DELETE' }),
  audit: (params: Record<string, string | number | undefined> = {}) =>
    request<Page<AuditEntry>>(`/audit${qs(params)}`),
  verifyAudit: () => request<{ valid: boolean; checked: number; broken_at: string | null; message: string }>('/audit/verify'),

  // -- integrations -------------------------------------------------
  integrations: () => request<IntegrationHealth[]>('/integrations'),
  testIntegrations: () => request<IntegrationHealth[]>('/integrations/test', { method: 'POST' }),
  notificationStatus: () => request<Record<string, unknown>>('/integrations/notifications'),

  // -- reports ------------------------------------------------------
  dailyReport: (day?: string) => request<Report>(`/reports/daily${qs({ day })}`),
  monthlyReport: (year?: number, month?: number) => request<Report>(`/reports/monthly${qs({ year, month })}`),
  incidentStats: (days = 30) => request<Record<string, unknown>>(`/reports/incidents?days=${days}`),

  // -- users / notifications ---------------------------------------
  users: () => request<Page<User>>('/users'),
  createUser: (payload: Record<string, unknown>) => request<User>('/users', { method: 'POST', body: payload }),
  updateUser: (id: string, payload: Record<string, unknown>) =>
    request<User>(`/users/${id}`, { method: 'PATCH', body: payload }),
  notifications: () => request<Page<Notification>>('/notifications?page_size=50'),
  acknowledgeNotification: (id: string) =>
    request<Notification>(`/notifications/${id}/acknowledge`, { method: 'POST' }),
}

export default api
