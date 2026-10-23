export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type Permission =
  | 'dashboard:view'
  | 'asset:read'
  | 'asset:write'
  | 'event:read'
  | 'event:ingest'
  | 'alert:read'
  | 'alert:triage'
  | 'incident:read'
  | 'incident:write'
  | 'evidence:collect'
  | 'action:request'
  | 'action:approve'
  | 'action:execute'
  | 'policy:read'
  | 'policy:write'
  | 'report:read'
  | 'audit:read'
  | 'user:admin'
  | 'integration:read'
  | 'integration:test'

export interface User {
  id: string
  email: string
  full_name: string
  role: 'viewer' | 'analyst' | 'responder' | 'admin'
  is_active: boolean
  mfa_enabled: boolean
  must_change_password: boolean
  last_login_at: string | null
  created_at: string
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  role: string
  must_change_password: boolean
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface Overview {
  generated_at: string
  demo: boolean
  posture: { score: number; label: string; trusted: number; unknown: number; quarantined: number }
  counts: {
    segments: number
    assets: number
    unknown_assets: number
    high_risk_assets: number
    open_alerts: number
    critical_alerts: number
    active_incidents: number
    events_24h: number
    pending_approvals: number
  }
  freshness: { last_event_at: string | null; stale: boolean | null; stale_after_seconds: number }
  window: { events_since: string; trend_since: string }
}

export interface Asset {
  id: string
  hostname: string
  ip_address: string
  mac_address: string | null
  device_type: string
  os_name: string | null
  os_version: string | null
  owner: string | null
  department: string | null
  segment_id: string | null
  criticality: number
  trust_state: 'trusted' | 'unknown' | 'noncompliant' | 'quarantined' | 'compromised'
  enrolled: boolean
  edr_status: string
  patch_level: string
  firewall_enabled: boolean | null
  disk_encrypted: boolean | null
  posture_score: number
  last_posture_at: string | null
  last_seen_at: string | null
  quarantine_reason: string | null
  quarantined_at: string | null
  tags: Record<string, unknown>
  updated_at: string
}

export interface Segment {
  id: string
  name: string
  cidr: string
  vlan_id: number | null
  sensitivity: string
  description: string | null
  monitored: boolean
}

export interface SecurityEvent {
  id: string
  ts: string
  received_at?: string
  source: string
  sensor?: string | null
  event_type: string
  severity: Severity
  src_ip: string | null
  dst_ip: string | null
  src_port?: number | null
  dst_port: number | null
  protocol?: string | null
  bytes_in?: number
  bytes_out?: number
  packets?: number
  duration_ms?: number | null
  dns_query?: string | null
  http_host?: string | null
  username?: string | null
  hostname?: string | null
  file_hash?: string | null
  signature?: string | null
  action?: string | null
  risk_score: number
  asset_id?: string | null
  alert_id: string | null
  raw?: Record<string, unknown>
  processed?: boolean
  fingerprint?: string
}

export interface RiskSignal {
  key: string
  label: string
  weight: number
  detail: string
  source: string
}

export interface Alert {
  id: string
  code: string
  title: string
  description: string
  severity: Severity
  confidence: number
  risk_score: number
  status: 'open' | 'acknowledged' | 'investigating' | 'suppressed' | 'closed'
  rule_id: string
  rule_version: string
  detection_source: string
  first_seen: string
  last_seen: string
  occurrence_count: number
  asset_id: string | null
  incident_id: string | null
  src_ip: string | null
  dst_ip: string | null
  dst_port: number | null
  dns_query: string | null
  signals: RiskSignal[]
  ttps: string[]
  recommended_actions: string[]
  evidence_refs: string[]
  assignee_id: string | null
  acknowledged_at: string | null
  closed_at: string | null
  suppressed_until: string | null
  false_positive: boolean
  analyst_note: string | null
  created_at: string
  updated_at: string
}

export interface AlertDetail {
  alert: Alert
  events: SecurityEvent[]
  explanation: {
    rule_id: string
    rule_version: string
    detection_source: string
    signals: RiskSignal[]
    confidence: number
    risk_score: number
    caveat: string
  }
}

export interface TimelineEntry {
  id: string
  incident_id: string
  ts: string
  kind: string
  actor: string
  message: string
  payload: Record<string, unknown>
}

export interface Evidence {
  id: string
  incident_id: string | null
  alert_id: string | null
  kind: string
  label: string
  sha256: string
  size_bytes: number
  collected_by: string
  collected_at: string
  source: string
  custody: Array<Record<string, unknown>>
  metadata_json: Record<string, unknown>
  sealed: boolean
}

export interface ResponseAction {
  id: string
  incident_id: string | null
  alert_id: string | null
  action_type: string
  target: string
  asset_id: string | null
  status: 'pending_approval' | 'approved' | 'executing' | 'succeeded' | 'failed' | 'rejected' | 'reverted'
  reason: string
  requested_by: string
  approved_by: string | null
  approved_at: string | null
  executed_at: string | null
  reverted_at: string | null
  integration: string | null
  mode: string
  result: string | null
  confidence: number
  reversible: boolean
  created_at: string
}

export interface Incident {
  id: string
  reference: string
  title: string
  summary: string
  severity: Severity
  status: 'new' | 'triage' | 'containment' | 'contained' | 'eradication' | 'recovery' | 'closed'
  risk_score: number
  owner_id: string | null
  detected_at: string
  contained_at: string | null
  closed_at: string | null
  observed_facts: Array<Record<string, string>>
  hypotheses: Array<Record<string, unknown>>
  affected_asset_ids: string[]
  affected_accounts: string[]
  mitre_tactics: string[]
  post_incident_review: string | null
  summary_report: string | null
  created_at: string
  updated_at: string
}

export interface IncidentDetail extends Incident {
  timeline: TimelineEntry[]
  evidence: Evidence[]
  actions: ResponseAction[]
  alerts: Array<{
    id: string
    title: string
    severity: Severity
    risk_score: number
    status: string
    rule_id: string
    first_seen: string
  }>
}

export interface IntegrationHealth {
  name: string
  kind: string
  layer: string
  mode: string
  enabled: boolean
  status: 'healthy' | 'degraded' | 'unavailable' | 'simulated' | 'not_configured' | 'partial'
  detail: string
  latency_ms: number | null
  checked_at: string
}

export interface ProtectionLayer {
  id: string
  name: string
  description: string
  status: string
  components: IntegrationHealth[]
}

export interface Policy {
  id: string
  key: string
  name: string
  description: string
  category: string
  enabled: boolean
  version: number
  config: Record<string, unknown>
  updated_at: string
}

export interface AdmissionRule {
  id: string
  name: string
  description: string
  priority: number
  enabled: boolean
  condition: Record<string, unknown>
  outcome: 'allow' | 'restrict_remediation' | 'deny' | 'quarantine'
  outcome_reason: string
  min_posture_score: number
}

export interface Topology {
  nodes: Array<{
    id: string
    type: 'segment' | 'asset'
    label: string
    cidr?: string
    ip?: string
    segment_id?: string | null
    device_type?: string
    trust_state?: string
    criticality?: number
    posture_score?: number
    sensitivity?: string
    device_count?: number
  }>
  links: Array<{
    id: string
    source: string
    target: string
    suspicious: boolean
    severity: Severity
    risk_score: number
    label: string
    alert_id?: string
  }>
  external_note: string
  demo: boolean
}

export interface AuditEntry {
  id: string
  ts: string
  actor_email: string
  actor_role: string
  action: string
  object_type: string
  object_id: string | null
  outcome: string
  detail: Record<string, unknown>
  client_ip: string | null
  entry_hash: string
}

export interface Notification {
  id: string
  channel: string
  recipient: string
  subject: string
  body: string
  severity: SevereNotification
  alert_id: string | null
  incident_id: string | null
  status: string
  attempts: number
  last_error: string | null
  delivered_at: string | null
  acknowledged_at: string | null
  created_at: string
}

type SevereNotification = Severity

export interface Report {
  label: string
  generated_at: string
  window: { start: string; end: string }
  events_ingested: number
  alerts: {
    total: number
    by_severity: Record<string, number>
    by_rule: Record<string, number>
    false_positives: number
    false_positive_rate: number
    open: number
  }
  incidents: {
    total: number
    open: number
    closed: number
    mttr_minutes: number | null
    by_severity: Record<string, number>
  }
  response_actions: { total: number; succeeded: number; simulated: number }
  evidence_collected: number
  device_compliance: {
    total_assets: number
    compliant: number
    unknown: number
    quarantined: number
    compliance_percent: number
  }
  sensor_coverage: {
    segments: number
    per_segment: Array<{ segment: string; cidr: string; monitored: boolean; devices: number; enrolled_percent: number }>
    enrolled_percent: number
  }
  administrative_activity: Array<{ action: string; count: number }>
  caveats: string[]
}

export interface SystemInfo {
  app: {
    name: string
    environment: string
    demo_mode: boolean
    demo_data: boolean
    enforcement_mode: string
    version: string
  }
  capabilities: { mfa: boolean; websocket: boolean; email: boolean; redis: boolean; enforcement_live: boolean }
  integrations: IntegrationHealth[]
  roles: Record<string, string[]>
}
