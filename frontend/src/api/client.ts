import type {
  AnalystDisposition,
  Case,
  ConnectorCard,
  FindRelated,
  QueueMetrics,
  SearchResponse,
  SetupStatus,
  Situation,
  Suppression,
  SuppressionSuggestion,
  UiConfig,
} from './types'

const TOKEN_KEY = 'agentic-soc-setup-token'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function api<T = unknown>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(path, opts)
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  if (!res.ok) {
    const detail =
      body && typeof body === 'object'
        ? ((body as { detail?: unknown; error?: unknown }).detail ??
          (body as { error?: unknown }).error)
        : null
    const msg =
      typeof detail === 'string'
        ? detail
        : detail
          ? JSON.stringify(detail)
          : res.statusText
    throw new ApiError(msg || `HTTP ${res.status}`, res.status)
  }
  return body as T
}

export function getSetupToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) || ''
}

export function setSetupToken(value: string): void {
  const token = value.trim()
  if (token) sessionStorage.setItem(TOKEN_KEY, token)
  else sessionStorage.removeItem(TOKEN_KEY)
}

function tokenHeaders(): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'X-Setup-Token': getSetupToken(),
  }
}

export function getUiConfig() {
  return api<UiConfig>('/tools/ui_config')
}

export function getSetup() {
  return api<SetupStatus>('/tools/setup')
}

export function listCases(params?: { status?: string; limit?: number }) {
  const q = new URLSearchParams()
  if (params?.status) q.set('status', params.status)
  q.set('limit', String(params?.limit ?? 100))
  return api<{ cases: Case[]; count?: number }>(`/tools/list_cases?${q}`)
}

export function getCase(caseId: number) {
  return api<Case>(`/tools/get_case/${caseId}`)
}

export function getQueueMetrics() {
  return api<QueueMetrics>('/tools/queue_metrics')
}

export function getSituation(limit = 12) {
  return api<Situation>(`/tools/situation?limit=${limit}`)
}

export function getAlert(alertId: string) {
  return api<Record<string, unknown>>(`/tools/get_alert/${encodeURIComponent(alertId)}`)
}

export function listAlerts(params?: {
  limit?: number
  min_level?: number
  agent_name?: string
  query_string?: string
}) {
  const q = new URLSearchParams()
  q.set('limit', String(params?.limit ?? 50))
  if (params?.min_level != null) q.set('min_level', String(params.min_level))
  if (params?.agent_name) q.set('agent_name', params.agent_name)
  if (params?.query_string) q.set('query_string', params.query_string)
  return api<{ alerts?: unknown[]; hits?: unknown[]; data?: unknown[] } | unknown[]>(
    `/tools/list_alerts?${q}`,
  )
}

export function listAgents(limit = 100) {
  return api<{ agents?: unknown[]; data?: unknown[]; affected_items?: unknown[] } | unknown[]>(
    `/tools/list_agents?limit=${limit}`,
  )
}

export function findRelated(caseId: number) {
  return api<FindRelated>(`/tools/find_related?case_id=${caseId}`)
}

export function enrichIoc(ioc: string) {
  return api<Record<string, unknown>>(`/tools/enrich_ioc?ioc=${encodeURIComponent(ioc)}`)
}

export function approveCase(
  caseId: number,
  body: { disposition: AnalystDisposition; note?: string; author?: string },
) {
  return api(`/tools/approve_case/${caseId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ author: 'dashboard', ...body }),
  })
}

export function approveCases(body: {
  case_ids: number[]
  disposition: AnalystDisposition
  note?: string
  author?: string
}) {
  return api<{ count?: number; skipped?: unknown[]; errors?: unknown[] }>(
    '/tools/approve_cases',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author: 'dashboard', ...body }),
    },
  )
}

export function listSuppressions(limit = 50) {
  return api<{ suppressions: Suppression[] }>(`/tools/list_suppressions?limit=${limit}`)
}

export function addSuppression(body: {
  rule_id: string
  source_ip?: string | null
  disposition?: string
  note?: string
  created_by?: string
}) {
  return api('/tools/add_suppression', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ created_by: 'dashboard', ...body }),
  })
}

export function disableSuppression(id: number) {
  return api(`/tools/disable_suppression/${id}`, { method: 'POST' })
}

export function suppressionSuggestions(minCount = 2, limit = 8) {
  return api<{ suggestions: SuppressionSuggestion[] }>(
    `/tools/suppression_suggestions?min_count=${minCount}&limit=${limit}`,
  )
}

export function containmentPlan(caseId: number, record = true) {
  return api<{ allowed?: boolean; reason?: string }>(
    `/tools/containment_plan?case_id=${encodeURIComponent(String(caseId))}&record=${record}`,
  )
}

export function executeContainment(body: {
  case_id: number
  confirm: boolean
  source_ip?: string | null
  author?: string
}) {
  return api<{ executed?: boolean; reason?: string; error?: string; source_ip?: string }>(
    '/tools/execute_containment',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author: 'dashboard', ...body }),
    },
  )
}

export function isolationPlan(caseId: number, record = true) {
  return api<{ allowed?: boolean; reason?: string }>(
    `/tools/isolation_plan?case_id=${encodeURIComponent(String(caseId))}&record=${record}`,
  )
}

export function executeIsolation(body: {
  case_id: number
  confirm: boolean
  action: 'isolate' | 'deisolate'
  agent_name?: string | null
  author?: string
}) {
  return api<{ executed?: boolean; reason?: string; error?: string; agent_name?: string }>(
    '/tools/execute_isolation',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author: 'dashboard', ...body }),
    },
  )
}

export function search(question: string) {
  return api<SearchResponse>('/tools/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  })
}

export function listConnectors() {
  return api<{ connectors: ConnectorCard[] }>('/tools/connectors')
}

export function saveConnector(
  id: string,
  body: { enabled: boolean; config: Record<string, unknown> },
) {
  return api(`/tools/connectors/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: tokenHeaders(),
    body: JSON.stringify(body),
  })
}

export function testConnector(
  id: string,
  body: { enabled: boolean; config: Record<string, unknown> },
) {
  return api<{ ok?: boolean; message?: string; error?: string }>(
    `/tools/connectors/${encodeURIComponent(id)}/test`,
    {
      method: 'POST',
      headers: tokenHeaders(),
      body: JSON.stringify(body),
    },
  )
}

/** Normalize list_alerts / list_agents response shapes from Wazuh wrappers. */
export function unwrapList<T>(data: unknown, keys: string[]): T[] {
  if (Array.isArray(data)) return data as T[]
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    for (const key of keys) {
      const val = obj[key]
      if (Array.isArray(val)) return val as T[]
      if (val && typeof val === 'object') {
        const nested = val as Record<string, unknown>
        if (Array.isArray(nested.affected_items)) return nested.affected_items as T[]
        if (Array.isArray(nested.alerts)) return nested.alerts as T[]
        if (Array.isArray(nested.agents)) return nested.agents as T[]
      }
    }
  }
  return []
}
