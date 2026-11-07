export type AnalystDisposition =
  | 'false_positive'
  | 'benign'
  | 'informational'
  | 'duplicate'
  | 'confirmed_compromise'

export interface CaseBrief {
  headline?: string
  actors?: {
    source_ip?: string | null
    user?: string | null
    agent?: string | null
  }
  rule?: {
    id?: string | null
    level?: number | null
    description?: string | null
  }
  evidence?: string
  why?: string[]
  vt?: string
  do_next?: string[]
  wazuh_url?: string | null
  disposition?: string | null
}

export interface CaseNote {
  id: number
  author: string
  note: string
  created_at: string
}

export interface IsolationState {
  action?: string | null
  updated_at?: string | null
  agent_name?: string | null
  command?: string | null
}

export interface Case {
  id: number
  title: string
  status: string
  severity: string
  alert_id?: string | null
  agent_name?: string | null
  summary?: string | null
  disposition?: string | null
  analyst_disposition?: string | null
  recommended_action?: string | null
  source_ip?: string | null
  actor_user?: string | null
  rule_id?: string | null
  created_at: string
  updated_at: string
  notes?: CaseNote[]
  brief?: CaseBrief
  alert_count?: number
  isolation_state?: IsolationState | null
}

export interface QueueMetrics {
  open?: number
  auto_closed?: number
  human_closed?: number
  active_suppressions?: number
  feedback_total?: number
  human_outcomes?: Record<string, number>
}

export interface SituationGroup {
  source_ip?: string | null
  user?: string | null
  alert_count?: number
  latest_at?: string
  top_rule?: string | null
  disposition?: string | null
  severity?: string | null
  case_ids?: number[]
}

export interface Situation {
  groups: SituationGroup[]
  group_count: number
  ungrouped_open: number
  open_cases: number
}

export interface Suppression {
  id: number
  rule_id: string
  source_ip?: string | null
  any_source?: boolean
  disposition?: string
  note?: string | null
  expires_at?: string | null
}

export interface SuppressionSuggestion {
  rule_id: string
  source_ip?: string | null
  any_source?: boolean
  count: number
  suggested_disposition?: string
}

export interface RelatedEntity {
  entity_type: string
  value: string
}

export interface RelatedCase {
  id: number
  title?: string
  status?: string
  severity?: string
  matched_entities?: RelatedEntity[]
}

export interface FindRelated {
  related_cases: RelatedCase[]
  entities: RelatedEntity[]
  related_alert_ids?: string[]
}

export interface UiConfig {
  app_name: string
  instance: string
  hostname?: string
  wazuh_dashboard_url?: string
  cases_db_path?: string
  lab_mode?: boolean
  containment_enabled: boolean
  host_isolation_enabled: boolean
  autonomy_min_level?: string
  include_auth?: string
  auto_close_noise?: string
  banner?: string
  note?: string
  connectors?: Record<string, boolean | string>
}

export interface ConnectorField {
  key: string
  label: string
  kind?: string
  secret?: boolean
  value?: string | boolean | null
  configured?: boolean
  hint?: string
}

export interface ConnectorCard {
  id: string
  name: string
  kind: string
  blurb?: string
  enabled: boolean
  configured: boolean
  fields: ConnectorField[]
}

export interface SetupStatus {
  ready: boolean
  [key: string]: unknown
}

export interface AgentRow {
  id?: string | number
  name?: string
  status?: string
  ip?: string
  os?: { name?: string; uname?: string } | string
  [key: string]: unknown
}

export interface AlertRow {
  id?: string
  _id?: string
  rule?: { id?: string | number; level?: number; description?: string }
  agent?: { name?: string; id?: string } | string
  data?: { srcip?: string; srcuser?: string; dstuser?: string }
  timestamp?: string
  full_log?: string
  [key: string]: unknown
}

export interface SearchStep {
  tool: string
  args?: Record<string, unknown>
  hit_count?: number
  total?: number
  error?: string | null
}

export interface SearchResults {
  alerts?: Record<string, unknown>[]
  inventory?: Record<string, unknown>[]
  vulnerabilities?: Record<string, unknown>[]
  cases?: Record<string, unknown>[]
  agents?: Record<string, unknown>[]
  buckets?: { key?: string | number; count?: number }[]
}

export interface SearchResponse {
  ok?: boolean
  mode?: 'llm' | 'keyword' | string
  model?: string | null
  answer?: string
  steps?: SearchStep[]
  results?: SearchResults
  stop_reason?: string
  error?: string
}
