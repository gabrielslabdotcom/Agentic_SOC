import type { AnalystDisposition, Case, CaseNote } from '../api/types'

export const ANALYST_OUTCOMES: Array<{
  id: AnalystDisposition
  label: string
  skip: boolean
  danger?: boolean
  text: string
}> = [
  {
    id: 'false_positive',
    label: 'False Positive',
    skip: true,
    text: 'The detector was wrong for this alert (wrong rule, self-ingest, CIS scored as attack, disk-full treated as intrusion). No incident. Skips repeats.',
  },
  {
    id: 'benign',
    label: 'Benign',
    skip: true,
    text: 'The event is real and the rule fired correctly, but activity is authorized or expected (lab nmap, known AD lab replay, admin typo). Skips repeats.',
  },
  {
    id: 'informational',
    label: 'Informational',
    skip: true,
    text: 'Awareness only; no investigation. Matches auto-close of SCA / routine agent events. Skips repeats.',
  },
  {
    id: 'duplicate',
    label: 'Duplicate',
    skip: true,
    text: 'Same incident already triaged on another case. Distinct from false positive so metrics stay honest. Skips repeats.',
  },
  {
    id: 'confirmed_compromise',
    label: 'Confirmed Compromise',
    skip: false,
    danger: true,
    text: 'Malicious or lab-as-adversary activity treated as a true incident. Does not skip repeats. Does not execute containment.',
  },
]

export function priorityFromSeverity(severity?: string | null): string {
  const s = (severity || '').toLowerCase()
  if (s === 'critical') return 'Critical'
  if (s === 'high') return 'High'
  if (s === 'medium') return 'Medium'
  if (s === 'low') return 'Low'
  return 'Info'
}

export function statusLabel(status?: string | null): string {
  const s = (status || 'open').toLowerCase()
  if (s === 'open' || s === 'pending') return 'Open'
  if (s === 'auto_closed') return 'Auto-closed'
  return 'Closed'
}

export function isOpenStatus(status?: string | null): boolean {
  const s = (status || 'open').toLowerCase()
  return s === 'open' || s === 'pending'
}

export function dispositionLabel(d?: string | null): string {
  if (!d) return ''
  return d.replace(/_/g, ' ')
}

export function noteField(text: string, key: string): string {
  const prefix = `${key}=`
  for (const line of String(text || '').split('\n')) {
    if (line.startsWith(prefix)) return line.slice(prefix.length)
  }
  return ''
}

export function isInvestigationNote(n: CaseNote): boolean {
  const a = (n.author || '').toLowerCase()
  const t = n.note || ''
  return (
    a === 'cursor_cloud_agent' ||
    a === 'incident_investigator' ||
    t.startsWith('[cursor_investigation]') ||
    t.startsWith('[incident_meaning]')
  )
}

export function isContainmentNote(n: CaseNote): boolean {
  const t = n.note || ''
  return t.startsWith('[containment_plan]') || t.startsWith('[containment_execute]')
}

export function isIsolationNote(n: CaseNote): boolean {
  const t = n.note || ''
  return t.startsWith('[isolation_plan]') || t.startsWith('[isolation_execute]')
}

export function isolationStatusLine(state?: Case['isolation_state']): string {
  if (!state || !state.action) return 'No isolation sent from this app.'
  const when = state.updated_at ? ` ${state.updated_at}` : ''
  if (state.action === 'isolate') return `Last sent: isolated${when}`
  if (state.action === 'deisolate') return `Last sent: deisolated${when}`
  return 'No isolation sent from this app.'
}

export function timelineLabel(n: CaseNote): string {
  const t = (n.note || '').trim()
  const a = (n.author || '').toLowerCase()
  const m = t.match(/^\[([^\]]+)\]/)
  if (m) return m[1].replace(/_/g, ' ')
  if (a === 'autonomy_loop') return 'autonomy event'
  if (a === 'agent') return 'agent note'
  const first = (t.split('\n')[0] || 'note').trim()
  return first.length > 80 ? `${first.slice(0, 77)}…` : first || 'note'
}

export function priorityTone(severity?: string | null): string {
  const s = (severity || '').toLowerCase()
  if (s === 'critical' || s === 'high') return 'text-danger border-danger/50 bg-danger/10'
  if (s === 'medium') return 'text-warn border-warn/50 bg-warn/10'
  return 'text-muted border-border bg-elevated'
}

export function statusTone(status?: string | null): string {
  if (isOpenStatus(status)) return 'text-info border-info/50 bg-info/10'
  if ((status || '').toLowerCase() === 'confirmed_compromise' || (status || '').toLowerCase() === 'approved') {
    return 'text-danger border-danger/50 bg-danger/10'
  }
  if ((status || '').toLowerCase() === 'benign') return 'text-ok border-ok/50 bg-ok/10'
  return 'text-muted border-border bg-elevated'
}

export function actorFromCase(c: Case): { sourceIp: string; user: string; agent: string } {
  const actors = c.brief?.actors || {}
  return {
    sourceIp: actors.source_ip || c.source_ip || '',
    user: actors.user || c.actor_user || '',
    agent: actors.agent || c.agent_name || '',
  }
}

export function formatWhen(iso?: string | null): string {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return iso
    return d.toLocaleString()
  } catch {
    return iso
  }
}

export function dayKey(iso?: string | null): string {
  if (!iso) return ''
  return String(iso).slice(0, 10)
}
