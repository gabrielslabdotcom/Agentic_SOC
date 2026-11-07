import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  approveCase,
  containmentPlan,
  enrichIoc,
  executeContainment,
  executeIsolation,
  findRelated,
  getAlert,
  getCase,
  getUiConfig,
  isolationPlan,
  listAlerts,
  unwrapList,
} from '../api/client'
import type { AnalystDisposition, AlertRow, Case, CaseBrief, CaseNote } from '../api/types'
import { DispositionBadge, PriorityBadge, StatusBadge } from '../components/Badge'
import {
  Button,
  Empty,
  Input,
  Panel,
  PanelHead,
  SectionTitle,
  TextArea,
} from '../components/ui'
import {
  ANALYST_OUTCOMES,
  actorFromCase,
  formatWhen,
  isContainmentNote,
  isInvestigationNote,
  isIsolationNote,
  isOpenStatus,
  isolationStatusLine,
  noteField,
  timelineLabel,
} from '../lib/mapping'
import { useToast } from '../lib/toast'

export function InvestigationPage() {
  const { id } = useParams()
  const caseId = Number(id)
  const { toast } = useToast()
  const qc = useQueryClient()
  const [resolveOpen, setResolveOpen] = useState(false)
  const [note, setNote] = useState('')
  const [rawAlertId, setRawAlertId] = useState<string | null>(null)
  const [ioc, setIoc] = useState('')
  const [iocOut, setIocOut] = useState('')
  const [tlFilter, setTlFilter] = useState('all')

  const config = useQuery({ queryKey: ['ui_config'], queryFn: getUiConfig })
  const detail = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId),
    enabled: Number.isFinite(caseId),
  })
  const related = useQuery({
    queryKey: ['related', caseId],
    queryFn: () => findRelated(caseId),
    enabled: Number.isFinite(caseId),
  })

  const c = detail.data
  const actor = c ? actorFromCase(c) : { sourceIp: '', user: '', agent: '' }

  const triggerAlert = useQuery({
    queryKey: ['alert', c?.alert_id],
    queryFn: () => getAlert(String(c!.alert_id)),
    enabled: !!c?.alert_id,
  })

  const actorAlerts = useQuery({
    queryKey: ['actor_alerts', actor.sourceIp, actor.user, actor.agent],
    queryFn: async () => {
      const parts: string[] = []
      if (actor.sourceIp) parts.push(`data.srcip:${actor.sourceIp}`)
      else if (actor.user) parts.push(`data.srcuser:${actor.user}`)
      else if (actor.agent) parts.push(`agent.name:${actor.agent}`)
      if (!parts.length) return [] as AlertRow[]
      const data = await listAlerts({
        limit: 25,
        query_string: parts.join(' OR '),
      })
      return unwrapList<AlertRow>(data, ['alerts', 'hits', 'data'])
    },
    enabled: !!(actor.sourceIp || actor.user || actor.agent),
  })

  const decide = useMutation({
    mutationFn: (disposition: AnalystDisposition) =>
      approveCase(caseId, { disposition, note }),
    onSuccess: async (_r, disposition) => {
      toast(`Recorded ${disposition} (no containment).`, 'ok')
      setResolveOpen(false)
      setNote('')
      await qc.invalidateQueries({ queryKey: ['case', caseId] })
      await qc.invalidateQueries({ queryKey: ['cases'] })
      await qc.invalidateQueries({ queryKey: ['metrics'] })
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  const notes = c?.notes || []
  const invNotes = notes.filter(isInvestigationNote)
  const containmentNotes = notes.filter(isContainmentNote)
  const isolationNotes = notes.filter(isIsolationNote)
  const timeline = useMemo(
    () => buildTimeline(c?.notes || [], c?.created_at, c?.updated_at),
    [c],
  )
  const shownTimeline = timeline.filter((i) => tlFilter === 'all' || i.kind === tlFilter)

  if (!Number.isFinite(caseId)) return <Empty>Invalid investigation id.</Empty>
  if (detail.isLoading) return <Empty>Loading investigation…</Empty>
  if (!c || (c as { error?: string }).error) return <Empty>Investigation not found.</Empty>

  const brief = c.brief || {}
  const canExecute = !!config.data?.containment_enabled
  const canIsolate = !!config.data?.host_isolation_enabled
  const open = isOpenStatus(c.status)
  const entities = (related.data?.entities || []).filter((e) => e.entity_type !== 'host')
  const users = entities.filter((e) => e.entity_type === 'user' || e.entity_type === 'actor')
  const indicators = entities.filter(
    (e) => !['user', 'actor', 'host'].includes(e.entity_type),
  )
  if (actor.user && !users.some((u) => u.value === actor.user)) {
    users.unshift({ entity_type: 'user', value: actor.user })
  }

  return (
    <div className="space-y-4">
      <div className="text-sm text-muted">
        <Link to="/" className="no-underline hover:underline">
          Inbox
        </Link>
        <span className="mx-2 text-border">/</span>
        <span className="text-text">#{c.id}</span>
      </div>

      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-4">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <PriorityBadge severity={c.severity} />
              <StatusBadge status={c.status} />
              <DispositionBadge disposition={c.disposition || c.analyst_disposition} />
              <span className="font-mono text-xs text-muted">
                {c.alert_count ?? (c.alert_id ? 1 : 0)} alert(s)
              </span>
            </div>
            <h2 className="m-0 text-xl font-semibold tracking-tight">
              #{c.id} · {brief.headline || c.title || '(untitled)'}
            </h2>
            <div className="mt-1 text-xs text-muted">
              Created {formatWhen(c.created_at)} · Updated {formatWhen(c.updated_at)}
            </div>
          </div>
          <Button
            variant={open ? 'primary' : 'ghost'}
            disabled={!open}
            onClick={() => setResolveOpen(true)}
          >
            Resolve
          </Button>
        </div>

        <div className="grid gap-0 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="min-w-0 space-y-8 px-5 py-5">
            <StorySection c={c} brief={brief} actor={actor} invNotes={invNotes} />

            <section>
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <SectionTitle>Activity</SectionTitle>
                <div className="flex flex-wrap gap-1">
                  {['all', 'note', 'approval', 'system'].map((f) => (
                    <button
                      key={f}
                      type="button"
                      className={`rounded-full px-2.5 py-1 text-xs capitalize ${
                        tlFilter === f
                          ? 'bg-accent-soft font-medium text-accent'
                          : 'text-muted hover:bg-elevated'
                      }`}
                      onClick={() => setTlFilter(f)}
                    >
                      {f === 'all' ? 'All' : f === 'note' ? 'Notes' : f === 'approval' ? 'Approvals' : 'System'}
                    </button>
                  ))}
                </div>
              </div>
              {shownTimeline.length === 0 ? (
                <p className="text-sm text-muted">No timeline events.</p>
              ) : (
                <ul className="m-0 list-none space-y-4 border-l border-border pl-4">
                  {shownTimeline.map((item, i) => (
                    <li key={`${item.when}-${i}`} className="relative">
                      <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-accent bg-panel" />
                      <div className="text-xs text-muted">
                        {formatWhen(item.when)} · {item.kind}
                      </div>
                      <div className="text-sm font-medium">{item.label}</div>
                      {item.body ? <pre className="prose-block mt-1">{item.body}</pre> : null}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <SectionTitle>Signals</SectionTitle>
              <p className="mt-0 mb-3 text-sm text-muted">
                This incident has {c.alert_count ?? 0} attached alert(s) in case memory. Cards below
                show the trigger alert and Wazuh alerts matching the same actor (not a full
                attached-alert list).
              </p>
              {c.alert_id ? (
                <div className="mb-3">
                  <div className="mb-1 text-xs font-medium text-muted">Trigger alert</div>
                  {triggerAlert.error ? (
                    <p className="text-sm text-muted">
                      Could not load alert {c.alert_id}:{' '}
                      {(triggerAlert.error as Error).message}
                    </p>
                  ) : triggerAlert.data ? (
                    <AlertCard
                      alert={alertFromRaw(triggerAlert.data, c.alert_id)}
                      onOpen={() => setRawAlertId(c.alert_id!)}
                    />
                  ) : (
                    <p className="text-sm text-muted">Loading…</p>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted">No trigger alert id on this case.</p>
              )}
              <div className="mb-1 text-xs font-medium text-muted">Actor matches from Wazuh</div>
              {(actorAlerts.data || []).length === 0 ? (
                <p className="text-sm text-muted">No matching alerts returned.</p>
              ) : (
                <div className="space-y-2">
                  {(actorAlerts.data || []).map((a, i) => {
                    const aid = String(a.id || a._id || i)
                    return (
                      <AlertCard
                        key={aid}
                        alert={a}
                        onOpen={() => a.id && setRawAlertId(String(a.id))}
                      />
                    )
                  })}
                </div>
              )}
            </section>
          </div>

          <aside className="space-y-3 border-t border-border bg-elevated/40 p-4 xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-y-auto xl:border-l xl:border-t-0">
            <RailCard title="People">
              {users.length ? (
                users.map((u) => (
                  <div key={`${u.entity_type}-${u.value}`} className="font-mono text-xs">
                    {u.value}
                  </div>
                ))
              ) : (
                <p className="m-0 text-xs text-muted">No users linked.</p>
              )}
            </RailCard>

            <RailCard title="Host">
              {actor.agent ? (
                <div className="font-mono text-xs">{actor.agent}</div>
              ) : (
                <p className="m-0 text-xs text-muted">No asset on this case.</p>
              )}
            </RailCard>

            <RailCard title="Indicators">
              {indicators.length ? (
                indicators.map((ind) => (
                  <button
                    key={`${ind.entity_type}-${ind.value}`}
                    type="button"
                    className="block w-full border-none bg-transparent p-0 text-left font-mono text-xs text-accent"
                    onClick={() => setIoc(ind.value)}
                  >
                    {ind.entity_type} {ind.value}
                  </button>
                ))
              ) : actor.sourceIp ? (
                <button
                  type="button"
                  className="block border-none bg-transparent p-0 font-mono text-xs text-accent"
                  onClick={() => setIoc(actor.sourceIp)}
                >
                  ip {actor.sourceIp}
                </button>
              ) : (
                <p className="m-0 text-xs text-muted">No indicators.</p>
              )}
              <div className="mt-2 flex gap-1">
                <Input
                  className="min-w-0 flex-1 text-xs"
                  placeholder="Enrich IOC"
                  value={ioc}
                  onChange={(e) => setIoc(e.target.value)}
                />
                <Button
                  variant="ghost"
                  className="shrink-0 px-2"
                  onClick={async () => {
                    if (!ioc.trim()) {
                      toast('Enter an IOC first', 'error')
                      return
                    }
                    setIocOut('Looking up…')
                    try {
                      const data = await enrichIoc(ioc.trim())
                      setIocOut(JSON.stringify(data, null, 2))
                    } catch (e) {
                      const msg = e instanceof Error ? e.message : String(e)
                      setIocOut(`Error: ${msg}`)
                      toast(msg, 'error')
                    }
                  }}
                >
                  Go
                </Button>
              </div>
              {iocOut ? <pre className="prose-block mt-2 max-h-40">{iocOut}</pre> : null}
            </RailCard>

            <RailCard title="Related">
              {(related.data?.related_cases || []).length === 0 ? (
                <p className="m-0 text-xs text-muted">No related cases.</p>
              ) : (
                (related.data?.related_cases || []).map((rc) => (
                  <Link
                    key={rc.id}
                    to={`/i/${rc.id}`}
                    className="mb-2 block rounded-lg border border-border bg-panel p-2 text-text no-underline hover:border-accent/40"
                  >
                    <div className="text-sm font-medium">
                      #{rc.id} · {rc.title || '(untitled)'}
                    </div>
                    <div className="mt-1 flex gap-1">
                      <StatusBadge status={rc.status} />
                      <PriorityBadge severity={rc.severity} />
                    </div>
                  </Link>
                ))
              )}
            </RailCard>

            <RailCard title="Response">
              <SectionTitle>Containment plan</SectionTitle>
              <p className="mt-0 text-xs text-muted">Outcomes never run UFW.</p>
              {actor.sourceIp ? (
                <p className="text-xs text-muted">
                  Source IP: <code>{actor.sourceIp}</code>
                </p>
              ) : (
                <p className="text-xs text-muted">No source IP — cannot plan a deny.</p>
              )}
              {containmentNotes.map((n) => (
                <div key={n.id} className="mb-2">
                  <div className="text-[0.7rem] text-muted">
                    {n.author} · {n.created_at}
                  </div>
                  <pre className="prose-block">{n.note}</pre>
                </div>
              ))}
              <div className="mb-3 flex flex-wrap gap-2">
                <Button
                  variant="ghost"
                  disabled={!actor.sourceIp}
                  onClick={async () => {
                    try {
                      const plan = await containmentPlan(caseId, true)
                      toast(
                        plan.allowed
                          ? 'Recorded UFW deny plan (dry-run, not executed).'
                          : `Plan not allowed: ${plan.reason || 'unknown'}`,
                        plan.allowed ? 'ok' : 'error',
                      )
                      await qc.invalidateQueries({ queryKey: ['case', caseId] })
                    } catch (e) {
                      toast(e instanceof Error ? e.message : String(e), 'error')
                    }
                  }}
                >
                  Record UFW plan
                </Button>
                <Button
                  variant="danger"
                  disabled={!actor.sourceIp || !canExecute}
                  onClick={async () => {
                    if (!canExecute) {
                      toast('CONTAINMENT_ENABLED is off. Record a dry-run plan instead.', 'error')
                      return
                    }
                    const ok = window.confirm(
                      `Run sudo ufw deny from ${actor.sourceIp || 'this source'} on this host? Analyst outcomes will not do this.`,
                    )
                    if (!ok) return
                    try {
                      const result = await executeContainment({
                        case_id: caseId,
                        confirm: true,
                        source_ip: actor.sourceIp || null,
                      })
                      if (result.executed) {
                        toast(`UFW deny inserted for ${result.source_ip || actor.sourceIp}.`, 'ok')
                      } else {
                        toast(
                          `Not executed: ${result.reason || result.error || 'unknown'}`,
                          'error',
                        )
                      }
                      await qc.invalidateQueries({ queryKey: ['case', caseId] })
                    } catch (e) {
                      toast(e instanceof Error ? e.message : String(e), 'error')
                    }
                  }}
                >
                  {canExecute ? 'Execute UFW deny' : 'Execute disabled (dry-run)'}
                </Button>
              </div>
              <details className="mb-4 text-xs text-muted">
                <summary>UFW policy</summary>
                <p>
                  Approve / outcomes never run UFW. Execute stays off unless{' '}
                  <code>CONTAINMENT_ENABLED=true</code>.
                </p>
              </details>

              <SectionTitle>Host isolation</SectionTitle>
              <p className="mt-0 text-xs text-muted">
                Via Wazuh Active Response — not the Pop UFW deny.
              </p>
              {actor.agent ? (
                <p className="text-xs text-muted">
                  Agent: <code>{actor.agent}</code>
                </p>
              ) : (
                <p className="text-xs text-muted">No agent — cannot plan isolation.</p>
              )}
              <p className="text-xs text-muted">{isolationStatusLine(c.isolation_state)}</p>
              {isolationNotes.map((n) => (
                <div key={n.id} className="mb-2">
                  <div className="text-[0.7rem] text-muted">
                    {n.author} · {n.created_at}
                  </div>
                  <pre className="prose-block">{n.note}</pre>
                </div>
              ))}
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="ghost"
                  disabled={!actor.agent}
                  onClick={async () => {
                    try {
                      const plan = await isolationPlan(caseId, true)
                      toast(
                        plan.allowed
                          ? 'Recorded isolation plan (dry-run, not executed).'
                          : `Plan not allowed: ${plan.reason || 'unknown'}`,
                        plan.allowed ? 'ok' : 'error',
                      )
                      await qc.invalidateQueries({ queryKey: ['case', caseId] })
                    } catch (e) {
                      toast(e instanceof Error ? e.message : String(e), 'error')
                    }
                  }}
                >
                  Record isolation plan
                </Button>
                <Button
                  variant="danger"
                  disabled={!actor.agent || !canIsolate}
                  onClick={async () => {
                    if (!canIsolate) {
                      toast(
                        'HOST_ISOLATION_ENABLED is off. Record a dry-run plan instead.',
                        'error',
                      )
                      return
                    }
                    const ok = window.confirm(
                      `Isolate host ${actor.agent}? Analyst outcomes will not do this.`,
                    )
                    if (!ok) return
                    try {
                      const result = await executeIsolation({
                        case_id: caseId,
                        confirm: true,
                        action: 'isolate',
                        agent_name: actor.agent || null,
                      })
                      if (result.executed) {
                        toast(`Isolate sent for ${result.agent_name || actor.agent}.`, 'ok')
                      } else {
                        toast(
                          `Not executed: ${result.reason || result.error || 'unknown'}`,
                          'error',
                        )
                      }
                      await qc.invalidateQueries({ queryKey: ['case', caseId] })
                    } catch (e) {
                      toast(e instanceof Error ? e.message : String(e), 'error')
                    }
                  }}
                >
                  {canIsolate ? 'Isolate host' : 'Isolate disabled (dry-run)'}
                </Button>
                <Button
                  variant="ghost"
                  disabled={!actor.agent || !canIsolate}
                  onClick={async () => {
                    if (!canIsolate) {
                      toast('HOST_ISOLATION_ENABLED is off.', 'error')
                      return
                    }
                    const ok = window.confirm(`De-isolate host ${actor.agent}?`)
                    if (!ok) return
                    try {
                      const result = await executeIsolation({
                        case_id: caseId,
                        confirm: true,
                        action: 'deisolate',
                        agent_name: actor.agent || null,
                      })
                      if (result.executed) {
                        toast(`De-isolate sent for ${result.agent_name || actor.agent}.`, 'ok')
                      } else {
                        toast(
                          `Not executed: ${result.reason || result.error || 'unknown'}`,
                          'error',
                        )
                      }
                      await qc.invalidateQueries({ queryKey: ['case', caseId] })
                    } catch (e) {
                      toast(e instanceof Error ? e.message : String(e), 'error')
                    }
                  }}
                >
                  {canIsolate ? 'De-isolate host' : 'De-isolate disabled'}
                </Button>
              </div>
              <details className="mt-3 text-xs text-muted">
                <summary>Isolation policy</summary>
                <p>
                  Execute stays off unless <code>HOST_ISOLATION_ENABLED=true</code>. The SIEM agent
                  cannot be isolated.
                </p>
              </details>
            </RailCard>
          </aside>
        </div>
      </Panel>

      {resolveOpen && open ? (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/30 p-4 sm:items-center"
          onClick={() => setResolveOpen(false)}
        >
          <div
            className="sheet-enter w-full max-w-lg rounded-2xl border border-border bg-panel p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="mt-0 text-lg font-semibold">Resolve investigation</h3>
            <p className="text-sm text-muted">
              Records status + note only. No firewall, isolation, or other containment.
            </p>
            <TextArea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. Confirmed lab nmap from Kali; document only"
            />
            <div className="mt-3 flex flex-wrap gap-2">
              {ANALYST_OUTCOMES.map((o) => (
                <Button
                  key={o.id}
                  variant={o.danger ? 'danger' : 'default'}
                  disabled={decide.isPending}
                  onClick={() => decide.mutate(o.id)}
                >
                  {o.label}
                </Button>
              ))}
            </div>
            <details className="mt-4 text-xs text-muted">
              <summary>What these labels mean</summary>
              <div className="mt-2 space-y-2">
                {ANALYST_OUTCOMES.map((o) => (
                  <article key={o.id} className="rounded-lg border border-border bg-elevated p-2">
                    <h4 className="m-0 text-xs font-semibold">
                      {o.label}
                      {o.skip ? '' : ' (no skip)'}
                    </h4>
                    <p className="mb-0 mt-1">{o.text}</p>
                  </article>
                ))}
              </div>
            </details>
            <div className="mt-4 flex justify-end">
              <Button variant="ghost" onClick={() => setResolveOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {rawAlertId ? (
        <RawAlertDrawer
          alertId={rawAlertId}
          data={rawAlertId === c.alert_id ? triggerAlert.data : undefined}
          onClose={() => setRawAlertId(null)}
        />
      ) : null}
    </div>
  )
}

function StorySection({
  c,
  brief,
  actor,
  invNotes,
}: {
  c: Case
  brief: CaseBrief
  actor: { sourceIp: string; user: string; agent: string }
  invNotes: CaseNote[]
}) {
  const rule = brief.rule || {}
  const ruleLabel =
    (rule.id || c.rule_id || '—') + (rule.level != null ? ` · level ${rule.level}` : '')

  return (
    <section className="space-y-4">
      <SectionTitle>Story</SectionTitle>
      <div className="rounded-xl border border-border bg-elevated/50 p-4">
        <h3 className="mt-0 text-lg font-semibold tracking-tight">
          {brief.headline || c.title || '(untitled)'}
        </h3>
        <dl className="mb-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
          <div>
            <dt className="text-xs text-muted">Source</dt>
            <dd className="m-0 font-mono text-sm">{actor.sourceIp || '—'}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">User</dt>
            <dd className="m-0 font-mono text-sm">{actor.user || '—'}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Host</dt>
            <dd className="m-0 font-mono text-sm">{actor.agent || '—'}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Rule</dt>
            <dd className="m-0 font-mono text-sm">{ruleLabel}</dd>
          </div>
        </dl>
        {brief.why?.length ? (
          <p className="text-sm text-muted">{brief.why.join('; ')}</p>
        ) : null}
        {brief.do_next?.length ? (
          <ol className="mb-0 pl-5 text-sm">
            {brief.do_next.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        ) : null}
        {brief.wazuh_url ? (
          <p className="mb-0 mt-3 text-sm">
            <a href={brief.wazuh_url} target="_blank" rel="noopener noreferrer">
              Open Wazuh
            </a>
          </p>
        ) : null}
      </div>

      {(brief.evidence || brief.vt) && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted">Evidence</div>
          {brief.evidence ? <pre className="prose-block">{brief.evidence}</pre> : null}
          {brief.vt ? <p className="text-sm text-muted">VirusTotal: {brief.vt}</p> : null}
        </div>
      )}

      <div className="investigation-panel rounded-xl border border-border bg-panel p-4">
        <SectionTitle>Cursor investigation</SectionTitle>
        {invNotes.length ? (
          <>
            <p className="mt-0 text-xs text-muted">
              Copied from the cloud agent final reply onto this case. Still propose-only.
            </p>
            {invNotes.map((n) => (
              <div key={n.id} className="mb-3">
                <div className="mb-1 text-xs text-muted">
                  {n.author} · {n.created_at}
                </div>
                <pre className="prose-block">{n.note}</pre>
              </div>
            ))}
          </>
        ) : isOpenStatus(c.status) ? (
          <p className="investigation-empty m-0 text-sm text-muted">Investigation not in yet.</p>
        ) : (
          <p className="m-0 text-sm text-muted">No investigation note on this closed case.</p>
        )}
      </div>
    </section>
  )
}

function RailCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-panel">
      <PanelHead title={title} />
      <div className="space-y-1 p-3">{children}</div>
    </div>
  )
}

function normalizeAlert(alert: AlertRow): AlertRow {
  const src = (alert._source || alert) as AlertRow
  return {
    ...src,
    id: String(alert.id || alert._id || src.id || ''),
    rule: src.rule || alert.rule,
    agent: src.agent || alert.agent,
    timestamp: String(src.timestamp || alert.timestamp || ''),
  }
}

function AlertCard({ alert, onOpen }: { alert: AlertRow; onOpen: () => void }) {
  const a = normalizeAlert(alert)
  const rule = a.rule || {}
  const agentName =
    typeof a.agent === 'object' && a.agent
      ? a.agent.name || '—'
      : typeof a.agent === 'string'
        ? a.agent
        : '—'
  return (
    <button
      type="button"
      onClick={onOpen}
      className="block w-full rounded-xl border border-border bg-panel p-3 text-left transition-colors hover:border-accent/40"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <strong className="text-sm">
          {rule.description || 'Alert'} · rule {rule.id ?? '—'}
        </strong>
        <span className="font-mono text-xs text-muted">level {rule.level ?? '—'}</span>
      </div>
      <div className="mt-1 font-mono text-xs text-muted">
        {agentName}
        {a.timestamp ? ` · ${a.timestamp}` : ''}
      </div>
    </button>
  )
}

function alertFromRaw(raw: Record<string, unknown>, id: string): AlertRow {
  const nested = (raw._source || raw) as Record<string, unknown>
  return {
    id,
    rule: (nested.rule as AlertRow['rule']) || undefined,
    agent: (nested.agent as AlertRow['agent']) || undefined,
    timestamp: String(nested.timestamp || nested['@timestamp'] || ''),
    full_log: String(nested.full_log || ''),
    ...nested,
  }
}

function RawAlertDrawer({
  alertId,
  data,
  onClose,
}: {
  alertId: string
  data?: Record<string, unknown>
  onClose: () => void
}) {
  const q = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => getAlert(alertId),
    enabled: !data && !!alertId,
  })
  const payload = data || q.data
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/25" onClick={onClose}>
      <div
        className="sheet-enter h-full w-full max-w-xl overflow-auto border-l border-border bg-panel p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h3 className="m-0 font-semibold">Raw alert</h3>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
        <p className="text-xs text-muted">{alertId}</p>
        <pre className="prose-block max-h-none">
          {payload ? JSON.stringify(payload, null, 2) : q.isLoading ? 'Loading…' : 'Unavailable'}
        </pre>
      </div>
    </div>
  )
}

function buildTimeline(
  notes: CaseNote[],
  createdAt?: string,
  updatedAt?: string,
): Array<{ when: string; label: string; body?: string; kind: string }> {
  const items: Array<{ when: string; label: string; body?: string; kind: string }> = []
  if (createdAt) items.push({ when: createdAt, label: 'Investigation created', kind: 'system' })
  if (updatedAt && updatedAt !== createdAt) {
    items.push({ when: updatedAt, label: 'Investigation updated', kind: 'system' })
  }
  for (const n of notes) {
    if (isInvestigationNote(n) || isContainmentNote(n) || isIsolationNote(n)) {
      items.push({
        when: n.created_at,
        label: timelineLabel(n),
        body: n.note,
        kind: 'note',
      })
      continue
    }
    const text = n.note || ''
    if (text.includes('[human_approval]')) {
      const sentence = noteField(text, 'note') || text
      items.push({
        when: n.created_at,
        label: sentence,
        body: sentence !== text ? text : undefined,
        kind: 'approval',
      })
      continue
    }
    items.push({
      when: n.created_at,
      label: `${n.author || '?'} · ${timelineLabel(n)}`,
      body: text,
      kind: 'note',
    })
  }
  return items.sort((a, b) => String(b.when).localeCompare(String(a.when)))
}
