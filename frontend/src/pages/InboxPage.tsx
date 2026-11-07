import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { approveCases, getQueueMetrics, getSituation, listCases } from '../api/client'
import type { AnalystDisposition, Case } from '../api/types'
import { DispositionBadge, PriorityBadge, StatusBadge } from '../components/Badge'
import { Button, Empty, Input, Panel, PanelHead, Select } from '../components/ui'
import { usePolling } from '../hooks/useAutoRefresh'
import { ANALYST_OUTCOMES, actorFromCase, formatWhen, isOpenStatus } from '../lib/mapping'
import { useToast } from '../lib/toast'

export function InboxPage() {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [status, setStatus] = useState('open')
  const [priority, setPriority] = useState('')
  const [disposition, setDisposition] = useState('')
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [bulkNote, setBulkNote] = useState('')
  const [bulkDisposition, setBulkDisposition] =
    useState<AnalystDisposition>('false_positive')

  const metrics = useQuery({ queryKey: ['metrics'], queryFn: getQueueMetrics })
  const situation = useQuery({ queryKey: ['situation'], queryFn: () => getSituation(8) })
  const cases = useQuery({
    queryKey: ['cases', status || 'all'],
    queryFn: () => listCases({ status: status || undefined, limit: 200 }),
  })

  usePolling(() => {
    void metrics.refetch()
    void situation.refetch()
    void cases.refetch()
  })

  const filtered = useMemo(() => {
    let rows = cases.data?.cases || []
    if (priority) {
      rows = rows.filter((c) => (c.severity || '').toLowerCase() === priority)
    }
    if (disposition) {
      rows = rows.filter(
        (c) =>
          (c.disposition || '').toLowerCase() === disposition ||
          (c.analyst_disposition || '').toLowerCase() === disposition,
      )
    }
    if (q.trim()) {
      const needle = q.trim().toLowerCase()
      rows = rows.filter((c) => {
        const a = actorFromCase(c)
        return (
          String(c.id).includes(needle) ||
          (c.title || '').toLowerCase().includes(needle) ||
          (c.rule_id || '').toLowerCase().includes(needle) ||
          a.sourceIp.toLowerCase().includes(needle) ||
          a.user.toLowerCase().includes(needle) ||
          a.agent.toLowerCase().includes(needle)
        )
      })
    }
    return rows
  }, [cases.data, priority, disposition, q])

  const bulk = useMutation({
    mutationFn: () =>
      approveCases({
        case_ids: [...selected],
        disposition: bulkDisposition,
        note: bulkNote,
      }),
    onSuccess: async (result) => {
      const n = result.count || 0
      const skipped = (result.skipped || []).length
      const errors = (result.errors || []).length
      toast(
        `Closed ${n} as ${bulkDisposition} (record only, no containment)` +
          (skipped ? `; skipped ${skipped} not-open` : '') +
          (errors ? `; ${errors} error(s)` : '') +
          '.',
        errors ? 'error' : 'ok',
      )
      setSelected(new Set())
      await qc.invalidateQueries({ queryKey: ['cases'] })
      await qc.invalidateQueries({ queryKey: ['metrics'] })
      await qc.invalidateQueries({ queryKey: ['situation'] })
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  const m = metrics.data || {}
  const groups = situation.data?.groups || []

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {[
          ['Open', m.open],
          ['Auto-closed', m.auto_closed],
          ['Human closed', m.human_closed],
          ['Suppressions', m.active_suppressions],
          ['Feedback', m.feedback_total],
        ].map(([label, value]) => (
          <div key={String(label)} className="rounded-xl border border-border bg-panel px-4 py-3">
            <div className="font-mono text-2xl font-semibold tracking-tight">{value ?? '—'}</div>
            <div className="text-xs text-muted">{label}</div>
          </div>
        ))}
      </div>

      {groups.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {groups.map((g, i) => {
            const caseId = (g.case_ids || [])[0]
            const who = g.source_ip || (g.user ? `user ${g.user}` : '—')
            return (
              <Link
                key={`${who}-${i}`}
                to={caseId ? `/i/${caseId}` : '/'}
                className="inline-flex items-center gap-2 rounded-full border border-border bg-panel px-3 py-1.5 text-sm text-text no-underline hover:border-accent/40 hover:bg-accent-soft"
              >
                <span className="font-mono text-xs">{who}</span>
                <PriorityBadge severity={g.severity} />
                <span className="text-xs text-muted">{g.alert_count || 0} alerts</span>
              </Link>
            )
          })}
        </div>
      ) : null}

      <Panel>
        <PanelHead title="Inbox">
          <Select
            aria-label="Filter by status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value)
              setSelected(new Set())
            }}
          >
            <option value="">All</option>
            <option value="open">Open / pending</option>
            <option value="confirmed_compromise">Confirmed compromise</option>
            <option value="false_positive">False positive</option>
            <option value="benign">Benign</option>
            <option value="informational">Informational</option>
            <option value="duplicate">Duplicate</option>
            <option value="auto_closed">Auto-closed noise</option>
          </Select>
          <Select
            aria-label="Filter by priority"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
          >
            <option value="">Any priority</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
          <Select
            aria-label="Filter by disposition"
            value={disposition}
            onChange={(e) => setDisposition(e.target.value)}
          >
            <option value="">Any disposition</option>
            <option value="true_positive">True positive</option>
            <option value="suspicious">Suspicious</option>
            <option value="false_positive">False positive</option>
            <option value="informational">Informational</option>
            <option value="benign">Benign</option>
          </Select>
          <Input
            placeholder="Search title, IP, user, asset…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="min-w-[200px]"
          />
          <Button variant="ghost" onClick={() => void cases.refetch()}>
            Refresh
          </Button>
        </PanelHead>

        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-elevated/50 px-4 py-2">
          <label className="inline-flex items-center gap-1.5 text-xs text-muted">
            <input
              type="checkbox"
              checked={filtered.length > 0 && filtered.every((c) => selected.has(c.id))}
              onChange={(e) => {
                if (e.target.checked) setSelected(new Set(filtered.map((c) => c.id)))
                else setSelected(new Set())
              }}
            />
            Select all
          </label>
          <span className="text-xs text-muted">{selected.size} selected</span>
          <Input
            className="min-w-[160px] flex-1"
            placeholder="Bulk note (optional)"
            value={bulkNote}
            onChange={(e) => setBulkNote(e.target.value)}
          />
          <Select
            value={bulkDisposition}
            onChange={(e) => setBulkDisposition(e.target.value as AnalystDisposition)}
            aria-label="Bulk analyst outcome"
          >
            {ANALYST_OUTCOMES.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </Select>
          <Button
            variant="primary"
            disabled={selected.size === 0 || bulk.isPending}
            onClick={() => bulk.mutate()}
          >
            Apply to selected
          </Button>
        </div>

        {cases.isLoading ? (
          <Empty>Loading inbox…</Empty>
        ) : filtered.length === 0 ? (
          <Empty>No cases for this filter.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] border-collapse text-left text-sm">
              <thead className="text-xs text-muted">
                <tr>
                  <th className="w-10 px-3 py-2.5 font-medium" />
                  <th className="px-3 py-2.5 font-medium">Priority</th>
                  <th className="px-3 py-2.5 font-medium">Investigation</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Disposition</th>
                  <th className="px-3 py-2.5 font-medium">Alerts</th>
                  <th className="px-3 py-2.5 font-medium">Asset</th>
                  <th className="px-3 py-2.5 font-medium">Actor</th>
                  <th className="px-3 py-2.5 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <InvestigationRow
                    key={c.id}
                    c={c}
                    checked={selected.has(c.id)}
                    onCheck={(on) => {
                      setSelected((prev) => {
                        const next = new Set(prev)
                        if (on) next.add(c.id)
                        else next.delete(c.id)
                        return next
                      })
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="border-t border-border px-4 py-2 text-xs text-muted">
          {filtered.length} investigation(s)
          {cases.dataUpdatedAt
            ? ` · refreshed ${new Date(cases.dataUpdatedAt).toLocaleTimeString()}`
            : ''}
        </div>
      </Panel>
    </div>
  )
}

function InvestigationRow({
  c,
  checked,
  onCheck,
}: {
  c: Case
  checked: boolean
  onCheck: (on: boolean) => void
}) {
  const actor = actorFromCase(c)
  return (
    <tr className="border-t border-border transition-colors hover:bg-elevated/60">
      <td className="px-3 py-2.5 align-top">
        <input
          type="checkbox"
          checked={checked}
          disabled={!isOpenStatus(c.status)}
          onChange={(e) => onCheck(e.target.checked)}
          aria-label={`Select case ${c.id}`}
        />
      </td>
      <td className="px-3 py-2.5 align-top">
        <PriorityBadge severity={c.severity} />
      </td>
      <td className="px-3 py-2.5 align-top">
        <Link
          to={`/i/${c.id}`}
          className="font-medium text-text no-underline hover:text-accent"
        >
          #{c.id} · {c.title || '(untitled)'}
        </Link>
        {c.rule_id ? (
          <div className="mt-0.5 font-mono text-[0.7rem] text-muted">rule {c.rule_id}</div>
        ) : null}
      </td>
      <td className="px-3 py-2.5 align-top">
        <StatusBadge status={c.status} />
      </td>
      <td className="px-3 py-2.5 align-top">
        <DispositionBadge disposition={c.disposition || c.analyst_disposition} />
      </td>
      <td className="px-3 py-2.5 align-top font-mono text-xs">
        {c.alert_count ?? (c.alert_id ? 1 : 0)}
      </td>
      <td className="px-3 py-2.5 align-top font-mono text-xs">{actor.agent || '—'}</td>
      <td className="px-3 py-2.5 align-top font-mono text-xs">
        {[actor.sourceIp, actor.user].filter(Boolean).join(' · ') || '—'}
      </td>
      <td className="px-3 py-2.5 align-top text-xs text-muted">{formatWhen(c.updated_at)}</td>
    </tr>
  )
}
