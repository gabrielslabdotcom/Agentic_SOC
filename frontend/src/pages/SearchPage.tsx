import { useMutation } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { search } from '../api/client'
import type { SearchResponse, SearchStep } from '../api/types'
import { Button, Empty, Panel, PanelHead, TextArea } from '../components/ui'
import { useToast } from '../lib/toast'

const EXAMPLES = [
  'which hosts listen on 3389',
  'who logged in as tstark this week',
  'critical CVEs on domain-controller',
  'any PowerShell processes on windows-workstation',
  'failed logins from 198.51.100.0/24 in the last 24h',
]

const RECENT_KEY = 'agentic-soc-search-recent'
const MAX_RECENT = 8

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string').slice(0, MAX_RECENT) : []
  } catch {
    return []
  }
}

function pushRecent(question: string): string[] {
  const next = [question, ...loadRecent().filter((q) => q !== question)].slice(0, MAX_RECENT)
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next))
  } catch {
    /* ignore quota */
  }
  return next
}

function cell(value: unknown): string {
  if (value == null) return '—'
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function SearchPage() {
  const { toast } = useToast()
  const [params, setParams] = useSearchParams()
  const initialQ = params.get('q') || ''
  const [question, setQuestion] = useState(initialQ)
  const [recent, setRecent] = useState<string[]>(() => loadRecent())
  const [result, setResult] = useState<SearchResponse | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    const q = params.get('q') || ''
    if (q && q !== question) setQuestion(q)
    // Only sync when the URL changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params])

  const mutation = useMutation({
    mutationFn: (q: string) => search(q),
    onSuccess: (data, q) => {
      setResult(data)
      setRecent(pushRecent(q))
      setParams(q ? { q } : {})
    },
    onError: (err: Error) => {
      toast(err.message || 'Search failed')
    },
  })

  function run(q: string) {
    const trimmed = q.trim()
    if (!trimmed) {
      toast('Enter a question')
      return
    }
    setExpanded(null)
    mutation.mutate(trimmed)
  }

  const steps = result?.steps || []
  const results = result?.results
  const hasRows = useMemo(() => {
    if (!results) return false
    return Boolean(
      (results.alerts && results.alerts.length) ||
        (results.inventory && results.inventory.length) ||
        (results.vulnerabilities && results.vulnerabilities.length) ||
        (results.cases && results.cases.length) ||
        (results.agents && results.agents.length) ||
        (results.buckets && results.buckets.length),
    )
  }, [results])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-4">
      <Panel>
        <PanelHead title="Ask Pop">
          <span className="text-xs text-muted">
            Natural-language search over alerts, inventory, vulns, and cases
          </span>
        </PanelHead>
        <div className="space-y-3 p-4">
          <TextArea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about a user, host, CVE, port, or incident…"
            rows={3}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                e.preventDefault()
                run(question)
              }
            }}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              disabled={mutation.isPending}
              onClick={() => run(question)}
            >
              {mutation.isPending ? 'Searching…' : 'Search'}
            </Button>
            <span className="text-xs text-muted">⌘/Ctrl + Enter</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                className="rounded-lg border border-border bg-elevated px-2.5 py-1 text-xs text-muted hover:text-text"
                onClick={() => {
                  setQuestion(ex)
                  run(ex)
                }}
              >
                {ex}
              </button>
            ))}
          </div>
          {recent.length ? (
            <div className="text-xs text-muted">
              Recent:{' '}
              {recent.map((q, i) => (
                <button
                  key={`${q}-${i}`}
                  type="button"
                  className="mr-2 text-accent hover:underline"
                  onClick={() => {
                    setQuestion(q)
                    run(q)
                  }}
                >
                  {q.length > 48 ? `${q.slice(0, 47)}…` : q}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      </Panel>

      {result ? (
        <>
          <Panel>
            <PanelHead title="Answer">
              <span className="text-xs text-muted">
                {result.mode === 'llm'
                  ? result.model || 'llm'
                  : 'keyword fallback'}
              </span>
            </PanelHead>
            <div className="prose-block m-4 max-h-none whitespace-pre-wrap font-sans text-sm leading-relaxed">
              {result.answer || 'No answer.'}
            </div>
          </Panel>

          {steps.length ? (
            <Panel>
              <PanelHead title="How Pop searched" />
              <div className="divide-y divide-border">
                {steps.map((step, idx) => (
                  <StepRow key={`${step.tool}-${idx}`} step={step} />
                ))}
              </div>
            </Panel>
          ) : null}

          {hasRows ? (
            <div className="space-y-4">
              {(results?.buckets || []).length ? (
                <ResultTable
                  title="Aggregations"
                  columns={['key', 'count']}
                  rows={(results?.buckets || []).map((b) => ({
                    key: b.key,
                    count: b.count,
                  }))}
                />
              ) : null}
              {(results?.alerts || []).length ? (
                <AlertTable
                  rows={results?.alerts || []}
                  expanded={expanded}
                  setExpanded={setExpanded}
                />
              ) : null}
              {(results?.inventory || []).length ? (
                <ResultTable
                  title={`Inventory (${results?.inventory?.length})`}
                  columns={['agent', 'category', 'process', 'destination', 'package', 'user']}
                  rows={results?.inventory || []}
                />
              ) : null}
              {(results?.vulnerabilities || []).length ? (
                <ResultTable
                  title={`Vulnerabilities (${results?.vulnerabilities?.length})`}
                  columns={['agent', 'cve', 'severity', 'score', 'package', 'description']}
                  rows={results?.vulnerabilities || []}
                />
              ) : null}
              {(results?.cases || []).length ? (
                <CaseTable rows={results?.cases || []} />
              ) : null}
              {(results?.agents || []).length ? (
                <ResultTable
                  title={`Agents (${results?.agents?.length})`}
                  columns={['name', 'ip', 'status', 'os', 'version']}
                  rows={results?.agents || []}
                />
              ) : null}
            </div>
          ) : mutation.isSuccess ? (
            <Panel>
              <Empty>No matching records in the tool results.</Empty>
            </Panel>
          ) : null}
        </>
      ) : (
        <Panel>
          <Empty>
            Ask a question in plain English. Pop turns it into read-only searches over Wazuh and
            local cases.
          </Empty>
        </Panel>
      )}
    </div>
  )
}

function StepRow({ step }: { step: SearchStep }) {
  const args = step.args || {}
  const summary = Object.entries(args)
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' · ')
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
      <code className="font-mono text-xs text-accent">{step.tool}</code>
      <span className="text-muted">
        {step.hit_count ?? 0}
        {step.total != null && step.total !== step.hit_count ? ` / ${step.total}` : ''} hits
      </span>
      {summary ? <span className="text-xs text-muted">{summary}</span> : null}
      {step.error ? <span className="text-xs text-danger">{step.error}</span> : null}
    </div>
  )
}

function ResultTable({
  title,
  columns,
  rows,
}: {
  title: string
  columns: string[]
  rows: Record<string, unknown>[]
}) {
  return (
    <Panel>
      <PanelHead title={title} />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-muted">
              {columns.map((c) => (
                <th key={c} className="px-3 py-2 font-medium">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-border/70 align-top">
                {columns.map((c) => (
                  <td key={c} className="max-w-[220px] truncate px-3 py-2 font-mono text-xs">
                    {cell(row[c])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function AlertTable({
  rows,
  expanded,
  setExpanded,
}: {
  rows: Record<string, unknown>[]
  expanded: string | null
  setExpanded: (id: string | null) => void
}) {
  return (
    <Panel>
      <PanelHead title={`Alerts (${rows.length})`} />
      <div className="divide-y divide-border">
        {rows.map((row, i) => {
          const id = String(row.id || i)
          const open = expanded === id
          return (
            <div key={id} className="px-4 py-3">
              <button
                type="button"
                className="flex w-full flex-wrap items-baseline gap-x-3 gap-y-1 text-left text-sm"
                onClick={() => setExpanded(open ? null : id)}
              >
                <span className="font-mono text-xs text-muted">{cell(row.timestamp)}</span>
                <span className="font-medium">{cell(row.agent)}</span>
                <span className="text-muted">
                  rule {cell(row.rule_id)} · L{cell(row.rule_level)}
                </span>
                <span className="text-muted">
                  {cell(row.user)} {cell(row.srcip)}
                </span>
                <span className="basis-full text-sm">{cell(row.description)}</span>
              </button>
              {open ? (
                <pre className="prose-block mt-2 max-h-64 overflow-auto">
                  {JSON.stringify(row, null, 2)}
                </pre>
              ) : null}
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

function CaseTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <Panel>
      <PanelHead title={`Cases (${rows.length})`} />
      <div className="divide-y divide-border">
        {rows.map((row) => {
          const id = Number(row.id)
          return (
            <div key={String(row.id)} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-3 text-sm">
              {Number.isFinite(id) ? (
                <Link to={`/i/${id}`} className="font-medium">
                  #{id}
                </Link>
              ) : (
                <span className="font-medium">#{cell(row.id)}</span>
              )}
              <span>{cell(row.title)}</span>
              <span className="text-xs text-muted">
                {cell(row.status)} · {cell(row.severity)} · {cell(row.agent_name)}
              </span>
              {row.summary ? (
                <span className="basis-full text-xs text-muted">{cell(row.summary)}</span>
              ) : null}
            </div>
          )
        })}
      </div>
    </Panel>
  )
}
