import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  addSuppression,
  disableSuppression,
  listSuppressions,
  suppressionSuggestions,
} from '../api/client'
import { Button, Empty, Input, Panel, PanelHead, Select } from '../components/ui'
import { useToast } from '../lib/toast'

export function ExceptionsPage() {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [ruleId, setRuleId] = useState('')
  const [sourceIp, setSourceIp] = useState('')
  const [disposition, setDisposition] = useState('informational')
  const [note, setNote] = useState('')

  const suppressions = useQuery({
    queryKey: ['suppressions'],
    queryFn: () => listSuppressions(50),
  })
  const suggestions = useQuery({
    queryKey: ['suppression_suggestions'],
    queryFn: () => suppressionSuggestions(2, 8),
  })

  const add = useMutation({
    mutationFn: () =>
      addSuppression({
        rule_id: ruleId.trim(),
        source_ip: sourceIp.trim() || null,
        disposition,
        note: note.trim(),
      }),
    onSuccess: async () => {
      toast(`Suppression added for rule ${ruleId.trim()}`, 'ok')
      setRuleId('')
      setSourceIp('')
      setNote('')
      await qc.invalidateQueries({ queryKey: ['suppressions'] })
      await qc.invalidateQueries({ queryKey: ['metrics'] })
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  const disable = useMutation({
    mutationFn: (id: number) => disableSuppression(id),
    onSuccess: async (_r, id) => {
      toast(`Suppression #${id} disabled`, 'ok')
      await qc.invalidateQueries({ queryKey: ['suppressions'] })
      await qc.invalidateQueries({ queryKey: ['metrics'] })
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  return (
    <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
      <Panel>
        <PanelHead title="Add exception" />
        <div className="space-y-3 p-4">
          <p className="m-0 text-xs text-muted">
            Auto-close before Discord/Cursor. Empty source = any IP. Confirmed compromise cannot
            suppress.
          </p>
          <Input
            placeholder="rule_id (e.g. 2501)"
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            className="w-full"
            aria-label="Suppression rule id"
          />
          <Input
            placeholder="source IP (optional)"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            className="w-full"
            aria-label="Suppression source IP"
          />
          <Select
            value={disposition}
            onChange={(e) => setDisposition(e.target.value)}
            className="w-full"
            aria-label="Suppression disposition"
          >
            <option value="informational">Informational</option>
            <option value="false_positive">False positive</option>
          </Select>
          <Input
            placeholder="note (optional)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="w-full"
            aria-label="Suppression note"
          />
          <Button
            variant="primary"
            className="w-full"
            disabled={!ruleId.trim() || add.isPending}
            onClick={() => add.mutate()}
          >
            Add suppression
          </Button>
        </div>
      </Panel>

      <div className="space-y-4">
        <Panel>
          <PanelHead title="Active suppressions" />
          {suppressions.isLoading ? (
            <Empty>Loading…</Empty>
          ) : (suppressions.data?.suppressions || []).length === 0 ? (
            <Empty>No active suppressions.</Empty>
          ) : (
            <ul className="m-0 list-none divide-y divide-border p-0">
              {(suppressions.data?.suppressions || []).map((s) => {
                const src = s.any_source ? 'any source' : s.source_ip || '—'
                return (
                  <li
                    key={s.id}
                    className="flex flex-wrap items-center justify-between gap-2 px-4 py-3"
                  >
                    <div>
                      <code>#{s.id}</code> rule <code>{s.rule_id}</code> · {src} ·{' '}
                      {s.disposition || ''}
                      {s.expires_at ? ` · exp ${s.expires_at}` : ''}
                      {s.note ? <div className="text-xs text-muted">{s.note}</div> : null}
                    </div>
                    <Button
                      variant="ghost"
                      onClick={() => disable.mutate(s.id)}
                      disabled={disable.isPending}
                    >
                      Disable
                    </Button>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>

        <Panel>
          <PanelHead title="Suggestions from feedback" />
          {(suggestions.data?.suggestions || []).length === 0 ? (
            <Empty>No suggestions.</Empty>
          ) : (
            <ul className="m-0 list-none divide-y divide-border p-0">
              {(suggestions.data?.suggestions || []).map((s, i) => {
                const src = s.any_source ? '' : s.source_ip || ''
                const label = `rule ${s.rule_id}${src ? ` @ ${src}` : ' (any)'} ×${s.count}`
                return (
                  <li
                    key={`${s.rule_id}-${i}`}
                    className="flex flex-wrap items-center justify-between gap-2 px-4 py-3"
                  >
                    <span className="text-sm">{label}</span>
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setRuleId(s.rule_id)
                        setSourceIp(src)
                        setDisposition(s.suggested_disposition || 'informational')
                        setNote('seeded from feedback suggestion')
                      }}
                    >
                      Add
                    </Button>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}
