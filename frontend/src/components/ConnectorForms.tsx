import { useState } from 'react'
import type { ConnectorCard } from '../api/types'
import { Button, Input } from './ui'

function fieldValue(field: ConnectorCard['fields'][number]): string | boolean {
  if (field.kind === 'bool') return !!field.value
  if (field.secret) return ''
  return String(field.value || '')
}

export function ConnectorForms({
  cards,
  prefix,
  onSave,
  onTest,
}: {
  cards: ConnectorCard[]
  prefix: string
  onSave: (id: string, body: { enabled: boolean; config: Record<string, unknown> }) => Promise<void>
  onTest: (id: string, body: { enabled: boolean; config: Record<string, unknown> }) => Promise<void>
}) {
  return (
    <>
      {cards.map((card) => (
        <ConnectorCardForm
          key={`${prefix}-${card.id}`}
          card={card}
          prefix={prefix}
          onSave={onSave}
          onTest={onTest}
        />
      ))}
    </>
  )
}

function ConnectorCardForm({
  card,
  prefix,
  onSave,
  onTest,
}: {
  card: ConnectorCard
  prefix: string
  onSave: (id: string, body: { enabled: boolean; config: Record<string, unknown> }) => Promise<void>
  onTest: (id: string, body: { enabled: boolean; config: Record<string, unknown> }) => Promise<void>
}) {
  const [enabled, setEnabled] = useState(card.enabled)
  const [values, setValues] = useState<Record<string, string | boolean>>(() => {
    const init: Record<string, string | boolean> = {}
    for (const f of card.fields || []) init[f.key] = fieldValue(f)
    return init
  })
  const [busy, setBusy] = useState(false)

  function body() {
    return { enabled, config: { ...values } as Record<string, unknown> }
  }

  return (
    <form
      className="rounded-xl border border-border bg-elevated/60 p-4"
      data-connector={card.id}
      data-prefix={prefix}
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        try {
          await onSave(card.id, body())
        } finally {
          setBusy(false)
        }
      }}
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="m-0 text-base font-semibold">{card.name}</h3>
        <span className="text-xs text-muted">
          {card.kind} · {enabled ? 'enabled' : 'off'}
        </span>
      </div>
      {card.blurb ? <p className="mt-0 text-sm text-muted">{card.blurb}</p> : null}
      <label className="mb-3 flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          className="conn-enabled"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        Enabled
      </label>
      <div className="space-y-3">
        {(card.fields || []).map((field) => {
          const id = `${prefix}-${card.id}-${field.key}`
          if (field.kind === 'bool') {
            return (
              <label key={field.key} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  id={id}
                  data-key={field.key}
                  checked={!!values[field.key]}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [field.key]: e.target.checked }))
                  }
                />
                {field.label}
              </label>
            )
          }
          return (
            <div key={field.key}>
              <label htmlFor={id} className="mb-1 block text-sm text-muted">
                {field.label}
              </label>
              <Input
                id={id}
                data-key={field.key}
                type={field.secret ? 'password' : 'text'}
                className="w-full"
                autoComplete="off"
                value={String(values[field.key] ?? '')}
                placeholder={field.secret && field.configured ? field.hint || 'saved' : ''}
                onChange={(e) =>
                  setValues((v) => ({ ...v, [field.key]: e.target.value }))
                }
              />
            </div>
          )
        })}
      </div>
      <div className="mt-3 flex gap-2">
        <Button type="submit" variant="primary" disabled={busy}>
          Save
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            try {
              await onTest(card.id, body())
            } finally {
              setBusy(false)
            }
          }}
        >
          Test
        </Button>
      </div>
    </form>
  )
}
