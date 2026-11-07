import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  getSetup,
  getSetupToken,
  listConnectors,
  saveConnector,
  setSetupToken,
  testConnector,
} from '../api/client'
import type { ConnectorCard } from '../api/types'
import { useToast } from '../lib/toast'
import { Button, Input } from './ui'
import { ConnectorForms } from './ConnectorForms'

export function SetupWizard({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [token, setToken] = useState(getSetupToken())
  const connectors = useQuery({
    queryKey: ['connectors'],
    queryFn: listConnectors,
    enabled: open,
  })

  const saveAll = useMutation({
    mutationFn: async (cards: ConnectorCard[]) => {
      setSetupToken(token)
      for (const card of cards) {
        const form = document.querySelector(
          `form[data-connector="${card.id}"][data-prefix="wiz"]`,
        ) as HTMLFormElement | null
        if (!form) continue
        const enabledBox = form.querySelector('.conn-enabled') as HTMLInputElement | null
        if (card.id === 'wazuh' && enabledBox) enabledBox.checked = true
        const config: Record<string, unknown> = {}
        form.querySelectorAll<HTMLInputElement>('[data-key]').forEach((input) => {
          config[input.dataset.key!] =
            input.type === 'checkbox' ? input.checked : input.value
        })
        const enabled = !!(enabledBox && enabledBox.checked)
        if (card.id !== 'wazuh' && !enabled) continue
        await saveConnector(card.id, { enabled, config })
      }
      return getSetup()
    },
    onSuccess: async (setup) => {
      toast('Connectors saved')
      await qc.invalidateQueries({ queryKey: ['connectors'] })
      await qc.invalidateQueries({ queryKey: ['setup'] })
      await qc.invalidateQueries({ queryKey: ['ui_config'] })
      if (setup.ready) onClose()
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  if (!open) return null
  const cards = connectors.data?.connectors || []

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/30 p-6">
      <div className="sheet-enter w-full max-w-3xl rounded-2xl border border-border bg-panel p-6 shadow-xl">
        <h2 className="mt-0 text-xl font-semibold tracking-tight">Set up Agentic SOC</h2>
        <p className="text-sm text-muted">
          Wazuh is required. An LLM, VirusTotal, and Discord are optional. From inside Docker,{' '}
          <code>127.0.0.1</code> is the container itself. If Wazuh runs on the same machine, use that
          machine’s LAN address or <code>host.docker.internal</code>.
        </p>
        <label className="mt-4 block text-sm text-muted" htmlFor="wizard-token">
          Setup token
        </label>
        <Input
          id="wizard-token"
          type="password"
          className="mt-1 w-full"
          value={token}
          autoComplete="off"
          placeholder="From the container logs on first boot"
          onChange={(e) => {
            setToken(e.target.value)
            setSetupToken(e.target.value)
          }}
        />
        <div className="mt-4 space-y-4">
          <ConnectorForms
            cards={cards}
            prefix="wiz"
            onTest={async (id, body) => {
              setSetupToken(token)
              const result = await testConnector(id, body)
              if (result.ok) toast(result.message || 'Connection ok')
              else toast(result.error || 'Connection failed', 'error')
            }}
            onSave={async (id, body) => {
              setSetupToken(token)
              await saveConnector(id, body)
              toast(`Saved ${id}`)
              await qc.invalidateQueries({ queryKey: ['connectors'] })
            }}
          />
        </div>
        <div className="mt-5 flex gap-2">
          <Button
            variant="primary"
            disabled={saveAll.isPending}
            onClick={() => saveAll.mutate(cards)}
          >
            Save connectors
          </Button>
          <Button onClick={onClose}>Open the queue</Button>
        </div>
      </div>
    </div>
  )
}
