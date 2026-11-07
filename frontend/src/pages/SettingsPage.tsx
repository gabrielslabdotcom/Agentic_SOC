import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  getSetupToken,
  listConnectors,
  saveConnector,
  setSetupToken,
  testConnector,
} from '../api/client'
import { ConnectorForms } from '../components/ConnectorForms'
import { Input, Panel, PanelHead } from '../components/ui'
import { useToast } from '../lib/toast'

export function SettingsPage() {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [token, setToken] = useState(getSetupToken())
  const connectors = useQuery({ queryKey: ['connectors'], queryFn: listConnectors })

  return (
    <Panel>
      <PanelHead title="Settings · Connectors" />
      <div className="space-y-4 p-5">
        <p className="m-0 text-sm text-muted">
          API keys stay on this host. After you save, the form shows a masked hint instead of the
          secret. Paste the setup token below before Save — it protects connector writes and lives in{' '}
          <code>data/setup_token</code>. From inside Docker, use the host LAN address or{' '}
          <code>host.docker.internal</code> for Wazuh.
        </p>
        <div>
          <label htmlFor="connectors-token" className="mb-1 block text-sm text-muted">
            Setup token (required to save)
          </label>
          <Input
            id="connectors-token"
            type="password"
            className="w-full max-w-md"
            autoComplete="off"
            value={token}
            onChange={(e) => {
              setToken(e.target.value)
              setSetupToken(e.target.value)
            }}
          />
          {!token.trim() ? (
            <p className="mb-0 mt-1 text-xs text-warn">
              Empty setup token — Save will be rejected until this field is filled.
            </p>
          ) : null}
        </div>
        <div className="space-y-4">
          <ConnectorForms
            cards={connectors.data?.connectors || []}
            prefix="page"
            onSave={async (id, body) => {
              setSetupToken(token)
              if (!token.trim()) {
                toast('Paste the setup token above before saving', 'error')
                throw new Error('setup token required')
              }
              try {
                await saveConnector(id, body)
                toast(`Saved ${id}`)
                await qc.invalidateQueries({ queryKey: ['connectors'] })
                await qc.invalidateQueries({ queryKey: ['ui_config'] })
                await qc.invalidateQueries({ queryKey: ['setup'] })
              } catch (err) {
                const msg = err instanceof Error ? err.message : 'Save failed'
                toast(msg, 'error')
                throw err
              }
            }}
            onTest={async (id, body) => {
              setSetupToken(token)
              if (!token.trim()) {
                toast('Paste the setup token above before testing', 'error')
                return
              }
              try {
                const result = await testConnector(id, body)
                if (result.ok) toast(result.message || 'Connection ok')
                else toast(result.error || 'Connection failed', 'error')
              } catch (err) {
                const msg = err instanceof Error ? err.message : 'Test failed'
                toast(msg, 'error')
              }
            }}
          />
        </div>
      </div>
    </Panel>
  )
}
