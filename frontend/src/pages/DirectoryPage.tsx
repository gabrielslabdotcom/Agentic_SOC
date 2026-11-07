import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { listAgents, listCases, unwrapList } from '../api/client'
import type { AgentRow } from '../api/types'
import { PriorityBadge, StatusBadge } from '../components/Badge'
import { Empty, Panel, PanelHead, Segmented } from '../components/ui'
import { actorFromCase, isOpenStatus } from '../lib/mapping'

export function DirectoryPage() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'endpoints' ? 'endpoints' : 'users'
  const [localTab, setLocalTab] = useState(tab)

  function setTab(id: string) {
    setLocalTab(id)
    setParams(id === 'endpoints' ? { tab: 'endpoints' } : {})
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="m-0 text-lg font-semibold tracking-tight">Directory</h2>
        <Segmented
          options={[
            { id: 'users', label: 'Users' },
            { id: 'endpoints', label: 'Endpoints' },
          ]}
          value={localTab}
          onChange={setTab}
        />
      </div>
      {localTab === 'users' ? <UsersPanel /> : <EndpointsPanel />}
    </div>
  )
}

function UsersPanel() {
  const cases = useQuery({
    queryKey: ['cases', 'users'],
    queryFn: () => listCases({ limit: 500 }),
  })

  const rows = useMemo(() => {
    const byUser = new Map<
      string,
      { open: number; total: number; latestId?: number; severity?: string }
    >()
    for (const c of cases.data?.cases || []) {
      const user = actorFromCase(c).user
      if (!user) continue
      const row = byUser.get(user) || { open: 0, total: 0 }
      row.total += 1
      if (isOpenStatus(c.status)) {
        row.open += 1
        row.latestId = c.id
        row.severity = c.severity
      } else if (!row.latestId) {
        row.latestId = c.id
      }
      byUser.set(user, row)
    }
    return [...byUser.entries()].sort(
      (a, b) => b[1].open - a[1].open || b[1].total - a[1].total,
    )
  }, [cases.data])

  return (
    <Panel>
      <PanelHead title="Users & accounts" />
      {cases.isLoading ? (
        <Empty>Loading…</Empty>
      ) : rows.length === 0 ? (
        <Empty>No users found on cases.</Empty>
      ) : (
        <table className="w-full border-collapse text-left text-sm">
          <thead className="text-xs text-muted">
            <tr>
              <th className="px-4 py-2.5 font-medium">User</th>
              <th className="px-4 py-2.5 font-medium">Open</th>
              <th className="px-4 py-2.5 font-medium">Total</th>
              <th className="px-4 py-2.5 font-medium">Priority</th>
              <th className="px-4 py-2.5 font-medium">Latest</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([user, info]) => (
              <tr key={user} className="border-t border-border hover:bg-elevated/50">
                <td className="px-4 py-2.5 font-mono">{user}</td>
                <td className="px-4 py-2.5">
                  <StatusBadge status={info.open ? 'open' : 'closed'} />
                  <span className="ml-2 text-xs text-muted">{info.open}</span>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{info.total}</td>
                <td className="px-4 py-2.5">
                  <PriorityBadge severity={info.severity} />
                </td>
                <td className="px-4 py-2.5">
                  {info.latestId ? (
                    <Link to={`/i/${info.latestId}`}>#{info.latestId}</Link>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}

function EndpointsPanel() {
  const agents = useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      const data = await listAgents(200)
      return unwrapList<AgentRow>(data, ['agents', 'data', 'affected_items'])
    },
  })
  const cases = useQuery({
    queryKey: ['cases', 'assets'],
    queryFn: () => listCases({ status: 'open', limit: 500 }),
  })

  const { rows, openByAgent, latestByAgent } = useMemo(() => {
    const openByAgent = new Map<string, number>()
    const latestByAgent = new Map<string, number>()
    for (const c of cases.data?.cases || []) {
      const agent = actorFromCase(c).agent
      if (!agent || !isOpenStatus(c.status)) continue
      openByAgent.set(agent, (openByAgent.get(agent) || 0) + 1)
      if (!latestByAgent.has(agent)) latestByAgent.set(agent, c.id)
    }
    const rows = [...(agents.data || [])]
    const known = new Set(rows.map((a) => String(a.name || '')))
    for (const name of openByAgent.keys()) {
      if (name && !known.has(name)) {
        rows.push({ name, status: 'unknown' })
        known.add(name)
      }
    }
    return { rows, openByAgent, latestByAgent }
  }, [agents.data, cases.data])

  return (
    <Panel>
      <PanelHead title="Assets & endpoints" />
      {agents.isLoading ? (
        <Empty>Loading agents…</Empty>
      ) : rows.length === 0 ? (
        <Empty>No agents returned from Wazuh.</Empty>
      ) : (
        <table className="w-full border-collapse text-left text-sm">
          <thead className="text-xs text-muted">
            <tr>
              <th className="px-4 py-2.5 font-medium">Asset</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">IP</th>
              <th className="px-4 py-2.5 font-medium">Open</th>
              <th className="px-4 py-2.5 font-medium">Jump</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const name = String(a.name || a.id || '—')
              const open = openByAgent.get(name) || 0
              const os =
                typeof a.os === 'string'
                  ? a.os
                  : a.os && typeof a.os === 'object'
                    ? a.os.name || a.os.uname || ''
                    : ''
              return (
                <tr key={name} className="border-t border-border hover:bg-elevated/50">
                  <td className="px-4 py-2.5">
                    <div className="font-mono text-sm">{name}</div>
                    {os ? <div className="text-xs text-muted">{os}</div> : null}
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusBadge
                      status={
                        String(a.status || '').toLowerCase() === 'active' ? 'open' : 'closed'
                      }
                    />
                    <span className="ml-2 text-xs text-muted">{String(a.status || '—')}</span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">{String(a.ip || '—')}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{open}</td>
                  <td className="px-4 py-2.5">
                    {latestByAgent.get(name) ? (
                      <Link to={`/i/${latestByAgent.get(name)}`}>Open</Link>
                    ) : (
                      '—'
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
