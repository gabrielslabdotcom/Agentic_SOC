import { useQuery } from '@tanstack/react-query'
import {
  Inbox,
  BookUser,
  Settings,
  ShieldOff,
  PanelLeftClose,
  PanelLeft,
  Activity,
  Search,
} from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { getSetup, getUiConfig } from '../api/client'
import { useAutoRefresh } from '../hooks/useAutoRefresh'
import { SetupWizard } from './SetupWizard'

const NAV = [
  { to: '/', label: 'Inbox', icon: Inbox, end: true },
  { to: '/search', label: 'Search', icon: Search },
  { to: '/directory', label: 'Directory', icon: BookUser },
  { to: '/exceptions', label: 'Exceptions', icon: ShieldOff },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const [wizardDismissed, setWizardDismissed] = useState(false)
  const { enabled, setEnabled } = useAutoRefresh()
  const config = useQuery({ queryKey: ['ui_config'], queryFn: getUiConfig })
  const setup = useQuery({
    queryKey: ['setup'],
    queryFn: getSetup,
    refetchOnWindowFocus: false,
  })

  const showWizard = !wizardDismissed && setup.data?.ready === false
  const ui = config.data
  const instance = ui?.instance || 'mac-local'

  return (
    <div className="flex min-h-screen">
      <aside
        className={`sticky top-0 flex h-screen shrink-0 flex-col border-r border-border bg-panel transition-[width] ${
          collapsed ? 'w-[68px]' : 'w-[200px]'
        }`}
      >
        <div className="flex items-center gap-2.5 px-3 py-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent">
            <Activity className="h-4 w-4" />
          </div>
          {!collapsed ? (
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold tracking-tight">Agentic SOC</div>
              <div className="truncate text-[0.7rem] text-muted">Analyst</div>
            </div>
          ) : null}
        </div>
        <nav className="flex-1 space-y-0.5 px-2">
          {NAV.map((item) => {
            const Icon = item.icon
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                title={item.label}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm no-underline transition-colors ${
                    isActive
                      ? 'bg-accent-soft font-medium text-accent'
                      : 'text-muted hover:bg-elevated hover:text-text'
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!collapsed ? <span className="truncate">{item.label}</span> : null}
              </NavLink>
            )
          })}
        </nav>
        <button
          type="button"
          className="m-2 flex items-center justify-center gap-2 rounded-lg px-2 py-2 text-muted hover:bg-elevated hover:text-text"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          {collapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          {!collapsed ? <span className="text-xs">Collapse</span> : null}
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-border bg-panel/90 backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-3">
            <div>
              <h1 className="m-0 text-base font-semibold tracking-tight">
                {ui?.app_name || 'Agentic SOC Analyst'}
              </h1>
              <p className="m-0 text-xs text-muted">Triage and resolve · containment stays manual</p>
            </div>
            <div className="flex flex-wrap items-center gap-4 text-xs text-muted">
              <span className="font-mono">
                {ui?.cases_db_path || '…'}
                {ui?.hostname ? ` · ${ui.hostname}` : ''}
              </span>
              {ui?.wazuh_dashboard_url ? (
                <a href={ui.wazuh_dashboard_url} target="_blank" rel="noopener noreferrer">
                  Wazuh
                </a>
              ) : null}
              <label className="inline-flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                Auto 15s
              </label>
            </div>
          </div>
          <div className="flex flex-wrap gap-2 px-6 pb-3">
            <div
              id="instance-banner"
              className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                instance === 'pop-live'
                  ? 'bg-accent-soft text-accent'
                  : 'bg-elevated text-muted'
              }`}
            >
              {ui?.banner || 'Identifying cases database…'}
            </div>
            <details className="rounded-lg bg-warn/10 px-3 py-1.5 text-xs text-warn">
              <summary className="cursor-pointer font-medium">
                Lab mode · decisions recorded only · no containment
              </summary>
              <p className="mb-0 mt-2 max-w-2xl leading-relaxed text-muted">
                Analyst outcomes only record the decision (case status + note). Containment is never
                executed from this UI. <strong>False Positive</strong>, <strong>Benign</strong>,{' '}
                <strong>Informational</strong>, and <strong>Duplicate</strong> skip the same rule_id
                + source IP for 14 days. <strong>Confirmed Compromise</strong> does not skip.
                Suppressions auto-close matching rules before Discord / Cursor. UFW deny and host
                isolation stay dry-run unless enabled on the host (still HITL, never automatic).
              </p>
            </details>
          </div>
        </header>

        <main className="page-enter flex-1 px-6 py-5">
          <Outlet />
        </main>
      </div>

      <SetupWizard open={!!showWizard} onClose={() => setWizardDismissed(true)} />
    </div>
  )
}
