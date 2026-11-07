import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { createElement } from 'react'

interface AutoRefreshApi {
  enabled: boolean
  setEnabled: (v: boolean) => void
  intervalMs: number
}

const AutoRefreshContext = createContext<AutoRefreshApi>({
  enabled: true,
  setEnabled: () => undefined,
  intervalMs: 15000,
})

export function AutoRefreshProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabled] = useState(true)
  const value = useMemo(
    () => ({ enabled, setEnabled, intervalMs: 15000 }),
    [enabled],
  )
  return createElement(AutoRefreshContext.Provider, { value }, children)
}

export function useAutoRefresh() {
  return useContext(AutoRefreshContext)
}

export function usePolling(refetch: () => void, enabledOverride?: boolean) {
  const { enabled, intervalMs } = useAutoRefresh()
  const on = enabledOverride ?? enabled
  useEffect(() => {
    if (!on) return
    const id = window.setInterval(() => refetch(), intervalMs)
    return () => window.clearInterval(id)
  }, [on, intervalMs, refetch])
}
