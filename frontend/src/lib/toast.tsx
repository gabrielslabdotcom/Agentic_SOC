import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

type ToastKind = 'ok' | 'error' | ''

interface ToastState {
  message: string
  kind: ToastKind
}

interface ToastApi {
  toast: (message: string, kind?: ToastKind) => void
}

const ToastContext = createContext<ToastApi>({ toast: () => undefined })

export function ToastProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ToastState | null>(null)

  const toast = useCallback((message: string, kind: ToastKind = '') => {
    setState({ message, kind })
    window.setTimeout(() => setState(null), 3500)
  }, [])

  const value = useMemo(() => ({ toast }), [toast])

  return (
    <ToastContext.Provider value={value}>
      {children}
      {state ? (
        <div
          role="status"
          className={`fixed bottom-5 right-5 z-[100] max-w-sm rounded-xl border px-3 py-2 shadow-lg ${
            state.kind === 'error'
              ? 'border-danger/30 bg-panel text-danger'
              : state.kind === 'ok'
                ? 'border-ok/30 bg-panel text-ok'
                : 'border-border bg-panel text-text'
          }`}
        >
          {state.message}
        </div>
      ) : null}
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}
