import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { HashRouter, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { AppLayout } from './components/AppLayout'
import { AutoRefreshProvider } from './hooks/useAutoRefresh'
import { ToastProvider } from './lib/toast'
import { DirectoryPage } from './pages/DirectoryPage'
import { ExceptionsPage } from './pages/ExceptionsPage'
import { InboxPage } from './pages/InboxPage'
import { InvestigationPage } from './pages/InvestigationPage'
import { SearchPage } from './pages/SearchPage'
import { SettingsPage } from './pages/SettingsPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
})

function RedirectInvestigation() {
  const { id } = useParams()
  return <Navigate to={`/i/${id}`} replace />
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AutoRefreshProvider>
          <HashRouter>
            <Routes>
              <Route element={<AppLayout />}>
                <Route index element={<InboxPage />} />
                <Route path="i/:id" element={<InvestigationPage />} />
                <Route path="search" element={<SearchPage />} />
                <Route path="directory" element={<DirectoryPage />} />
                <Route path="exceptions" element={<ExceptionsPage />} />
                <Route path="settings" element={<SettingsPage />} />
                {/* Legacy redirects */}
                <Route path="investigations" element={<Navigate to="/" replace />} />
                <Route path="investigations/:id" element={<RedirectInvestigation />} />
                <Route path="users" element={<Navigate to="/directory" replace />} />
                <Route path="assets" element={<Navigate to="/directory?tab=endpoints" replace />} />
                <Route path="rules" element={<Navigate to="/exceptions" replace />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </HashRouter>
        </AutoRefreshProvider>
      </ToastProvider>
    </QueryClientProvider>
  )
}
