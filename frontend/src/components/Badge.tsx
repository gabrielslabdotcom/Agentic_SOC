export function Badge({
  children,
  className = '',
}: {
  children: React.ReactNode
  className?: string
}) {
  if (!children) return null
  return (
    <span
      className={`inline-block rounded-md px-1.5 py-0.5 font-mono text-[0.7rem] font-medium uppercase tracking-wide ${className}`}
    >
      {children}
    </span>
  )
}

export function PriorityBadge({ severity }: { severity?: string | null }) {
  const s = (severity || '').toLowerCase()
  const tone =
    s === 'critical' || s === 'high'
      ? 'bg-danger/12 text-danger'
      : s === 'medium'
        ? 'bg-warn/12 text-warn'
        : 'bg-elevated text-muted'
  const label =
    s === 'critical'
      ? 'Critical'
      : s === 'high'
        ? 'High'
        : s === 'medium'
          ? 'Medium'
          : s === 'low'
            ? 'Low'
            : 'Info'
  return <Badge className={tone}>{label}</Badge>
}

export function StatusBadge({ status }: { status?: string | null }) {
  const s = (status || 'open').toLowerCase()
  const open = s === 'open' || s === 'pending'
  const tone = open
    ? 'border border-accent/30 bg-accent-soft text-accent'
    : s === 'confirmed_compromise' || s === 'approved'
      ? 'border border-danger/30 bg-danger/10 text-danger'
      : s === 'benign'
        ? 'border border-ok/30 bg-ok/10 text-ok'
        : 'border border-border bg-panel text-muted'
  const label = open ? 'Open' : s === 'auto_closed' ? 'Auto-closed' : 'Closed'
  return <Badge className={tone}>{label}</Badge>
}

export function DispositionBadge({ disposition }: { disposition?: string | null }) {
  if (!disposition) return null
  const d = disposition.toLowerCase()
  const tone =
    d.includes('compromise') || d.includes('true_positive')
      ? 'border border-danger/30 text-danger'
      : d.includes('suspicious')
        ? 'border border-warn/30 text-warn'
        : d.includes('benign')
          ? 'border border-ok/30 text-ok'
          : 'border border-border text-muted'
  return <Badge className={tone}>{disposition.replace(/_/g, ' ')}</Badge>
}
