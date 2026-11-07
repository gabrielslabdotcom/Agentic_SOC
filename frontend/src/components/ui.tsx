import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'

export function Panel({
  children,
  className = '',
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div className={`rounded-xl border border-border bg-panel ${className}`}>{children}</div>
  )
}

export function PanelHead({
  title,
  children,
}: {
  title: string
  children?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
      <h2 className="m-0 text-sm font-semibold tracking-tight text-text">{title}</h2>
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  )
}

export function Button({
  variant = 'default',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
}) {
  const base =
    'cursor-pointer rounded-lg border px-3 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45'
  const variants: Record<string, string> = {
    default: 'border-border bg-panel text-text hover:bg-elevated',
    primary: 'border-accent bg-accent text-white hover:bg-accent-dim',
    danger: 'border-danger/30 bg-danger/10 text-danger hover:bg-danger/15',
    ghost: 'border-transparent bg-transparent text-muted hover:bg-elevated hover:text-text',
  }
  return (
    <button className={`${base} ${variants[variant]} ${className}`} {...props} />
  )
}

export function Input({
  className = '',
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`rounded-lg border border-border bg-panel px-2.5 py-2 text-text outline-none focus:border-accent ${className}`}
      {...props}
    />
  )
}

export function Select({
  className = '',
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`rounded-lg border border-border bg-panel px-2.5 py-2 text-text outline-none focus:border-accent ${className}`}
      {...props}
    />
  )
}

export function TextArea({
  className = '',
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`w-full min-h-[88px] resize-y rounded-lg border border-border bg-panel px-2.5 py-2 font-mono text-sm text-text outline-none focus:border-accent ${className}`}
      {...props}
    />
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-4 py-12 text-center text-sm text-muted">{children}</div>
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-2 mt-0 text-xs font-semibold uppercase tracking-[0.06em] text-muted">
      {children}
    </h3>
  )
}

export function Segmented({
  options,
  value,
  onChange,
}: {
  options: { id: string; label: string }[]
  value: string
  onChange: (id: string) => void
}) {
  return (
    <div className="inline-flex rounded-lg border border-border bg-elevated p-0.5">
      {options.map((opt) => (
        <button
          key={opt.id}
          type="button"
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            value === opt.id
              ? 'bg-panel text-text shadow-sm'
              : 'bg-transparent text-muted hover:text-text'
          }`}
          onClick={() => onChange(opt.id)}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
