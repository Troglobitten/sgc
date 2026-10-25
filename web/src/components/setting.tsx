import { useId, useState, type ReactNode } from 'react'
import { ChevronDown, Info, TriangleAlert } from 'lucide-react'

import { Card, CardContent } from '@/components/ui/card'
import { toneDot, toneText, type Tone } from '@/lib/tone'
import { cn } from '@/lib/utils'

/*
 * The parts every settings card is made of (docs/design.md §13):
 *
 *   - a header: the name, and the state in a word or two on the right;
 *   - what matters now: one or two sentences, a list, the buttons;
 *   - warnings, which are always in view;
 *   - "More about this": the explanation, folded away until asked for.
 *
 * A card shows its whole explanation only while it is off or not set up,
 * when the owner needs it to decide; once it is set up the explanation
 * moves behind "More about this".
 */

/** A state in a word or two, with a dot in its colour. */
export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={cn('inline-flex shrink-0 items-center gap-1.5 text-sm font-medium', toneText[tone])}>
      <span className={cn('size-2 rounded-full', toneDot[tone])} aria-hidden="true" />
      {children}
    </span>
  )
}

/** The dot alone, for lists. */
export function StatusDot({ tone, label }: { tone: Tone; label?: string }) {
  return (
    <span
      className={cn('inline-block size-2 shrink-0 rounded-full', toneDot[tone])}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  )
}

/** A settings card: name and state on top, then what matters now. */
export function SettingCard({
  title,
  status,
  children,
  className,
  id,
}: {
  title: ReactNode
  status?: ReactNode
  children: ReactNode
  className?: string
  id?: string
}) {
  const headingId = useId()
  return (
    <Card id={id} className={className} aria-labelledby={headingId} role="region">
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <h2 id={headingId} className="text-[15px] font-semibold">
            {title}
          </h2>
          {status}
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

/** A warning: always in view, never folded away. */
export function Warning({ children, tone = 'warn' }: { children: ReactNode; tone?: 'warn' | 'bad' }) {
  return (
    <div
      role="status"
      className={cn(
        'flex items-start gap-2 rounded-lg px-3 py-2 text-sm',
        tone === 'bad'
          ? 'bg-destructive/10 text-destructive'
          : 'bg-amber-500/10 text-amber-800 dark:text-amber-300',
      )}
    >
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div className="flex min-w-0 flex-1 flex-col gap-2">{children}</div>
    </div>
  )
}

/** The explanation, folded away until asked for. */
export function More({ label = 'More about this', children }: { label?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const contentId = useId()
  return (
    <div className="flex flex-col gap-2">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex w-fit items-center gap-1.5 rounded-sm text-[13px] text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        <Info className="size-3.5" aria-hidden="true" />
        {label}
        <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} aria-hidden="true" />
      </button>
      {open && (
        <div id={contentId} className="flex max-w-prose flex-col gap-2 text-[13px] text-muted-foreground">
          {children}
        </div>
      )}
    </div>
  )
}

/** A set-up thing in a few lines: what, where, when. */
export function Facts({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-5 gap-y-1 text-sm">
      {items.map(([term, value], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{term}</dt>
          <dd className="break-words">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** A page's own title, with a line under it saying what the page is for. */
export function PageTitle({ title, lead, children }: { title: string; lead?: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="flex flex-col gap-0.5">
        <h1 className="text-xl font-semibold">{title}</h1>
        {lead && <p className="text-sm text-muted-foreground">{lead}</p>}
      </div>
      {children}
    </div>
  )
}
