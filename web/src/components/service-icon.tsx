import { useState } from 'react'

import type { Service } from '@/lib/api'

/** A few calm colours for the initial of a service without an icon. */
const tones = [
  'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200',
  'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
  'bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200',
  'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200',
]

/**
 * A service's icon: the PNG SGC drew from what the service serves, or else
 * its initial. The picture comes from SGC itself, never from the service.
 */
export function ServiceIcon({ service, size = 'size-9' }: { service: Service; size?: string }) {
  const [failed, setFailed] = useState(false)
  const label = service.title || service.name
  if (service.hasIcon && !failed) {
    return (
      <img
        src={`/api/services/${service.id}/icon?v=${encodeURIComponent(service.updatedAt)}`}
        alt=""
        className={`${size} shrink-0 rounded-lg object-contain`}
        onError={() => setFailed(true)}
      />
    )
  }
  const tone = tones[[...service.name].reduce((sum, c) => sum + c.charCodeAt(0), 0) % tones.length]
  return (
    <span
      aria-hidden="true"
      className={`${size} ${tone} flex shrink-0 items-center justify-center rounded-lg text-sm font-semibold uppercase`}
    >
      {label.slice(0, 1)}
    </span>
  )
}

/** Up, down or not probed, as a dot with words for screen readers. */
export function HealthDot({ service }: { service: Service }) {
  const { state, abandoned } = service.health
  const [tone, words] =
    !service.enabled || service.pending
      ? ['bg-muted-foreground/40', 'not in use']
      : state === 'up'
        ? ['bg-emerald-500', 'up']
        : state === 'down'
          ? [abandoned ? 'bg-muted-foreground' : 'bg-red-500', abandoned ? 'down for a long time' : 'down']
          : ['bg-muted-foreground/40', 'not probed']
  return (
    <span className="inline-flex items-center gap-1.5" title={words}>
      <span className={`size-2 rounded-full ${tone}`} aria-hidden="true" />
      <span className="sr-only">{words}</span>
    </span>
  )
}
