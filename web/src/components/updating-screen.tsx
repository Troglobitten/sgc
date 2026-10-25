import { useEffect, useState } from 'react'

import { Logo } from '@/components/logo'
import { api, ApiError } from '@/lib/api'

/**
 * Shown while SGC updates itself. SGC is stopped for part of that time, so
 * failed requests are expected and simply retried. The update is over when
 * the updater has recorded the outcome of a new attempt.
 */
export function UpdatingScreen({
  previousAttempt,
  onFinished,
  onSignedOut,
}: {
  previousAttempt: number | null
  onFinished: () => void
  onSignedOut: () => void
}) {
  const [slow, setSlow] = useState(false)

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    const started = Date.now()
    const again = () => {
      if (Date.now() - started > 6 * 60 * 1000) setSlow(true)
      timer = setTimeout(check, 2_000)
    }
    const check = () =>
      api.update().then(
        (status) => {
          const last = status.lastUpdate
          if (!last || last.id === previousAttempt || last.state === 'running') return again()
          // A new version brings new interface files: load them. After a
          // rollback the page is still right; the dashboard shows what happened.
          if (last.state === 'succeeded') window.location.reload()
          else onFinished()
        },
        (error) => {
          if (error instanceof ApiError && error.status === 401) onSignedOut()
          else again()
        },
      )
    timer = setTimeout(check, 2_000)
    return () => clearTimeout(timer)
  }, [previousAttempt, onFinished, onSignedOut])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-4 bg-muted/40 p-4 text-center">
      <Logo className="size-14 animate-spin [animation-duration:6s]" />
      <h1 className="text-base font-medium">Updating SGC</h1>
      <p className="max-w-xs text-sm text-muted-foreground">
        {slow
          ? 'This is taking longer than expected. You can reload the page; if SGC stays unreachable, check it over SSH with: sudo sgc update --check'
          : 'This takes about a minute. The page comes back by itself.'}
      </p>
    </div>
  )
}
