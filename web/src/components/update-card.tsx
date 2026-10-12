import { useCallback, useEffect, useId, useState } from 'react'
import { CircleCheck, RefreshCw, TriangleAlert, X } from 'lucide-react'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  api,
  errorMessage,
  type MaintenanceStatus,
  type UpdateOutcome,
  type UpdateStatus,
} from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'

const refreshInterval = 60_000

/** What "install by itself" means right now, in one line. */
function autoUpdateHint(m: MaintenanceStatus): string {
  if (m.autoUpdate && !m.enabled) {
    return 'The maintenance window is switched off (System page), so nothing installs by itself yet.'
  }
  if (m.autoUpdate && m.updateVersion && m.updateInstallableFrom) {
    const from = new Date(m.updateInstallableFrom)
    return from.getTime() <= Date.now()
      ? `SGC ${m.updateVersion} installs in the next window, from ${m.start}.`
      : `SGC ${m.updateVersion} installs in the first window after ${from.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}.`
  }
  return `A new version installs once this device has known it for ${m.updateWaitDays} days. The button installs it sooner.`
}
const dismissedKey = 'sgc-dismissed-update'

/**
 * What SGC knows about newer versions of itself, and the way to install one.
 *
 * onUpdating is called once an update has started, with the number of the
 * previous attempt, so the caller can tell when this one has finished.
 */
export function UpdateCard({
  onError,
  onUpdating,
}: {
  onError: (error: unknown) => void
  onUpdating: (previousAttempt: number | null) => void
}) {
  const [status, setStatus] = useState<UpdateStatus | null>(null)
  const [checking, setChecking] = useState(false)
  const [dialogOpen, setDialogOpen] = useState(false)
  const switchId = useId()
  // The maintenance window, for the "install by itself" switch.
  const [maintenance, setMaintenance] = useState<MaintenanceStatus | null>(null)
  const autoId = useId()

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.update().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
      api.maintenance().then(
        (m) => !stopped && setMaintenance(m),
        (e) => !stopped && onError(e),
      )
    }
    load()
    const timer = setInterval(load, refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError])

  const checkNow = useCallback(async () => {
    setChecking(true)
    try {
      setStatus(await api.checkForUpdate())
    } catch (e) {
      onError(e)
    } finally {
      setChecking(false)
    }
  }, [onError])

  async function setAutoCheck(enabled: boolean) {
    try {
      setStatus(await api.setAutoCheck(enabled))
      // Switching the daily check off takes "install by itself" with it.
      setMaintenance(await api.maintenance())
    } catch (e) {
      onError(e)
    }
  }

  async function setAutoUpdate(enabled: boolean) {
    try {
      setMaintenance(await api.setAutoUpdate(enabled))
      // Switching it on switches the daily check on as well.
      setStatus(await api.update())
    } catch (e) {
      onError(e)
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">SGC updates</h2>

        {status === null ? (
          <p className="text-sm text-muted-foreground">…</p>
        ) : (
          <>
            <LastOutcome outcome={status.lastUpdate} />

            {status.updateAvailable ? (
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-medium">SGC {status.latest} is available</p>
                  <p className="text-sm text-muted-foreground">You have {status.current}.</p>
                </div>
                <Button onClick={() => setDialogOpen(true)}>View update</Button>
              </div>
            ) : (
              <p className="text-sm">
                {status.checkedAt
                  ? `SGC ${status.current} is the newest version.`
                  : `You have SGC ${status.current}.`}
              </p>
            )}

            {status.checkError && (
              // A check that keeps failing must not look like "up to date".
              <p className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-400">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                <span>
                  Couldn't check for updates
                  {status.checkFailedAt ? ` (${formatTimeAgo(status.checkFailedAt)})` : ''}:{' '}
                  {status.checkError}.
                </span>
              </p>
            )}

            {maintenance && (
              <div className="flex flex-col gap-1 border-t pt-3">
                <div className="flex items-center gap-2">
                  <Switch
                    id={autoId}
                    checked={maintenance.autoUpdate}
                    onCheckedChange={setAutoUpdate}
                  />
                  <Label htmlFor={autoId} className="font-normal">
                    Install by itself in the maintenance window
                  </Label>
                </div>
                <p className="text-xs text-muted-foreground">{autoUpdateHint(maintenance)}</p>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t pt-3">
              <div className="flex items-center gap-2">
                <Switch id={switchId} checked={status.autoCheck} onCheckedChange={setAutoCheck} />
                <Label htmlFor={switchId} className="font-normal">
                  Check daily
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {status.checkedAt
                    ? `Checked ${formatTimeAgo(status.checkedAt)}`
                    : 'Not checked yet'}
                </span>
                <Button variant="outline" size="sm" onClick={checkNow} disabled={checking}>
                  <RefreshCw className={cn(checking && 'animate-spin')} />
                  Check now
                </Button>
              </div>
            </div>

            <UpdateDialog
              status={status}
              open={dialogOpen}
              onOpenChange={setDialogOpen}
              onStarted={() => onUpdating(status.lastUpdate?.id ?? null)}
            />
          </>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * How the last update ended. A success is mentioned quietly for a day; an
 * update that was rolled back or failed stays until dismissed.
 */
function LastOutcome({ outcome }: { outcome: UpdateOutcome | null }) {
  const [dismissed, setDismissed] = useState(() => readDismissed())
  // The time this card appeared. Read once, so that drawing the card always
  // gives the same result for the same data.
  const [shownAt] = useState(() => Date.now())

  if (!outcome || outcome.state === 'running' || !outcome.finishedAt) return null

  if (outcome.state === 'succeeded') {
    const age = shownAt - new Date(outcome.finishedAt).getTime()
    if (age > 24 * 60 * 60 * 1000) return null
    return (
      <p className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
        <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        {outcome.message}
      </p>
    )
  }

  if (dismissed === outcome.id) return null
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
    >
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span className="flex-1">{outcome.message}</span>
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label="Dismiss"
        onClick={() => {
          writeDismissed(outcome.id)
          setDismissed(outcome.id)
        }}
      >
        <X />
      </Button>
    </div>
  )
}

function readDismissed(): number | null {
  try {
    const stored = localStorage.getItem(dismissedKey)
    return stored === null ? null : Number(stored)
  } catch {
    return null
  }
}

function writeDismissed(id: number) {
  try {
    localStorage.setItem(dismissedKey, String(id))
  } catch {
    // Dismissed for this visit only.
  }
}

function UpdateDialog({
  status,
  open,
  onOpenChange,
  onStarted,
}: {
  status: UpdateStatus
  open: boolean
  onOpenChange: (open: boolean) => void
  onStarted: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function install() {
    setBusy(true)
    setError(null)
    try {
      await api.installUpdate(status.latest)
      onOpenChange(false)
      onStarted()
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const notes = status.notes.trim()
  return (
    <AlertDialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <AlertDialogContent className="max-h-[calc(100svh-2rem)] overflow-y-auto data-[size=default]:sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle>Update to SGC {status.latest}?</AlertDialogTitle>
          <AlertDialogDescription>
            SGC restarts during the update. If the new version doesn't start correctly, SGC goes
            back to {status.current} by itself.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {notes && (
          // Shown as plain text on purpose: release notes come from the
          // network and are never interpreted as HTML.
          <div className="max-h-60 overflow-y-auto rounded-lg bg-muted px-3 py-2 text-sm whitespace-pre-wrap">
            {notes}
          </div>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Not now</AlertDialogCancel>
          <AlertDialogAction onClick={install} disabled={busy}>
            {busy ? 'Downloading…' : 'Update now'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
