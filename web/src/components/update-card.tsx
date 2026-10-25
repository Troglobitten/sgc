import { useCallback, useEffect, useId, useState, type ReactNode } from 'react'
import { CircleCheck, RefreshCw, X } from 'lucide-react'

import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
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
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  api,
  errorMessage,
  type MaintenanceStatus,
  type UpdateOutcome,
  type UpdateStatus,
} from '@/lib/api'
import { formatDate, formatTimeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'

const refreshInterval = 60_000

/** What "install by itself" means right now, in one line. */
function autoUpdateHint(m: MaintenanceStatus): string {
  if (m.autoUpdate && !m.enabled) {
    return 'The maintenance window is switched off, so nothing installs by itself yet.'
  }
  if (m.autoUpdate && m.updateVersion && m.updateInstallableFrom) {
    const from = new Date(m.updateInstallableFrom)
    return from.getTime() <= Date.now()
      ? `SGC ${m.updateVersion} installs in the next window, from ${m.start}.`
      : `SGC ${m.updateVersion} installs in the first window after ${formatDate(from)}.`
  }
  if (m.autoUpdate) return `By themselves in the maintenance window, once this device has known them for ${m.updateWaitDays} days.`
  return 'When you install them.'
}
const dismissedKey = 'sgc-dismissed-update'

/** SGC's update state and the maintenance window, loaded and kept fresh. */
function useUpdateState(onError: (error: unknown) => void) {
  const [status, setStatus] = useState<UpdateStatus | null>(null)
  const [maintenance, setMaintenance] = useState<MaintenanceStatus | null>(null)
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
  return { status, setStatus, maintenance, setMaintenance }
}

/**
 * The dashboard's part: there only when there is something to do, a newer
 * version or an update that went wrong. Everything else about SGC's updates
 * is on the System page, under Updates.
 *
 * onUpdating is called once an update has started, with the number of the
 * previous attempt, so the caller can tell when this one has finished.
 */
export function AvailableUpdateCard({
  onError,
  onUpdating,
}: {
  onError: (error: unknown) => void
  onUpdating: (previousAttempt: number | null) => void
}) {
  const { status, maintenance } = useUpdateState(onError)
  const [dialogOpen, setDialogOpen] = useState(false)
  if (!status) return null
  if (!status.updateAvailable) {
    // A rollback or failure stays in view until dismissed; a success for a day.
    return <LastOutcome outcome={status.lastUpdate} framed />
  }
  return (
    <SettingCard title={`SGC ${status.latest} is out`} status={<StatusBadge tone="warn">You have {status.current}</StatusBadge>}>
      <LastOutcome outcome={status.lastUpdate} />
      {maintenance && <p className="text-sm text-muted-foreground">{autoUpdateHint(maintenance)}</p>}
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => setDialogOpen(true)}>What’s new, and install</Button>
      </div>
      <UpdateDialog
        status={status}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onStarted={() => onUpdating(status.lastUpdate?.id ?? null)}
      />
    </SettingCard>
  )
}

/** The System page's part: the version, how new versions arrive, and the way to install one. */
export function SgcUpdatesCard({
  onError,
  onUpdating,
}: {
  onError: (error: unknown) => void
  onUpdating: (previousAttempt: number | null) => void
}) {
  const { status, setStatus, maintenance, setMaintenance } = useUpdateState(onError)
  const [checking, setChecking] = useState(false)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [changing, setChanging] = useState(false)
  const switchId = useId()
  const autoId = useId()

  const checkNow = useCallback(async () => {
    setChecking(true)
    try {
      setStatus(await api.checkForUpdate())
    } catch (e) {
      onError(e)
    } finally {
      setChecking(false)
    }
  }, [onError, setStatus])

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

  if (status === null) {
    return (
      <SettingCard title="SGC">
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
    )
  }

  const badge = status.updateAvailable ? (
    <StatusBadge tone="warn">{status.latest} is out</StatusBadge>
  ) : status.checkError ? (
    <StatusBadge tone="warn">Could not look</StatusBadge>
  ) : status.checkedAt ? (
    <StatusBadge tone="ok">{status.current}, the newest</StatusBadge>
  ) : (
    <StatusBadge tone="muted">{status.current}</StatusBadge>
  )

  return (
    <SettingCard title="SGC" status={badge}>
      <LastOutcome outcome={status.lastUpdate} />
      {status.checkError && (
        // A check that keeps failing must not look like "up to date".
        <Warning>
          <p>
            SGC could not look for a new version
            {status.checkFailedAt ? ` (${formatTimeAgo(status.checkFailedAt)})` : ''}: {status.checkError}.
          </p>
        </Warning>
      )}
      {status.updateAvailable && (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm">
            SGC {status.latest} is out; you have {status.current}.
          </p>
          <Button onClick={() => setDialogOpen(true)}>What’s new, and install</Button>
        </div>
      )}
      <Facts
        items={[
          ['New versions', maintenance ? autoUpdateHint(maintenance) : '…'],
          [
            'Last looked',
            status.autoCheck
              ? status.checkedAt
                ? `${formatTimeAgo(status.checkedAt)} (every day)`
                : 'not yet (every day)'
              : status.checkedAt
                ? `${formatTimeAgo(status.checkedAt)} (only when you ask)`
                : 'only when you ask',
          ],
        ]}
      />
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={checkNow} disabled={checking}>
          <RefreshCw className={cn(checking && 'animate-spin')} />
          Look now
        </Button>
        {!changing && (
          <Button variant="outline" onClick={() => setChanging(true)}>
            Change
          </Button>
        )}
      </div>
      {changing && maintenance && (
        <div className="flex flex-col gap-3 border-t pt-3">
          <div className="flex items-start gap-2">
            <Switch id={autoId} checked={maintenance.autoUpdate} onCheckedChange={setAutoUpdate} />
            <Label htmlFor={autoId} className="flex flex-col items-start gap-0.5 font-normal">
              Install new versions by themselves in the maintenance window
              <span className="text-xs text-muted-foreground">
                A new version waits until this device has known it for {maintenance.updateWaitDays} days, so that a faulty
                release can be withdrawn first.
              </span>
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id={switchId} checked={status.autoCheck} onCheckedChange={setAutoCheck} />
            <Label htmlFor={switchId} className="font-normal">
              Look for a new version every day
            </Label>
          </div>
          <div>
            <Button variant="ghost" size="sm" onClick={() => setChanging(false)}>
              Done
            </Button>
          </div>
        </div>
      )}
      <More>
        <p>
          A new version is checked against SGC’s signature before it is installed. If it does not start correctly, SGC
          goes back to the version before by itself. Over SSH: <code>sudo sgc update</code>.
        </p>
      </More>
      <UpdateDialog
        status={status}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onStarted={() => onUpdating(status.lastUpdate?.id ?? null)}
      />
    </SettingCard>
  )
}

/**
 * How the last update ended. A success is mentioned quietly for a day; an
 * update that was rolled back or failed stays until dismissed.
 */
function LastOutcome({ outcome, framed = false }: { outcome: UpdateOutcome | null; framed?: boolean }) {
  const [dismissed, setDismissed] = useState(() => readDismissed())
  // The time this card appeared. Read once, so that drawing the card always
  // gives the same result for the same data.
  const [shownAt] = useState(() => Date.now())

  if (!outcome || outcome.state === 'running' || !outcome.finishedAt) return null
  // On the dashboard the outcome is a card of its own, there only while it is news.
  const frame = (content: ReactNode) => (framed ? <SettingCard title="SGC updates">{content}</SettingCard> : content)

  if (outcome.state === 'succeeded') {
    const age = shownAt - new Date(outcome.finishedAt).getTime()
    if (age > 24 * 60 * 60 * 1000) return null
    return frame(
      <p className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
        <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        {outcome.message}
      </p>,
    )
  }

  if (dismissed === outcome.id) return null
  return frame(
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
    >
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
    </div>,
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
