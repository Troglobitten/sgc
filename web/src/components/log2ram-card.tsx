import { useEffect, useId, useState, type ReactNode } from 'react'

import { FormError } from '@/components/auth-card'
import { More, SettingCard, StatusBadge, Warning } from '@/components/setting'
import {
  AlertDialog,
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
import { api, errorMessage, type Log2ramStatus } from '@/lib/api'

const refreshInterval = 15_000

const megabytes = (bytes: number) => `${Math.round(bytes / (1024 * 1024))} MB`

/**
 * Logs in memory (log2ram), for a device that runs from an SD card.
 *
 * It comes with SGC, switched off. Whether the device runs from an SD card
 * is for the owner to say; SGC does not try to find out. Switching on or off
 * takes effect when the device restarts, and the card says in which of the
 * in-between states the device is.
 */
export function Log2ramCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<Log2ramStatus | null>(null)
  const [asking, setAsking] = useState(false)
  const [busy, setBusy] = useState(false)
  const switchId = useId()

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.log2ram().then(
        (s) => !stopped && setStatus(s),
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

  const title = 'Logs in memory'
  if (status === null) {
    return (
      <SettingCard title={title}>
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
    )
  }

  // Switching off changes nothing until the restart and removes nothing, so
  // it is done at once. Switching on cuts the system journal down first,
  // which is said before it happens.
  async function onSwitch(checked: boolean) {
    if (checked) {
      setAsking(true)
      return
    }
    setBusy(true)
    try {
      setStatus(await api.setLog2ramEnabled(false))
    } catch (e) {
      onError(e)
    } finally {
      setBusy(false)
    }
  }

  const space = `${megabytes(status.usedBytes)} of ${megabytes(status.sizeBytes)}`
  const largest = status.largest.map((e) => `${e.name} (${megabytes(e.bytes)})`).join(', ')

  const badge = status.active ? (
    <StatusBadge tone={status.nearlyFull ? 'warn' : 'ok'}>In memory · {space}</StatusBadge>
  ) : status.enabled ? (
    <StatusBadge tone="muted">On from the next restart</StatusBadge>
  ) : (
    <StatusBadge tone="muted">Off</StatusBadge>
  )

  return (
    <SettingCard title={title} status={badge}>

        {!status.available && (
          <Notice>The device could not be asked about log2ram just now.</Notice>
        )}

        <div className="flex items-center gap-2">
          <Switch
            id={switchId}
            checked={status.enabled}
            disabled={!status.available || busy}
            onCheckedChange={onSwitch}
          />
          <Label htmlFor={switchId} className="font-normal">
            This device runs from an SD card
          </Label>
        </div>

        {!status.enabled && (
          <p className="text-sm">
            For a device on an SD card: the logs are written to the card once a day instead of all the time, which spares
            the card.
          </p>
        )}

        {status.restartNeeded && status.enabled && (
          <Notice>
            Switched on. It takes effect when the device restarts (Restart, below).
          </Notice>
        )}
        {status.restartNeeded && !status.enabled && (
          <Notice>Switched off. The logs stay in memory until the device restarts.</Notice>
        )}
        {status.startFailed && (
          <Notice>
            At the last start-up the logs did not fit in memory ({megabytes(status.usedBytes)} of
            logs, {megabytes(status.sizeBytes)} of space), so they stayed on the disk. Nothing is
            lost. The largest in the log folder: {largest}. Make room there and restart the
            device, or switch this off.
          </Notice>
        )}
        {status.nearlyFull && (
          <Notice>
            The space in memory is almost full. The device keeps working when it is full, but
            log entries get lost, and after a restart the logs stay on the disk until there is
            room again. The largest in the log folder: {largest}.
          </Notice>
        )}
        {status.wanted && (
          <Notice>This was switched on on the device this SGC was restored from.</Notice>
        )}

        <More>
          <p>
            Switched on, the logs are kept in memory (log2ram, from Debian) and written to the card once a day and at
            shutdown, instead of all the time. After a power cut the log entries since the last write are gone.
            {!status.installed && ' Switching on installs log2ram first.'}
          </p>
        </More>

        {asking && (
          <SwitchOnDialog
            status={status}
            onClose={() => setAsking(false)}
            onDone={(next) => {
              setAsking(false)
              setStatus(next)
            }}
          />
        )}
    </SettingCard>
  )
}

function Notice({ children }: { children: ReactNode }) {
  return <Warning>{children}</Warning>
}

/** Says what switching on means, then does it. A refusal is shown here. */
function SwitchOnDialog({
  status,
  onClose,
  onDone,
}: {
  status: Log2ramStatus
  onClose: () => void
  onDone: (next: Log2ramStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function act() {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.setLog2ramEnabled(true))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Keep the logs in memory?</AlertDialogTitle>
          <AlertDialogDescription>
            From the next restart the logs live in up to {megabytes(status.sizeBytes)} of this
            device&apos;s memory and are written to the card once a day and at shutdown. So that
            they fit, SGC limits the system journal to {megabytes(status.sizeBytes / 4)} now and
            removes older entries beyond that. If the logs of this device do not fit, SGC says
            so and changes nothing.
            {!status.installed && ' log2ram is installed from Debian first.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={act} disabled={busy}>
            {busy ? 'Switching on…' : 'Switch on'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
