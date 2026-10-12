import { useEffect, useId, useState, type ReactNode } from 'react'
import { TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type MaintenanceStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

const refreshInterval = 30_000

/**
 * The maintenance window: a daily period in which SGC may do by itself what
 * interrupts the device. That is restarting it when an installed update
 * needs a restart, and installing SGC's own updates if the owner allowed
 * that on the dashboard. Off until switched on.
 */
export function MaintenanceCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<MaintenanceStatus | null>(null)
  // What is in the form; null until the owner changes something.
  const [draft, setDraft] = useState<{ enabled: boolean; start: string; end: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const switchId = useId()
  const startId = useId()
  const endId = useId()

  useEffect(() => {
    let stopped = false
    const load = () =>
      api.maintenance().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
    load()
    const timer = setInterval(load, refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError])

  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">Maintenance window</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  const form = draft ?? { enabled: status.enabled, start: status.start, end: status.end }
  const changed =
    form.enabled !== status.enabled || form.start !== status.start || form.end !== status.end

  async function save() {
    setBusy(true)
    setError(null)
    try {
      setStatus(await api.setMaintenance(form.enabled, form.start, form.end))
      setDraft(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">Maintenance window</h2>
          <span className="text-sm font-medium">{status.enabled ? 'On' : 'Off'}</span>
        </div>
        <p className="text-sm">
          A time of day at which SGC may restart the device by itself, if an installed update
          needs a restart. Outside it, and while it is off, nothing restarts by itself.
        </p>

        <div className="flex items-center gap-2">
          <Switch
            id={switchId}
            checked={form.enabled}
            onCheckedChange={(enabled) => setDraft({ ...form, enabled })}
          />
          <Label htmlFor={switchId} className="font-normal">
            Every day
          </Label>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <Label htmlFor={startId} className="text-xs font-normal text-muted-foreground">
              From
            </Label>
            <Input
              id={startId}
              type="time"
              className="w-28"
              value={form.start}
              onChange={(e) => setDraft({ ...form, start: e.target.value })}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor={endId} className="text-xs font-normal text-muted-foreground">
              To
            </Label>
            <Input
              id={endId}
              type="time"
              className="w-28"
              value={form.end}
              onChange={(e) => setDraft({ ...form, end: e.target.value })}
            />
          </div>
          <Button variant="outline" onClick={save} disabled={!changed || busy}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          By the device&apos;s own clock, which says {status.deviceTime} ({status.timeZone}).
        </p>
        <FormError message={error} />

        {status.enabled && !status.clockSynchronised && (
          <Notice>
            The device&apos;s clock has not been set from the network since it started. Until it
            has, nothing happens in the window.
          </Notice>
        )}
        {status.restartNeeded && (
          <Notice>
            {status.enabled
              ? `A restart is waiting. It happens in the next window, from ${status.start}.`
              : 'A restart is waiting. With the window off, it is yours to start.'}
          </Notice>
        )}
        {status.lastRestart && (
          <p className="text-sm text-muted-foreground">
            SGC last restarted the device by itself {formatTimeAgo(status.lastRestart)}.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-400">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}
