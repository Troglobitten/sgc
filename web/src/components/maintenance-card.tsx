import { useEffect, useId, useState } from 'react'

import { FormError } from '@/components/auth-card'
import { SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Button } from '@/components/ui/button'
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
 * that (System, Updates). Off until switched on.
 */
export function MaintenanceCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<MaintenanceStatus | null>(null)
  // What is in the form; null until the owner changes something.
  const [draft, setDraft] = useState<{ enabled: boolean; start: string; end: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState(false)
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
      <SettingCard title="Maintenance window">
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
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
      setEditing(false)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingCard
      title="Maintenance window"
      status={
        status.enabled ? (
          <StatusBadge tone="ok">
            Every day {status.start}–{status.end}
          </StatusBadge>
        ) : (
          <StatusBadge tone="muted">Off</StatusBadge>
        )
      }
    >
        <p className="text-sm">
          {status.enabled
            ? 'When an update needs a restart, and when SGC’s own updates may install. Outside it, nothing restarts by itself.'
            : 'Off: nothing restarts by itself, and SGC’s own updates wait for you.'}
        </p>

        {status.enabled && !status.clockSynchronised && (
          <Warning>
            The device’s clock has not been set from the network since it started. Until it has, nothing happens in the
            window.
          </Warning>
        )}
        {status.restartNeeded && (
          <Warning>
            {status.enabled
              ? `A restart is waiting. It happens in the next window, from ${status.start}.`
              : 'A restart is waiting. With the window off, it is yours to start (under This device).'}
          </Warning>
        )}
        {status.lastRestart && (
          <p className="text-sm text-muted-foreground">
            SGC last restarted the device by itself {formatTimeAgo(status.lastRestart)}.
          </p>
        )}

        {editing ? (
          <div className="flex flex-col gap-3 border-t pt-3">
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
            </div>
            <p className="text-xs text-muted-foreground">
              By the device’s own clock, which says {status.deviceTime} ({status.timeZone}).
            </p>
            <FormError message={error} />
            <div className="flex gap-2">
              <Button onClick={save} disabled={!changed || busy}>
                {busy ? 'Saving…' : 'Save'}
              </Button>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setDraft(null)
                  setError(null)
                  setEditing(false)
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div>
            <Button variant="outline" onClick={() => setEditing(true)}>
              Change
            </Button>
          </div>
        )}
    </SettingCard>
  )
}

