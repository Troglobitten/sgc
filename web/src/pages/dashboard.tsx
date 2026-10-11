import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  BadgeCheck,
  Globe,
  HardDrive,
  LogOut,
  RotateCw,
  Route,
  ShieldCheck,
  TriangleAlert,
  User,
} from 'lucide-react'

import { Logo } from '@/components/logo'
import { ThemeMenu } from '@/components/theme-menu'
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { api, ApiError, errorMessage, type AuditEntry, type Health } from '@/lib/api'
import { formatDuration, formatGigabytes, formatTimeAgo, percentOf } from '@/lib/format'

const healthInterval = 3_000
const activityInterval = 15_000

export function DashboardPage({
  username,
  version,
  onSignedOut,
}: {
  username: string
  version: string
  onSignedOut: () => void
}) {
  const [health, setHealth] = useState<Health | null>(null)
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [restarting, setRestarting] = useState(false)

  // A 401 means the session ended (expired, or signed out in another tab):
  // go back to the sign-in screen instead of showing a broken dashboard.
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )

  useEffect(() => {
    if (restarting) return
    let stopped = false
    const load = () =>
      api.health().then(
        (h) => {
          if (stopped) return
          setHealth(h)
          setProblem(null)
        },
        (e) => !stopped && handleError(e),
      )
    load()
    const timer = setInterval(load, healthInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [handleError, restarting])

  useEffect(() => {
    if (restarting) return
    let stopped = false
    const load = () =>
      api.audit().then(
        (entries) => !stopped && setActivity(entries),
        (e) => !stopped && handleError(e),
      )
    load()
    const timer = setInterval(load, activityInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [handleError, restarting])

  async function signOut() {
    try {
      await api.logout()
    } finally {
      onSignedOut()
    }
  }

  if (restarting) return <RestartingScreen />

  return (
    <div className="min-h-svh bg-muted/40">
      <header className="flex items-center gap-2.5 border-b bg-background px-4 py-2">
        <Logo className="size-7" />
        <span className="font-medium">SGC</span>
        {health && <span className="text-sm text-muted-foreground">{health.hostname}</span>}
        <span className="rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground">
          {version}
        </span>
        <div className="flex-1" />
        <ThemeMenu />
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" />}>
            <User />
            {username}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={signOut}>
              <LogOut />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </header>

      <main className="mx-auto flex max-w-5xl flex-col gap-6 p-4">
        {problem && (
          <p
            role="alert"
            className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
          >
            <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
            {problem}
          </p>
        )}

        <Section title="System">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <Metric label="Processor" value={health && `${Math.round(health.cpuPercent)}%`} />
            <Metric
              label="Memory"
              value={health && `${percentOf(health.memoryUsedBytes, health.memoryTotalBytes)}%`}
              detail={
                health &&
                `${formatGigabytes(health.memoryUsedBytes)} of ${formatGigabytes(health.memoryTotalBytes)}`
              }
            />
            <Metric
              label="Disk"
              value={health && `${percentOf(health.diskUsedBytes, health.diskTotalBytes)}%`}
              detail={
                health &&
                `${formatGigabytes(health.diskUsedBytes)} of ${formatGigabytes(health.diskTotalBytes)}`
              }
            />
            <Metric
              label="Temperature"
              value={
                health &&
                (health.temperatureC === null ? '–' : `${Math.round(health.temperatureC)} °C`)
              }
              detail={health && health.temperatureC === null ? 'No sensor' : null}
            />
            <Metric label="Running for" value={health && formatDuration(health.uptimeSeconds)} />
          </div>
          {health && (
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
              <HardDrive className="size-4" aria-hidden="true" />
              {[health.model, health.os, bootMediumLabel(health.bootMedium)]
                .filter(Boolean)
                .join(' · ')}
            </p>
          )}
        </Section>

        <Section title="Services">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <ServiceTile icon={<ShieldCheck />} name="VPN" />
            <ServiceTile icon={<Globe />} name="DNS" />
            <ServiceTile icon={<Route />} name="Proxy" />
            <ServiceTile icon={<BadgeCheck />} name="Certificate" />
          </div>
        </Section>

        <div className="grid gap-3 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <Card>
            <CardContent className="flex flex-col gap-2">
              <h2 className="text-sm text-muted-foreground">Recent activity</h2>
              <ActivityList entries={activity} />
            </CardContent>
          </Card>
          <Card>
            <CardContent className="flex flex-col gap-3">
              <h2 className="text-sm text-muted-foreground">Device</h2>
              <RestartButton onRestarting={() => setRestarting(true)} />
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2.5">
      <h2 className="text-sm text-muted-foreground">{title}</h2>
      {children}
    </section>
  )
}

/** One number with its label. Shows a quiet placeholder until the first reading arrives. */
function Metric({
  label,
  value,
  detail,
}: {
  label: string
  value: string | null
  detail?: string | null
}) {
  return (
    <div className="rounded-xl bg-card p-3 ring-1 ring-foreground/10">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="text-2xl font-medium tabular-nums">{value ?? '…'}</p>
      {detail && <p className="text-xs text-muted-foreground">{detail}</p>}
    </div>
  )
}

/** A placeholder for a part of SGC that a later version brings. */
function ServiceTile({ icon, name }: { icon: ReactNode; name: string }) {
  return (
    <div className="rounded-xl bg-card p-3 ring-1 ring-foreground/10">
      <p className="flex items-center gap-2 text-sm font-medium [&_svg]:size-4">
        {icon}
        {name}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">Not set up yet</p>
    </div>
  )
}

function ActivityList({ entries }: { entries: AuditEntry[] | null }) {
  if (entries === null) return <p className="text-sm text-muted-foreground">…</p>
  if (entries.length === 0) return <p className="text-sm text-muted-foreground">Nothing yet.</p>
  return (
    <ul className="divide-y">
      {entries.slice(0, 8).map((entry) => (
        <li key={entry.id} className="flex justify-between gap-4 py-1.5 text-sm">
          <span>{describeActivity(entry)}</span>
          <span className="shrink-0 text-muted-foreground">{formatTimeAgo(entry.at)}</span>
        </li>
      ))}
    </ul>
  )
}

// Stored action names (internal/audit) turned into sentences.
function describeActivity(entry: AuditEntry): string {
  switch (entry.action) {
    case 'setup.link_created':
      return 'Setup link created'
    case 'setup.completed':
      return 'Admin account created'
    case 'login.success':
      return `${entry.actor} signed in`
    case 'login.failed':
      return `Failed sign-in attempt from ${entry.remoteAddr}`
    case 'logout':
      return `${entry.actor} signed out`
    case 'device.restart':
      return `${entry.actor} restarted the device`
    case 'device.restart_failed':
      return 'Restarting the device failed'
    default:
      return entry.action
  }
}

function bootMediumLabel(medium: Health['bootMedium']): string {
  switch (medium) {
    case 'sd-card':
      return 'boots from SD card'
    case 'disk':
      return 'boots from disk'
    default:
      return ''
  }
}

function RestartButton({ onRestarting }: { onRestarting: () => void }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function restart() {
    setBusy(true)
    setError(null)
    try {
      await api.restartDevice()
      setOpen(false)
      onRestarting()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <RotateCw />
        Restart
      </Button>
      <AlertDialog open={open} onOpenChange={(next) => !busy && setOpen(next)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Restart the device?</AlertDialogTitle>
            <AlertDialogDescription>
              Everything running on this device stops for about a minute, including SGC itself.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={restart} disabled={busy}>
              {busy ? 'Restarting…' : 'Restart'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

/** Shown while the device is down; reloads the page once SGC answers again. */
function RestartingScreen() {
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    // Give the device time to actually go down first. Otherwise the first
    // check would still reach the old, about-to-stop SGC and reload too early.
    const check = () =>
      api.state().then(
        () => window.location.reload(),
        () => {
          timer = setTimeout(check, 3_000)
        },
      )
    timer = setTimeout(check, 10_000)
    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-4 bg-muted/40 p-4 text-center">
      <Logo className="size-14 animate-spin [animation-duration:6s]" />
      <h1 className="text-base font-medium">Restarting the device</h1>
      <p className="max-w-xs text-sm text-muted-foreground">
        This takes about a minute. The page comes back by itself.
      </p>
    </div>
  )
}
