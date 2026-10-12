import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  BadgeCheck,
  Globe,
  HardDrive,
  Route,
  Shield,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { Logo } from '@/components/logo'
import { UpdateCard } from '@/components/update-card'
import { Card, CardContent } from '@/components/ui/card'
import {
  api,
  ApiError,
  errorMessage,
  type AuditEntry,
  type FirewallStatus,
  type Health,
} from '@/lib/api'
import { formatDuration, formatGigabytes, formatTimeAgo, percentOf } from '@/lib/format'

const healthInterval = 3_000
const activityInterval = 15_000

export function DashboardPage({ shell }: { shell: ShellProps }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  // While an update runs: the number of the attempt before it (or null).
  const [updating, setUpdating] = useState<{ previousAttempt: number | null } | null>(null)
  // SGC is briefly unreachable during an update; the regular refreshing
  // pauses so it does not report that as a problem.
  const paused = updating !== null
  const finishUpdating = useCallback(() => setUpdating(null), [])

  // A 401 means the session ended (expired, or signed out in another tab):
  // go back to the sign-in screen instead of showing a broken dashboard.
  const { onSignedOut, onNavigate } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )

  useEffect(() => {
    if (paused) return
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
  }, [handleError, paused])

  useEffect(() => {
    if (paused) return
    let stopped = false
    const load = () => {
      api.audit().then(
        (entries) => !stopped && setActivity(entries),
        (e) => !stopped && handleError(e),
      )
      api.firewall().then(
        (status) => !stopped && setFirewall(status),
        (e) => !stopped && handleError(e),
      )
    }
    load()
    const timer = setInterval(load, activityInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [handleError, paused])

  if (updating) {
    return (
      <UpdatingScreen
        previousAttempt={updating.previousAttempt}
        onFinished={finishUpdating}
        onSignedOut={onSignedOut}
      />
    )
  }

  return (
    <AppShell page="dashboard" {...shell}>
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
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <FirewallTile status={firewall} onOpen={() => onNavigate('system')} />
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
        <div className="flex flex-col gap-3">
          <UpdateCard
            onError={handleError}
            onUpdating={(previousAttempt) => setUpdating({ previousAttempt })}
          />
        </div>
      </div>
    </AppShell>
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

/** The firewall at a glance. It is switched on and off on the System page. */
function FirewallTile({
  status,
  onOpen,
}: {
  status: FirewallStatus | null
  onOpen: () => void
}) {
  let text = '…'
  let tone = 'text-muted-foreground'
  if (status?.state === 'on') {
    text = 'On'
    tone = 'text-emerald-700 dark:text-emerald-400'
  } else if (status?.state === 'pending') {
    text = 'Waiting for confirmation'
    tone = 'text-amber-700 dark:text-amber-400'
  } else if (status) {
    text = 'Off'
    tone = 'text-amber-700 dark:text-amber-400'
  }
  return (
    <button
      type="button"
      onClick={onOpen}
      className="rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium">
        <Shield className="size-4" aria-hidden="true" />
        Firewall
      </span>
      <span className={`mt-1 block text-xs ${tone}`}>{text}</span>
    </button>
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
  // Firewall entries say in their detail which way the change went.
  const to = /\bswitch(ing|ed) on\b/.test(entry.detail) ? 'on' : 'off'
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
    case 'update.started':
      return entry.actor === 'console'
        ? `An update ${entry.detail} was started over SSH`
        : `${entry.actor} started an update ${entry.detail}`
    case 'update.succeeded':
    case 'update.rolled_back':
      // The updater's own sentence says it best.
      return entry.detail
    case 'update.failed':
      return `Update failed: ${entry.detail}`
    case 'setting.changed':
      return `${entry.actor}: ${entry.detail}`
    case 'export.created':
      return `${entry.actor} made an export`
    case 'restore.completed':
      return `Restored ${entry.detail}`
    case 'system.packages_installed':
      return `SGC installed ${entry.detail}`
    case 'firewall.change_started':
      return `${entry.actor} switched the firewall ${to}, to be confirmed`
    case 'firewall.change_confirmed':
      return entry.actor === 'console'
        ? `The firewall was switched ${to} over SSH`
        : `${entry.actor} confirmed: the firewall stays ${to}`
    case 'firewall.change_undone':
      return entry.actor === 'system'
        ? `Switching the firewall ${to} was undone: the wait for confirmation was interrupted`
        : `${entry.actor} undid switching the firewall ${to}`
    case 'firewall.change_expired':
      return `Switching the firewall ${to} was not confirmed in time and was undone`
    case 'firewall.change_failed':
      return `Switching the firewall ${to} failed`
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

/**
 * Shown while SGC updates itself. SGC is stopped for part of that time, so
 * failed requests are expected and simply retried. The update is over when
 * the updater has recorded the outcome of a new attempt.
 */
function UpdatingScreen({
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
