import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { ChevronLeft, ChevronRight, RotateCw, TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { AccountCard } from '@/components/account-card'
import { BackupsCard } from '@/components/backups-card'
import { CertificateCard } from '@/components/certificate-card'
import { DnsCard } from '@/components/dns-card'
import { DomainCard } from '@/components/domain-card'
import { ExportCard } from '@/components/export-card'
import { FirewallCard } from '@/components/firewall-card'
import { InternetSection } from '@/components/internet-cards'
import { Log2ramCard } from '@/components/log2ram-card'
import { Logo } from '@/components/logo'
import { MaintenanceCard } from '@/components/maintenance-card'
import { NamesCard } from '@/components/names-card'
import { NotificationsCard } from '@/components/notifications-card'
import { OsUpdatesCard } from '@/components/os-updates-card'
import { Facts, More, PageTitle, SettingCard, StatusDot } from '@/components/setting'
import { SoftwareCard } from '@/components/software-card'
import { SshCard } from '@/components/ssh-card'
import { SgcUpdatesCard } from '@/components/update-card'
import { UpdatingScreen } from '@/components/updating-screen'
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
import { api, ApiError, errorMessage, type Health } from '@/lib/api'
import { daysUntil, formatDuration, formatGigabytes, formatTimeAgo, percentOf } from '@/lib/format'
import { systemSectionNames, systemSections, type SystemSection } from '@/lib/pages'
import { usePolled } from '@/lib/poll'
import { toneClass, type Tone } from '@/lib/tone'
import { cn } from '@/lib/utils'

// The list's status lines are a convenience: a part that cannot be asked
// just shows nothing there, and its own card says why.
const ignore = () => {}
const summaryInterval = 30_000

/**
 * Settings of the device itself, in sections (docs/design.md §13): a list of
 * them with each one's state, and one section at a time. On a phone the
 * list is the page and a section opens on its own; on a wider screen the
 * list stays beside the section.
 */
export function SystemPage({
  shell,
  section,
  minPassphraseLength,
  minPasswordLength,
}: {
  shell: ShellProps
  section: SystemSection | null
  minPassphraseLength: number
  minPasswordLength: number
}) {
  const [problem, setProblem] = useState<string | null>(null)
  const [restarting, setRestarting] = useState(false)
  const [updating, setUpdating] = useState<{ previousAttempt: number | null } | null>(null)
  const finishUpdating = useCallback(() => setUpdating(null), [])

  // A 401 means the session ended (expired, or signed out in another tab).
  const { onSignedOut, onNavigate } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )
  const summary = useSectionSummary(updating === null && !restarting)

  if (restarting) return <RestartingScreen />
  if (updating) {
    return <UpdatingScreen previousAttempt={updating.previousAttempt} onFinished={finishUpdating} onSignedOut={onSignedOut} />
  }

  const shown: SystemSection = section ?? 'security'
  // A problem belongs to the section it came from.
  const open = (next: SystemSection | null) => {
    setProblem(null)
    onNavigate('system', next)
  }

  return (
    <AppShell page="system" {...shell}>
      <div className="flex flex-col gap-6 md:flex-row md:items-start md:gap-8">
        <nav aria-label="System" className={cn('flex-col gap-3 md:sticky md:top-4 md:flex md:w-64 md:shrink-0', section ? 'hidden' : 'flex')}>
          <h1 className="text-xl font-semibold md:hidden">System</h1>
          <ul className="divide-y overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10 md:divide-y-0 md:overflow-visible md:rounded-none md:bg-transparent md:ring-0">
            {systemSectionNames.map((name) => {
              const { label, icon: Icon } = systemSections[name]
              const line = summary[name]
              const current = name === shown
              return (
                <li key={name}>
                  <a
                    href={`/system/${name}`}
                    aria-current={current ? 'page' : undefined}
                    onClick={(event) => {
                      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
                      event.preventDefault()
                      open(name)
                    }}
                    className={cn(
                      'flex min-h-14 items-center gap-3 px-4 py-2.5 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50 md:min-h-0 md:rounded-lg md:px-3',
                      current && 'md:bg-card md:ring-1 md:ring-foreground/10',
                    )}
                  >
                    <Icon className="size-[18px] shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="text-sm font-medium">{label}</span>
                      {line && (
                        <span className={cn('flex items-center gap-1.5 truncate text-[13px]', line.tone === 'ok' ? 'text-muted-foreground' : toneClass(line.tone))}>
                          {line.tone !== 'ok' && line.tone !== 'muted' && <StatusDot tone={line.tone} />}
                          {line.text}
                        </span>
                      )}
                    </span>
                    <ChevronRight className="size-4 shrink-0 text-muted-foreground md:hidden" aria-hidden="true" />
                  </a>
                </li>
              )
            })}
          </ul>
        </nav>

        <div className={cn('min-w-0 max-w-3xl flex-1 flex-col gap-4 md:flex', section ? 'flex' : 'hidden')}>
          {section && (
            <button
              type="button"
              onClick={() => open(null)}
              className="-mb-1 inline-flex min-h-11 w-fit items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground md:hidden"
            >
              <ChevronLeft className="size-4" aria-hidden="true" />
              System
            </button>
          )}
          <PageTitle title={systemSections[shown].label} lead={systemSections[shown].lead} />
          {problem && (
            <p
              role="alert"
              className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
              {problem}
            </p>
          )}
          <SectionContent
            section={shown}
            onError={handleError}
            username={shell.username}
            minPassphraseLength={minPassphraseLength}
            minPasswordLength={minPasswordLength}
            onUpdating={(previousAttempt) => setUpdating({ previousAttempt })}
            onRestarting={() => setRestarting(true)}
          />
        </div>
      </div>
    </AppShell>
  )
}

function SectionContent({
  section,
  onError,
  username,
  minPassphraseLength,
  minPasswordLength,
  onUpdating,
  onRestarting,
}: {
  section: SystemSection
  onError: (error: unknown) => void
  username: string
  minPassphraseLength: number
  minPasswordLength: number
  onUpdating: (previousAttempt: number | null) => void
  onRestarting: () => void
}) {
  switch (section) {
    case 'security':
      return (
        <>
          <FirewallCard onError={onError} />
          <SshCard onError={onError} />
          <AccountCard username={username} minPasswordLength={minPasswordLength} />
        </>
      )
    case 'internet':
      return <InternetSection onError={onError} />
    case 'domain':
      return (
        <>
          <DomainCard onError={onError} />
          <CertificateCard onError={onError} />
          <NamesCard onError={onError} />
        </>
      )
    case 'dns':
      return <DnsCard onError={onError} />
    case 'updates':
      return (
        <>
          <SgcUpdatesCard onError={onError} onUpdating={onUpdating} />
          <OsUpdatesCard onError={onError} />
          <MaintenanceCard onError={onError} />
          <SoftwareCard onError={onError} />
        </>
      )
    case 'backups':
      return (
        <>
          <BackupsCard onError={onError} />
          <div className="grid gap-4 lg:grid-cols-2">
            <ExportCard minPassphraseLength={minPassphraseLength} />
            <RestoreCard />
          </div>
        </>
      )
    case 'notifications':
      return <NotificationsCard onError={onError} />
    case 'device':
      return (
        <>
          <DeviceCard onError={onError} />
          <Log2ramCard onError={onError} />
          <RestartCard onRestarting={onRestarting} />
        </>
      )
  }
}

type Line = { text: string; tone: Tone }

/** Each section's state in a few words, for the list. */
function useSectionSummary(active: boolean): Partial<Record<SystemSection, Line>> {
  const interval = active ? summaryInterval : 3_600_000
  const [firewall] = usePolled(api.firewall, interval, ignore)
  const [ssh] = usePolled(api.ssh, interval, ignore)
  const [domain] = usePolled(api.domain, interval, ignore)
  const [certificate] = usePolled(api.certificate, interval, ignore)
  const [dns] = usePolled(api.dns, interval, ignore)
  const [update] = usePolled(api.update, interval, ignore)
  const [os] = usePolled(api.osUpdates, interval, ignore)
  const [backups] = usePolled(api.backups, interval, ignore)
  const [notifications] = usePolled(api.notificationSettings, interval, ignore)
  const [health] = usePolled(api.health, interval, ignore)
  const [log2ram] = usePolled(api.log2ram, interval, ignore)
  const [internet] = usePolled(api.publicStatus, interval, ignore)

  const out: Partial<Record<SystemSection, Line>> = {}

  if (firewall) {
    const keys = ssh?.available ? (ssh.keysOnly ? ' · keys only' : ' · SSH passwords allowed') : ''
    if (firewall.state === 'pending') out.security = { text: 'Firewall waiting for confirmation', tone: 'warn' }
    else if (firewall.state === 'off') out.security = { text: `Firewall off${keys}`, tone: 'warn' }
    else if (firewall.behind.length > 0) out.security = { text: 'Firewall rules are behind', tone: 'warn' }
    else out.security = { text: `Firewall on${keys}`, tone: 'ok' }
  }

  if (internet) {
    const count = internet.services.length
    if (!internet.wanted) out.internet = { text: 'Off: nothing is public', tone: 'muted' }
    else if (internet.problem) out.internet = { text: 'A public name needs a look', tone: 'warn' }
    else out.internet = { text: count === 0 ? 'On, nothing public yet' : `${count} public`, tone: 'ok' }
  }

  if (domain) {
    const current = certificate?.certificate?.forDomain ? certificate.certificate : null
    const days = current ? daysUntil(current.notAfter) : null
    if (!domain.configured) out.domain = { text: 'Not set up yet', tone: 'muted' }
    else if (domain.checkedAt && !domain.ok) out.domain = { text: `${domain.providerName} does not accept the key`, tone: 'warn' }
    else if (days !== null && days < 14) out.domain = { text: `Certificate: ${days} days left`, tone: 'warn' }
    else if (days !== null) out.domain = { text: `${domain.domain} · certificate ${days} days`, tone: 'ok' }
    else out.domain = { text: `${domain.domain} · no certificate yet`, tone: 'muted' }
  }

  if (dns) {
    if (!dns.available) out.dns = { text: 'Could not be asked', tone: 'muted' }
    else if (!dns.enabled) out.dns = { text: 'Off', tone: 'muted' }
    else if (dns.running) out.dns = { text: 'AdGuard Home runs', tone: 'ok' }
    else out.dns = { text: 'AdGuard Home is not running', tone: 'warn' }
  }

  if (update || os) {
    const waitingCount = os?.waiting.length ?? 0
    if (os?.restartNeeded) out.updates = { text: 'A restart is needed', tone: 'warn' }
    else if (update?.updateAvailable) out.updates = { text: `SGC ${update.latest} is out`, tone: 'warn' }
    else if (os && os.mode === '') out.updates = { text: 'Device updates not set up', tone: 'warn' }
    else if (waitingCount > 0) out.updates = { text: `${waitingCount} device updates waiting`, tone: os?.mode === 'by-hand' ? 'warn' : 'muted' }
    else out.updates = { text: 'Up to date', tone: 'ok' }
  }

  if (backups) {
    if (!backups.settings.enabled) out.backups = { text: 'Daily backups off', tone: 'muted' }
    else if (backups.last && !backups.last.ok) out.backups = { text: 'The last backup failed', tone: 'warn' }
    else if (backups.overdue) out.backups = { text: 'Overdue', tone: 'warn' }
    else if (backups.lastSuccess) out.backups = { text: `Last ${formatTimeAgo(backups.lastSuccess)}`, tone: 'ok' }
    else out.backups = { text: 'None made yet', tone: 'muted' }
  }

  if (notifications) {
    const ways = ['the bell']
    if (notifications.channels.email.enabled) ways.push('email')
    if (notifications.channels.ntfy.enabled) ways.push('ntfy')
    const text = ways.length === 1 ? 'The bell only' : ways.join(', ').replace(/, ([^,]*)$/, ' and $1')
    out.notifications = { text: text.charAt(0).toUpperCase() + text.slice(1), tone: 'muted' }
  }

  if (health) {
    const parts = [health.model || health.hostname]
    if (log2ram?.active) parts.push('logs in memory')
    if (log2ram?.startFailed || log2ram?.nearlyFull) out.device = { text: 'Logs in memory need a look', tone: 'warn' }
    else out.device = { text: parts.join(' · '), tone: 'muted' }
  }

  return out
}

/** The device's readings, and what it is. */
function DeviceCard({ onError }: { onError: (error: unknown) => void }) {
  const [health] = usePolled(api.health, 5_000, onError)
  return (
    <SettingCard title="Hardware">
      {health ? (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Reading label="Processor" value={`${Math.round(health.cpuPercent)}%`} />
            <Reading
              label="Memory"
              value={`${percentOf(health.memoryUsedBytes, health.memoryTotalBytes)}%`}
              detail={`${formatGigabytes(health.memoryUsedBytes)} of ${formatGigabytes(health.memoryTotalBytes)}`}
            />
            <Reading
              label="Disk"
              value={`${percentOf(health.diskUsedBytes, health.diskTotalBytes)}%`}
              detail={`${formatGigabytes(health.diskUsedBytes)} of ${formatGigabytes(health.diskTotalBytes)}`}
            />
            {health.temperatureC !== null && <Reading label="Temperature" value={`${Math.round(health.temperatureC)} °C`} />}
            <Reading label="Running for" value={formatDuration(health.uptimeSeconds)} />
          </div>
          <Facts
            items={[
              ['Device', health.model || '–'],
              ['System', health.os],
              ['Kernel', health.kernel],
              ['Starts from', deviceMedium(health.bootMedium)],
              ['Name', health.hostname],
            ]}
          />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">…</p>
      )}
    </SettingCard>
  )
}

function Reading({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="rounded-lg bg-muted/50 p-3">
      <p className="text-[13px] text-muted-foreground">{label}</p>
      <p className="text-xl font-medium tabular-nums">{value}</p>
      {detail && <p className="text-xs text-muted-foreground">{detail}</p>}
    </div>
  )
}

function deviceMedium(medium: Health['bootMedium']): string {
  switch (medium) {
    case 'sd-card':
      return 'an SD card'
    case 'disk':
      return 'a disk'
    default:
      return '–'
  }
}

/** Where restoring is: on a fresh install, not here. */
function RestoreCard() {
  return (
    <SettingCard title="Restore">
      <p className="text-sm">A backup or an export is restored on a fresh install: open its setup link and choose the file.</p>
      <More label="Step by step">
        <ol className="flex list-decimal flex-col gap-1 pl-4">
          <li>Install SGC on the new device with the one-line command.</li>
          <li>Open the link the installer prints, and choose “Restore an export”.</li>
          <li>Choose the file, and enter its passphrase (an export) or the backup key (a backup).</li>
        </ol>
      </More>
    </SettingCard>
  )
}

function RestartCard({ onRestarting }: { onRestarting: () => void }) {
  return (
    <SettingCard title="Restart">
      <p className="text-sm">Restarts the whole device. Everything running on it stops for about a minute.</p>
      <div>
        <RestartButton onRestarting={onRestarting} />
      </div>
    </SettingCard>
  )
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
function RestartingScreen(): ReactNode {
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
