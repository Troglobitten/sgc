import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  BadgeCheck,
  Globe,
  HardDrive,
  PackageCheck,
  Route,
  Shield,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { GuideChecklist } from '@/components/guide-checklist'
import { HealthDot, ServiceIcon } from '@/components/service-icon'
import { Logo } from '@/components/logo'
import { UpdateCard } from '@/components/update-card'
import { Card, CardContent } from '@/components/ui/card'
import {
  api,
  ApiError,
  errorMessage,
  type AuditEntry,
  type CertificateStatus,
  type DnsStatus,
  type DomainStatus,
  type FirewallStatus,
  type Health,
  type OsUpdatesStatus,
  type ProxyStatus,
  type Service,
} from '@/lib/api'
import { daysUntil, formatDuration, formatGigabytes, formatTimeAgo, percentOf } from '@/lib/format'

const healthInterval = 3_000
const activityInterval = 15_000

export function DashboardPage({ shell, onOpenGuide }: { shell: ShellProps; onOpenGuide: () => void }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null)
  const [osUpdates, setOsUpdates] = useState<OsUpdatesStatus | null>(null)
  const [dns, setDns] = useState<DnsStatus | null>(null)
  const [domain, setDomain] = useState<DomainStatus | null>(null)
  const [certificate, setCertificate] = useState<CertificateStatus | null>(null)
  const [services, setServices] = useState<Service[] | null>(null)
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus | null>(null)
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
      api.osUpdates().then(
        (status) => !stopped && setOsUpdates(status),
        (e) => !stopped && handleError(e),
      )
      api.dns().then(
        (status) => !stopped && setDns(status),
        (e) => !stopped && handleError(e),
      )
      api.domain().then(
        (status) => !stopped && setDomain(status),
        (e) => !stopped && handleError(e),
      )
      api.certificate().then(
        (status) => !stopped && setCertificate(status),
        (e) => !stopped && handleError(e),
      )
      api.services().then(
        (data) => !stopped && setServices(data.services),
        (e) => !stopped && handleError(e),
      )
      api.proxy().then(
        (status) => !stopped && setProxyStatus(status),
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
      <GuideChecklist onContinue={onOpenGuide} />
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
        {/* Zone.eu no longer accepting the key stops certificates from being
            renewed, weeks before anything else shows it. */}
        {domain?.configured && domain.checkedAt !== null && !domain.ok && (
          <button
            type="button"
            onClick={() => onNavigate('system')}
            className="mb-3 flex w-full items-start gap-2 rounded-xl bg-card p-3 text-left text-sm text-amber-700 ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50 dark:text-amber-400"
          >
            <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <span>
              The domain {domain.domain}: {domain.problem} The System page has the details.
            </span>
          </button>
        )}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <FirewallTile status={firewall} onOpen={() => onNavigate('system')} />
          <OsUpdatesTile status={osUpdates} onOpen={() => onNavigate('system')} />
          <ServiceTile icon={<ShieldCheck />} name="VPN" />
          <DnsTile status={dns} onOpen={() => onNavigate('system')} />
          <ProxyTile status={proxyStatus} onOpen={() => onNavigate('services')} />
          <CertificateTile status={certificate} onOpen={() => onNavigate('system')} />
        </div>
      </Section>

      {services && services.length > 0 && (
        <Section title="Your services">
          <ServiceGrid services={services} onManage={() => onNavigate('services')} />
        </Section>
      )}

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

/** The proxy in a word; the Services page has the switch. */
function ProxyTile({ status, onOpen }: { status: ProxyStatus | null; onOpen: () => void }) {
  let text = '…'
  let tone = 'text-muted-foreground'
  if (status && !status.wanted) text = 'Off'
  else if (status?.running && status.lastApply?.ok !== false)
    [text, tone] = ['On', 'text-emerald-700 dark:text-emerald-400']
  else if (status?.running) [text, tone] = ['Last change failed', 'text-amber-700 dark:text-amber-400']
  else if (status) [text, tone] = ['Not running', 'text-amber-700 dark:text-amber-400']
  return (
    <button
      type="button"
      onClick={onOpen}
      className="rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium">
        <Route className="size-4" aria-hidden="true" />
        Proxy
      </span>
      <span className={`mt-1 block text-xs ${tone}`}>{text}</span>
    </button>
  )
}

/** The services in use, grouped by category, each opening at its name. */
function ServiceGrid({ services, onManage }: { services: Service[]; onManage: () => void }) {
  const live = services.filter((s) => s.enabled && !s.pending)
  const waiting = services.length - live.length
  const categories = [...new Set(live.map((s) => s.category))]
  return (
    <div className="flex flex-col gap-3">
      {categories.map((category) => (
        <div key={category || '-'} className="flex flex-col gap-2">
          {categories.length > 1 && (
            <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
              {category || 'Other'}
            </h3>
          )}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {live
              .filter((s) => s.category === category)
              .map((s) => {
                const inner = (
                  <>
                    <ServiceIcon service={s} />
                    <span className="flex min-w-0 flex-col">
                      <span className="flex items-center gap-1.5 truncate text-sm font-medium">
                        <HealthDot service={s} />
                        {s.title || s.name}
                      </span>
                      <span className="truncate text-xs text-muted-foreground">
                        {s.kind === 'http' ? s.url.replace('https://', '') : s.url}
                      </span>
                    </span>
                  </>
                )
                const className =
                  'flex items-center gap-3 rounded-xl bg-card p-3 ring-1 ring-foreground/10 outline-none'
                return s.kind === 'http' && s.url ? (
                  <a key={s.id} href={s.url} target="_blank" rel="noreferrer"
                    className={`${className} hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50`}>
                    {inner}
                  </a>
                ) : (
                  <div key={s.id} className={className}>
                    {inner}
                  </div>
                )
              })}
          </div>
        </div>
      ))}
      {waiting > 0 && (
        <button type="button" onClick={onManage} className="self-start text-sm text-muted-foreground hover:underline">
          {waiting} more switched off or waiting for approval
        </button>
      )}
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

/** The certificate in a word; the System page has the rest. */
function CertificateTile({
  status,
  onOpen,
}: {
  status: CertificateStatus | null
  onOpen: () => void
}) {
  const good = 'text-emerald-700 dark:text-emerald-400'
  const warn = 'text-amber-700 dark:text-amber-400'
  let text = '…'
  let tone = 'text-muted-foreground'
  const current = status?.certificate?.forDomain ? status.certificate : null
  const renewalFails =
    status?.lastAttempt != null && !status.lastAttempt.ok && status.lastAttempt.kind === 'renewal'
  if (status?.running) text = 'Being requested…'
  else if (current) {
    const days = daysUntil(current.notAfter)
    if (days < 0) [text, tone] = ['Run out', warn]
    else if (renewalFails) [text, tone] = [`${days} days left, renewing fails`, warn]
    else [text, tone] = [`${days} days left`, days < 14 ? warn : good]
  } else if (status?.lastAttempt != null && !status.lastAttempt.ok) [text, tone] = ['Last attempt failed', warn]
  else if (status) text = 'Not set up yet'
  return (
    <button
      type="button"
      onClick={onOpen}
      className="rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium">
        <BadgeCheck className="size-4" aria-hidden="true" />
        Certificate
      </span>
      <span className={`mt-1 block text-xs ${tone}`}>{text}</span>
    </button>
  )
}

/** AdGuard Home in a word; the System page has the rest. */
function DnsTile({ status, onOpen }: { status: DnsStatus | null; onOpen: () => void }) {
  let text = '…'
  let tone = 'text-muted-foreground'
  if (status?.available && !status.enabled) text = 'Off'
  else if (status?.running) [text, tone] = ['On', 'text-emerald-700 dark:text-emerald-400']
  else if (status?.available) [text, tone] = ['Not running', 'text-amber-700 dark:text-amber-400']
  return (
    <button
      type="button"
      onClick={onOpen}
      className="rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium">
        <Globe className="size-4" aria-hidden="true" />
        DNS
      </span>
      <span className={`mt-1 block text-xs ${tone}`}>{text}</span>
    </button>
  )
}

/** Updates for the device itself, in a few words; the System page has the rest. */
function OsUpdatesTile({
  status,
  onOpen,
}: {
  status: OsUpdatesStatus | null
  onOpen: () => void
}) {
  const calm = 'text-muted-foreground'
  const good = 'text-emerald-700 dark:text-emerald-400'
  const attention = 'text-amber-700 dark:text-amber-400'
  let text = '…'
  let tone = calm
  if (status) {
    const waiting = status.waiting.length
    if (status.mode === '') [text, tone] = ['Not set up', attention]
    else if (status.running === 'install') [text, tone] = ['Installing', calm]
    else if (status.restartNeeded) [text, tone] = ['Restart needed', attention]
    else if (status.problem) [text, tone] = ['Needs attention', attention]
    else if (waiting > 0 && status.mode === 'by-hand') [text, tone] = [`${waiting} waiting`, attention]
    else if (waiting > 0) [text, tone] = [`${waiting} waiting`, calm]
    else if (status.mode === 'automatic') [text, tone] = ['By themselves', good]
    else [text, tone] = ['By hand', calm]
  }
  return (
    <button
      type="button"
      onClick={onOpen}
      className="rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium">
        <PackageCheck className="size-4" aria-hidden="true" />
        Updates
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
      return entry.actor === 'system'
        ? 'SGC restarted the device in the maintenance window, to finish an update'
        : `${entry.actor} restarted the device`
    case 'device.restart_failed':
      return 'Restarting the device failed'
    case 'update.started':
      if (entry.actor === 'system') return `SGC started updating itself ${entry.detail}`
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
    case 'certificate.terms_agreed':
      return `${entry.actor} agreed to ${entry.detail}`
    case 'certificate.issued':
      return `A certificate was issued: ${entry.detail}`
    case 'certificate.renewed':
      return entry.actor === 'system'
        ? `The certificate was renewed: ${entry.detail}`
        : `${entry.actor} renewed the certificate: ${entry.detail}`
    case 'certificate.failed':
      return `Getting the certificate failed: ${entry.detail}`
    case 'domain.saved':
      return `${entry.actor} saved the domain ${entry.detail}`
    case 'domain.removed':
      return `${entry.actor} removed the domain ${entry.detail}`
    case 'zone.check_failed':
      return `Zone.eu: ${entry.detail}`
    case 'zone.check_recovered':
      return `Zone.eu accepts the saved key for ${entry.detail} again`
    case 'log2ram.switched_on':
      return `${entry.actor} switched logs in memory on (${entry.detail})`
    case 'log2ram.switched_off':
      return `${entry.actor} switched logs in memory off (${entry.detail})`
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
    case 'ssh.key_added':
      return `${entry.actor} added the SSH key ${keyName(entry.detail)}`
    case 'ssh.key_removed':
      return `${entry.actor} removed the SSH key ${keyName(entry.detail)}`
    case 'ssh.keys_installed':
      return `${entry.actor} installed ${entry.detail.replace(/\(s\)/, 's')} on this device`
    case 'ssh.keys_only_on':
      return 'SSH now accepts keys only (a login with a key was seen)'
    case 'ssh.keys_only_off':
      return entry.actor === 'console'
        ? 'Password logins over SSH were allowed again at the device'
        : `${entry.actor} allowed password logins over SSH again`
    case 'ssh.change_started':
      return `${entry.actor}: ${entry.detail}, waiting for a login with a key`
    case 'ssh.change_undone':
      return entry.actor === 'system'
        ? 'A change to SSH was undone: the wait for a login with a key was interrupted'
        : `${entry.actor} undid a change to SSH (${entry.detail})`
    case 'ssh.change_expired':
      return 'A change to SSH was undone: no login with a key was seen in time'
    case 'ssh.change_failed':
      return 'A change to SSH failed'
    case 'dns.installed':
      return entry.actor === 'console'
        ? `${entry.detail} was installed with SGC, or from the command line`
        : `${entry.actor} installed ${entry.detail}`
    case 'dns.removed':
      return `${entry.actor} removed AdGuard Home`
    case 'dns.switched_on':
      return entry.actor === 'console'
        ? 'DNS was switched on from the command line'
        : `${entry.actor} switched DNS on`
    case 'dns.switched_off':
      return entry.actor === 'console'
        ? 'DNS was switched off from the command line'
        : `${entry.actor} switched DNS off`
    case 'dns.restored':
      return `DNS after the restore: ${entry.detail}`
    case 'os_updates.mode_automatic':
      return `${entry.actor} set updates for the device to install by themselves`
    case 'os_updates.mode_by_hand':
      return `${entry.actor} set updates for the device to be started by hand`
    case 'os_updates.change_failed':
      return 'Changing how the device gets its updates failed'
    case 'os_updates.install_started':
      return `${entry.actor} started installing updates for the device`
    case 'os_updates.installed': {
      // "2 updates: liblzma5, xz-utils, started by alex"
      const what = entry.detail.replace(/, started by .*$/, '')
      const [count, names] = what.split(': ')
      return names
        ? `Installed for the device: ${count} (${names})`
        : `Updates for the device: ${what}`
    }
    case 'os_updates.install_failed':
      return 'Installing updates for the device did not finish'
    default: {
      // The later parts: what happened, then the detail as SGC wrote it.
      const what = laterActions[entry.action]
      if (!what) return entry.action
      const who = entry.actor === 'system' ? 'SGC' : entry.actor
      return `${what.replace('{who}', who)}${entry.detail ? `: ${entry.detail}` : ''}`
    }
  }
}

const laterActions: Record<string, string> = {
  'gateway.renamed': '{who} renamed this device',
  'proxy.switched_on': '{who} switched the proxy on',
  'proxy.switched_off': '{who} switched the proxy off',
  'proxy.apply_failed': 'The proxy’s configuration was not put in place',
  'service.added': '{who} added a service',
  'service.changed': '{who} changed a service',
  'service.removed': '{who} removed a service',
  'service.announced': 'A server announced a service',
  'service.announce_refused': 'An announcement was refused',
  'service.approved': '{who} approved a service',
  'service.settings_changed': '{who} changed how services are handled',
  'token.created': '{who} made a token for a server',
  'token.removed': '{who} removed a server’s token',
  'token.repinned': '{who} let a server’s token move',
  'token.refused': 'A token was refused',
  'vpn.switched_on': '{who} switched the VPN on',
  'vpn.switched_off': '{who} switched the VPN off',
  'vpn.settings_changed': '{who} changed the VPN',
  'vpn.endpoint_updated': 'The VPN’s public name was updated',
  'vpn.endpoint_failed': 'The VPN’s public name could not be updated',
  'vpn.apply_failed': 'The VPN could not be changed',
  'person.added': '{who} added a person',
  'person.changed': '{who} changed a person',
  'person.removed': '{who} removed a person',
  'person.expired': 'A guest’s time ran out',
  'person.password_changed': '{who} changed their password',
  'device.added': '{who} added a device',
  'device.changed': '{who} changed a device',
  'device.removed': '{who} removed a device',
  'device.revealed': '{who} showed a device’s QR code',
  'gate.login': '{who} passed SGC’s login',
  'gate.login_failed': 'A sign-in at SGC’s login failed',
  'notify.settings_changed': '{who} changed the notifications',
  'notify.test_sent': '{who} sent a test notification',
  'backup.settings_changed': '{who} changed the backups',
  'backup.key_created': '{who} made a backup key',
  'backup.made': 'A backup was made',
  'backup.failed': 'A backup failed',
  'admin.reset': 'The admin’s password was set anew from the command line',
}

// "laptop (ED25519 SHA256:...) for the account alex" -> "laptop"
function keyName(detail: string): string {
  return detail.replace(/^removing /, '').replace(/ \((ED25519|ECDSA|RSA)[^)]*\).*$/, '')
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
