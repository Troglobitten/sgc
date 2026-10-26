import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { BadgeCheck, ChevronRight, Earth, Globe, KeyRound, Route, Shield, ShieldCheck, TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { GuideChecklist } from '@/components/guide-checklist'
import { HealthDot, ServiceIcon } from '@/components/service-icon'
import { PageTitle, SettingCard } from '@/components/setting'
import { AvailableUpdateCard } from '@/components/update-card'
import { UpdatingScreen } from '@/components/updating-screen'
import {
  api,
  ApiError,
  errorMessage,
  type AuditEntry,
  type CertificateStatus,
  type DnsStatus,
  type FirewallStatus,
  type Health,
  type Notification,
  type ProxyStatus,
  type PublicStatus,
  type Service,
  type SshStatus,
  type VpnStatus,
} from '@/lib/api'
import { daysUntil, formatDuration, formatTimeAgo, percentOf } from '@/lib/format'
import type { Page, SystemSection } from '@/lib/pages'
import { toneClass, type Tone } from '@/lib/tone'

const healthInterval = 3_000
const activityInterval = 15_000

/**
 * The dashboard: what needs the owner first, then SGC's parts in a word
 * each, then the services. Settings are on the other pages; every part here
 * links to where it is set.
 */
export function DashboardPage({ shell, onOpenGuide }: { shell: ShellProps; onOpenGuide: () => void }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null)
  const [ssh, setSsh] = useState<SshStatus | null>(null)
  const [dns, setDns] = useState<DnsStatus | null>(null)
  const [certificate, setCertificate] = useState<CertificateStatus | null>(null)
  const [services, setServices] = useState<Service[] | null>(null)
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus | null>(null)
  const [vpn, setVpn] = useState<VpnStatus | null>(null)
  const [internet, setInternet] = useState<PublicStatus | null>(null)
  const [attention, setAttention] = useState<Notification[] | null>(null)
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
    // Each part in a word: a part that cannot be asked just stays "…",
    // and only the essential ones (the activity) report a problem.
    const quiet = () => {}
    const load = () => {
      api.audit().then(
        (entries) => !stopped && setActivity(entries),
        (e) => !stopped && handleError(e),
      )
      api.notificationSummary().then((s) => !stopped && setAttention(s.banners), quiet)
      api.firewall().then((s) => !stopped && setFirewall(s), quiet)
      api.ssh().then((s) => !stopped && setSsh(s), quiet)
      api.dns().then((s) => !stopped && setDns(s), quiet)
      api.certificate().then((s) => !stopped && setCertificate(s), quiet)
      api.services().then((data) => !stopped && setServices(data.services), quiet)
      api.proxy().then((s) => !stopped && setProxyStatus(s), quiet)
      api.vpn().then((s) => !stopped && setVpn(s), quiet)
      api.publicStatus().then((s) => !stopped && setInternet(s), quiet)
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
      <PageTitle title="Dashboard" />
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

      {attention && attention.length > 0 && <NeedsAttention items={attention} onNavigate={onNavigate} />}

      <Section title="Status">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          <Tile icon={<Shield />} label="Firewall" {...firewallWord(firewall)} onOpen={() => onNavigate('system', 'security')} />
          <Tile icon={<KeyRound />} label="SSH" {...sshWord(ssh)} onOpen={() => onNavigate('system', 'security')} />
          <Tile icon={<Globe />} label="DNS" {...dnsWord(dns)} onOpen={() => onNavigate('system', 'dns')} />
          <Tile icon={<Route />} label="Proxy" {...proxyWord(proxyStatus)} onOpen={() => onNavigate('services')} />
          <Tile icon={<ShieldCheck />} label="VPN" {...vpnWord(vpn)} onOpen={() => onNavigate('people')} />
          <Tile icon={<Earth />} label="Internet" {...internetWord(internet)} onOpen={() => onNavigate('system', 'internet')} />
          <Tile
            icon={<BadgeCheck />}
            label="Certificate"
            {...certificateWord(certificate)}
            onOpen={() => onNavigate('system', 'domain')}
          />
        </div>
      </Section>

      {services && services.length > 0 && (
        <Section title="Your services" action={<SectionLink onClick={() => onNavigate('services')}>Manage</SectionLink>}>
          <ServiceGrid services={services} onManage={() => onNavigate('services')} />
        </Section>
      )}

      <div className="grid items-start gap-4 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <SettingCard title="Recent activity" status={<SectionLink onClick={() => onNavigate('logs')}>All activity</SectionLink>}>
          <ActivityList entries={activity} limit={6} />
        </SettingCard>
        <div className="flex flex-col gap-4">
          <AvailableUpdateCard onError={handleError} onUpdating={(previousAttempt) => setUpdating({ previousAttempt })} />
          <SettingCard
            title="This device"
            status={<SectionLink onClick={() => onNavigate('system', 'device')}>Details</SectionLink>}
          >
            {health ? (
              <>
                <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm tabular-nums">
                  <span>
                    Processor <b className="font-semibold">{Math.round(health.cpuPercent)}%</b>
                  </span>
                  <span>
                    Memory <b className="font-semibold">{percentOf(health.memoryUsedBytes, health.memoryTotalBytes)}%</b>
                  </span>
                  <span>
                    Disk <b className="font-semibold">{percentOf(health.diskUsedBytes, health.diskTotalBytes)}%</b>
                  </span>
                  {health.temperatureC !== null && <b className="font-semibold">{Math.round(health.temperatureC)} °C</b>}
                  <span>
                    up <b className="font-semibold">{formatDuration(health.uptimeSeconds)}</b>
                  </span>
                </p>
                <p className="text-[13px] text-muted-foreground">
                  {[health.model, health.os, bootMediumLabel(health.bootMedium)].filter(Boolean).join(' · ')}
                </p>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">…</p>
            )}
          </SettingCard>
        </div>
      </div>
    </AppShell>
  )
}

function Section({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-[15px] font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function SectionLink({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-0.5 rounded-sm text-sm font-medium text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      {children}
      <ChevronRight className="size-4" aria-hidden="true" />
    </button>
  )
}

/**
 * The problems that last (the notifications' banners), each once, with the
 * way to where it is put right. The bell keeps the history.
 */
function NeedsAttention({
  items,
  onNavigate,
}: {
  items: Notification[]
  onNavigate: (page: Page, section?: SystemSection | null) => void
}) {
  const serious = items.some((n) => n.severity === 'problem')
  return (
    <section
      aria-labelledby="attention-heading"
      className={
        serious
          ? 'rounded-xl bg-destructive/10 px-4 py-3'
          : 'rounded-xl bg-amber-500/10 px-4 py-3'
      }
    >
      <h2
        id="attention-heading"
        className={`flex items-center gap-2 text-[15px] font-semibold ${serious ? 'text-destructive' : 'text-amber-800 dark:text-amber-300'}`}
      >
        <TriangleAlert className="size-4" aria-hidden="true" />
        Needs your attention
      </h2>
      <ul className="mt-1 divide-y divide-foreground/10">
        {items.map((n) => {
          const where = whereFor(n)
          return (
            <li key={n.id} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
              <span className="text-sm">
                <span className="font-medium">{n.title}</span>
                {n.body && <span className="text-muted-foreground"> · {n.body}</span>}
              </span>
              <SectionLink onClick={() => onNavigate(where.page, where.section)}>{where.label}</SectionLink>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

/** Where a lasting problem is put right. */
function whereFor(n: Notification): { label: string; page: Page; section?: SystemSection } {
  switch (n.event) {
    case 'certificate':
    case 'domain':
      return { label: 'Domain', page: 'system', section: 'domain' }
    case 'public_ip':
      return { label: 'People', page: 'people' }
    case 'service_down':
    case 'abandoned':
    case 'announce':
      return { label: 'Services', page: 'services' }
    case 'health':
      return { label: 'This device', page: 'system', section: 'device' }
    case 'updates':
    case 'end_of_life':
      return { label: 'Updates', page: 'system', section: 'updates' }
    case 'backup':
      return { label: 'Backups', page: 'system', section: 'backups' }
    case 'internet':
      return { label: 'Internet', page: 'system', section: 'internet' }
    case 'core_down':
      if (/DNS|AdGuard/i.test(n.title)) return { label: 'DNS', page: 'system', section: 'dns' }
      if (/proxy|Traefik/i.test(n.title)) return { label: 'Services', page: 'services' }
      if (/VPN|WireGuard/i.test(n.title)) return { label: 'People', page: 'people' }
      return { label: 'System', page: 'system' }
    default:
      return { label: 'Logs', page: 'logs' }
  }
}

/** A part of SGC in a word, opening where it is set. */
function Tile({
  icon,
  label,
  text,
  tone,
  onOpen,
}: {
  icon: ReactNode
  label: string
  text: string
  tone: Tone
  onOpen: () => void
}) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex min-h-16 flex-col items-start gap-0.5 rounded-xl bg-card p-3 text-left ring-1 ring-foreground/10 outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="flex items-center gap-2 text-sm font-medium [&_svg]:size-4 [&_svg]:text-muted-foreground">
        {icon}
        {label}
      </span>
      <span className={`text-xs ${toneClass(tone)}`}>{text}</span>
    </button>
  )
}

type Word = { text: string; tone: Tone }
const waiting: Word = { text: '…', tone: 'muted' }

function firewallWord(s: FirewallStatus | null): Word {
  if (!s) return waiting
  if (s.state === 'pending') return { text: 'Waiting for confirmation', tone: 'warn' }
  if (s.state === 'off') return { text: 'Off', tone: 'warn' }
  if (s.behind.length > 0) return { text: 'On, rules behind', tone: 'warn' }
  return { text: 'On', tone: 'ok' }
}

function sshWord(s: SshStatus | null): Word {
  if (!s) return waiting
  if (!s.available) return { text: 'Could not be asked', tone: 'muted' }
  if (s.pending) return { text: 'Waiting for a login with a key', tone: 'warn' }
  if (s.keysOnly) return { text: 'Keys only', tone: 'ok' }
  return { text: 'Passwords allowed', tone: 'muted' }
}

function dnsWord(s: DnsStatus | null): Word {
  if (!s) return waiting
  if (!s.available) return { text: 'Could not be asked', tone: 'muted' }
  if (!s.enabled) return { text: 'Off', tone: 'muted' }
  if (s.running) return { text: 'Running', tone: 'ok' }
  return { text: 'Not running', tone: 'warn' }
}

function proxyWord(s: ProxyStatus | null): Word {
  if (!s) return waiting
  if (!s.wanted) return { text: 'Off', tone: 'muted' }
  if (s.running && s.lastApply?.ok !== false) return { text: 'Running', tone: 'ok' }
  if (s.running) return { text: 'Last change failed', tone: 'warn' }
  return { text: 'Not running', tone: 'warn' }
}

function internetWord(s: PublicStatus | null): Word {
  if (!s) return waiting
  if (!s.wanted) return { text: 'Nothing public', tone: 'muted' }
  if (s.problem) return { text: 'Needs a look', tone: 'warn' }
  const count = s.services.length
  return { text: count === 0 ? 'On, nothing public' : `${count} public`, tone: 'ok' }
}

function vpnWord(s: VpnStatus | null): Word {
  if (!s) return waiting
  if (!s.enabled) return { text: 'Off', tone: 'muted' }
  if (!s.running || !s.up) return { text: 'Not running', tone: 'warn' }
  const devices = s.devices.filter((d) => d.enabled)
  if (devices.length === 0) return { text: 'On, no devices yet', tone: 'ok' }
  const connected = devices.filter((d) => d.connected).length
  return { text: `${connected} of ${devices.length} devices connected`, tone: 'ok' }
}

function certificateWord(s: CertificateStatus | null): Word {
  if (!s) return waiting
  const current = s.certificate?.forDomain ? s.certificate : null
  const renewalFails = s.lastAttempt != null && !s.lastAttempt.ok && s.lastAttempt.kind === 'renewal'
  if (s.running) return { text: 'Being requested…', tone: 'muted' }
  if (current) {
    const days = daysUntil(current.notAfter)
    if (days < 0) return { text: 'Run out', tone: 'bad' }
    if (renewalFails) return { text: `${days} days left, renewing fails`, tone: 'warn' }
    return { text: `${days} days left`, tone: days < 14 ? 'warn' : 'ok' }
  }
  if (s.lastAttempt != null && !s.lastAttempt.ok) return { text: 'Last attempt failed', tone: 'warn' }
  return { text: 'Not set up yet', tone: 'muted' }
}

/** The services in use, grouped by category, each opening at its name. */
function ServiceGrid({ services, onManage }: { services: Service[]; onManage: () => void }) {
  const live = services.filter((s) => s.enabled && !s.pending)
  const waitingCount = services.length - live.length
  const categories = [...new Set(live.map((s) => s.category))]
  return (
    <div className="flex flex-col gap-3">
      {categories.map((category) => (
        <div key={category || '-'} className="flex flex-col gap-2">
          {categories.length > 1 && (
            <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              {category || 'Other'}
            </h3>
          )}
          <div className="grid grid-cols-1 gap-3 min-[420px]:grid-cols-2 lg:grid-cols-4">
            {live
              .filter((s) => s.category === category)
              .map((s) => {
                const inner = (
                  <>
                    <ServiceIcon service={s} />
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate text-sm font-medium">{s.title || s.name}</span>
                      <span className="truncate text-xs text-muted-foreground">
                        {s.kind === 'http' ? s.url.replace('https://', '') : s.url}
                      </span>
                    </span>
                    <HealthDot service={s} />
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
      {waitingCount > 0 && (
        <button type="button" onClick={onManage} className="self-start text-sm text-muted-foreground hover:underline">
          {waitingCount} more switched off or waiting for approval
        </button>
      )}
    </div>
  )
}

function ActivityList({ entries, limit }: { entries: AuditEntry[] | null; limit: number }) {
  if (entries === null) return <p className="text-sm text-muted-foreground">…</p>
  if (entries.length === 0) return <p className="text-sm text-muted-foreground">Nothing yet.</p>
  return (
    <ul className="divide-y">
      {entries.slice(0, limit).map((entry) => (
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
      return `The DNS provider: ${entry.detail}`
    case 'zone.check_recovered':
      return `The DNS provider accepts the saved key for ${entry.detail} again`
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
  'service.public_opened': '{who} made a service reachable from the internet',
  'service.public_closed': 'A service was closed to the internet',
  'public.access_on': '{who} switched internet access on',
  'public.access_off': 'Internet access was switched off',
  'public.settings_changed': '{who} changed how visitors from the internet are filtered',
  'public.list_failed': 'A list of attackers could not be fetched',
  'public.unbanned': '{who} lifted a ban',
  'public.record_changed': 'A public name was updated',
  'public.record_failed': 'A public name could not be updated',
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
  'admin.password_changed': '{who} changed their password; every other sign-in ended',
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
