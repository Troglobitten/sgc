import { useState, type FormEvent } from 'react'
import { Earth } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { FirewallFollowUp } from '@/components/firewall-follow-up'
import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type PublicSettings, type PublicStatus } from '@/lib/api'
import { formatDateTime, formatTimeAgo } from '@/lib/format'
import { usePolled } from '@/lib/poll'

const selectClass =
  'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30'

/**
 * Services reachable from the internet (docs/design.md §14): the switch for
 * internet access, what the router must forward, and how visitors from the
 * internet are limited and filtered. Each card saves its own part of the
 * settings.
 */
export function InternetSection({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = usePolled(api.publicStatus, 20_000, onError)
  if (!status) return <p className="text-sm text-muted-foreground">…</p>
  const save = async (patch: Partial<PublicSettings>) => {
    setStatus(await api.savePublicSettings({ ...status.settings, ...patch }))
  }
  return (
    <>
      <InternetAccessCard status={status} onChange={setStatus} />
      <VisitorsCard settings={status.settings} save={save} />
      <ListsCard status={status} save={save} />
      <CountriesCard status={status} save={save} />
      <Fail2banCard status={status} save={save} />
    </>
  )
}

function InternetAccessCard({ status, onChange }: { status: PublicStatus; onChange: (next: PublicStatus) => void }) {
  const [asking, setAsking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const on = status.wanted
  const count = status.services.length

  async function switchOff() {
    setBusy(true)
    setError(null)
    try {
      onChange(await api.setPublicEnabled(false))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const badge = on ? (
    <StatusBadge tone={status.problem ? 'warn' : 'ok'}>{count === 0 ? 'On, nothing public' : `${count} public`}</StatusBadge>
  ) : (
    <StatusBadge tone="muted">Off</StatusBadge>
  )
  const lan = status.lanAddress || 'this device'
  const ownPorts = status.services.filter((s) => s.kind !== 'http')
  return (
    <SettingCard title="Internet access" status={badge}>
      <div className="flex items-start justify-between gap-4">
        <p className="text-sm">
          {on
            ? 'Services you make public on the Services page can be reached from the internet. Nothing else can: not SGC’s page, not AdGuard Home, not any other service.'
            : 'Off: nothing in your home network is reachable from the internet through SGC (the VPN aside). Switch it on to make chosen services public.'}
        </p>
        <Switch checked={on} disabled={busy} onCheckedChange={(v) => (v ? setAsking(true) : switchOff())} aria-label="Internet access" />
      </div>
      {on && (
        <>
          <div className="rounded-lg bg-muted/50 p-3 text-sm">
            <p className="font-medium">On your router</p>
            <p>
              Forward TCP port <b>443</b> from the internet to <b>{lan}</b>, port <b>{status.doorPort}</b>. That one forward serves every
              website you make public.
            </p>
            {ownPorts.length > 0 && (
              <ul className="mt-1 list-disc pl-5">
                {ownPorts.map((s) => (
                  <li key={s.id}>
                    {s.title || s.name}: forward {s.kind.toUpperCase()} port <b>{s.port}</b> to <b>{lan}</b>, port <b>{s.localPort}</b>.
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-1 text-xs text-muted-foreground">
              SGC cannot see your router. Try a public service from a phone with Wi-Fi switched off to see that it answers.
            </p>
          </div>
          {status.problem && <Warning>{status.problem}</Warning>}
          {count > 0 && (
            <div className="flex flex-col gap-1.5 text-sm">
              {status.services.map((s) => (
                <div key={s.id} className="flex flex-wrap items-baseline justify-between gap-x-3">
                  <span className="inline-flex items-center gap-1.5 font-medium">
                    <Earth className="size-3.5 text-muted-foreground" aria-hidden="true" />
                    {s.title || s.name}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {s.record.problem
                      ? s.record.problem
                      : s.record.ok
                        ? `${s.record.name} → ${s.record.address}${s.record.srv ? ' · with its SRV record' : ''}`
                        : 'Its public name is being made…'}
                  </span>
                  {s.record.srvManual && (
                    <p className="w-full text-xs text-amber-700 dark:text-amber-400">
                      Your DNS provider’s API cannot make SRV records: add this one by hand at the provider: <code>{s.record.srvManual}</code>
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
          {status.publicIp && <Facts items={[['The internet sees your home at', status.publicIp]]} />}
          <FirewallFollowUp watch={status.wanted} />
        </>
      )}
      <FormError message={error} />
      <More>
        <p>
          A public website is reached through one door: the router sends the internet’s port 443 to this device’s port {status.doorPort}, where only
          the services you made public have a route. Any other public service (a game or voice server, mail, file transfer, …) has a port of its own. Every visitor from the internet passes the limits
          and filters below first.
        </p>
        <p>
          A public service relies on its own login, unless it is behind SGC’s login: then visitors sign in under the service’s own name. Keep public
          services up to date: one that is broken into is inside your home network, which SGC cannot stop. If your router can put such servers on a
          network of their own, that is the real safeguard.
        </p>
        <p>
          SGC closes a public service by itself when its server announces it anew with other settings, when its token is removed or its server moved,
          and when it is switched off. Switching internet access off closes every public service, and so does restoring an export. Only you open a
          service again, on the Services page.
        </p>
      </More>
      {asking && <SwitchOnDialog onClose={() => setAsking(false)} onDone={(next) => { setAsking(false); onChange(next) }} />}
    </SettingCard>
  )
}

function SwitchOnDialog({ onClose, onDone }: { onClose: () => void; onDone: (next: PublicStatus) => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onDone(await api.setPublicEnabled(true, password))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }
  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Switch internet access on?</AlertDialogTitle>
          <AlertDialogDescription>
            The proxy gets a public door, and the firewall then needs its rules brought up to date (with the usual confirmation). Nothing becomes
            public until you open a service on the Services page.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <form id="internet-on" onSubmit={submit} className="flex flex-col gap-1.5 text-sm">
          <Label htmlFor="internet-password">Your admin password</Label>
          <Input id="internet-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </form>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button type="submit" form="internet-on" disabled={busy || password === ''}>
            {busy ? 'Switching on…' : 'Switch on'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** A small form for a card: busy, error and saved states. */
function useSaving() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const run = async (work: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    setSaved(false)
    try {
      await work()
      setSaved(true)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, saved, run }
}

function VisitorsCard({ settings, save }: { settings: PublicSettings; save: (patch: Partial<PublicSettings>) => Promise<void> }) {
  const [requests, setRequests] = useState(String(settings.requestsPerMinute))
  const [connections, setConnections] = useState(String(settings.connectionsPerMinute))
  const [allow, setAllow] = useState(settings.allow.join('\n'))
  const { busy, error, saved, run } = useSaving()
  function submit(event: FormEvent) {
    event.preventDefault()
    run(() =>
      save({
        requestsPerMinute: Number(requests),
        connectionsPerMinute: Number(connections),
        allow: allow.split(/[\s,]+/).filter(Boolean),
      }),
    )
  }
  return (
    <SettingCard title="Visitors from the internet">
      <form onSubmit={submit} className="flex flex-col gap-3 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="pub-requests">Requests a minute, per visitor</Label>
            <Input id="pub-requests" type="number" min={10} max={100000} value={requests} onChange={(e) => setRequests(e.target.value)} />
            <p className="text-xs text-muted-foreground">For websites. More are answered “too many requests”.</p>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="pub-connections">New connections a minute, per visitor</Label>
            <Input id="pub-connections" type="number" min={1} max={10000} value={connections} onChange={(e) => setConnections(e.target.value)} />
            <p className="text-xs text-muted-foreground">For every public port, websites and other services alike. More are dropped.</p>
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="pub-allow">Always let in (allow list)</Label>
          <textarea
            id="pub-allow"
            rows={3}
            value={allow}
            onChange={(e) => setAllow(e.target.value)}
            spellCheck={false}
            placeholder="198.51.100.7&#10;203.0.113.0/24"
            className="rounded-lg border border-input bg-transparent px-2.5 py-1.5 font-mono text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          />
          <p className="text-xs text-muted-foreground">
            IPv4 addresses or ranges, one a line: a friend whose address a list or a ban would keep out. They get past every filter and ban.
          </p>
        </div>
        <FormError message={error} />
        <div className="flex items-center gap-3">
          <Button type="submit" size="sm" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
          {saved && <span className="text-xs text-muted-foreground">Saved and in place.</span>}
        </div>
      </form>
    </SettingCard>
  )
}

function ListsCard({ status, save }: { status: PublicStatus; save: (patch: Partial<PublicSettings>) => Promise<void> }) {
  const { busy, error, run } = useSaving()
  const levels = status.lists.filter((l) => l.name.startsWith('firehol_'))
  const toggle = (name: string, on: boolean) =>
    run(() => save({ levels: on ? [...status.settings.levels, name] : status.settings.levels.filter((l) => l !== name) }))
  const count = status.settings.levels.length
  return (
    <SettingCard title="Lists of known attackers" status={<StatusBadge tone={count ? 'ok' : 'muted'}>{count ? `${count} of 4` : 'Off'}</StatusBadge>}>
      <p className="text-sm">
        FireHOL’s lists of addresses that attack. Each is a list of its own, from other sources; visitors on one that is switched on are refused.
        SGC fetches them every day in the maintenance window.
      </p>
      <div className="flex flex-col gap-3">
        {levels.map((l) => (
          <label key={l.name} className="flex items-start justify-between gap-4 text-sm">
            <span>
              {l.label}
              <span className="block text-xs text-muted-foreground">{l.description}</span>
              {l.enabled && (
                <span className={`block text-xs ${l.error ? 'text-amber-700 dark:text-amber-400' : 'text-muted-foreground'}`}>
                  {l.error
                    ? `The last download failed ${l.errorAt ? formatTimeAgo(l.errorAt) : ''}: ${l.error}${l.updatedAt ? ` (the one from ${formatTimeAgo(l.updatedAt)} stays in use)` : ''}`
                    : l.updatedAt
                      ? `${l.entries.toLocaleString('en-GB')} addresses and ranges, fetched ${formatTimeAgo(l.updatedAt)}`
                      : ''}
                </span>
              )}
            </span>
            <Switch checked={l.enabled} disabled={busy} onCheckedChange={(v) => toggle(l.name, v)} aria-label={l.label} />
          </label>
        ))}
      </div>
      {busy && <p className="text-xs text-muted-foreground">Fetching and putting it in place…</p>}
      <FormError message={error} />
      <p className="text-xs text-muted-foreground">
        Lists:{' '}
        <a href="https://iplists.firehol.org/" target="_blank" rel="noreferrer" className="underline-offset-4 hover:underline">
          FireHOL IP lists
        </a>
        .
      </p>
    </SettingCard>
  )
}

// ISO 3166-1 country codes; the names come from the browser.
const countryCodes =
  'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ')

const regionNames = typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['en'], { type: 'region' }) : null
const countryName = (code: string) => regionNames?.of(code) ?? code
const countriesByName = [...countryCodes].sort((a, b) => countryName(a).localeCompare(countryName(b), 'en'))

function CountriesCard({ status, save }: { status: PublicStatus; save: (patch: Partial<PublicSettings>) => Promise<void> }) {
  const [mode, setMode] = useState<PublicSettings['countryMode']>(status.settings.countryMode)
  const [countries, setCountries] = useState<string[]>(status.settings.countries)
  const { busy, error, saved, run } = useSaving()
  const list = status.lists.find((l) => l.name === 'dbip-country')
  const badge =
    status.settings.countryMode === 'allow' ? (
      <StatusBadge tone="ok">Only from {status.settings.countries.length}</StatusBadge>
    ) : status.settings.countryMode === 'block' ? (
      <StatusBadge tone="ok">Not from {status.settings.countries.length}</StatusBadge>
    ) : (
      <StatusBadge tone="muted">Off</StatusBadge>
    )
  return (
    <SettingCard title="Countries" status={badge}>
      <p className="text-sm">Let in visitors from chosen countries only, or from anywhere but chosen countries. Your home network and the VPN are never affected.</p>
      <div className="grid gap-3 text-sm sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="pub-country-mode">Visitors</Label>
          <select id="pub-country-mode" className={selectClass} value={mode} onChange={(e) => setMode(e.target.value as PublicSettings['countryMode'])}>
            <option value="">From anywhere (off)</option>
            <option value="allow">Only from these countries</option>
            <option value="block">From anywhere but these countries</option>
          </select>
        </div>
        {mode !== '' && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="pub-country-add">Add a country</Label>
            <select
              id="pub-country-add"
              className={selectClass}
              value=""
              onChange={(e) => e.target.value && setCountries((c) => (c.includes(e.target.value) ? c : [...c, e.target.value]))}
            >
              <option value="">Choose…</option>
              {countriesByName.map((code) => (
                <option key={code} value={code} disabled={countries.includes(code)}>
                  {countryName(code)}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
      {mode !== '' && (
        <div className="flex flex-wrap gap-1.5">
          {countries.length === 0 && <span className="text-xs text-muted-foreground">No country chosen yet.</span>}
          {countries.map((code) => (
            <button
              key={code}
              type="button"
              onClick={() => setCountries((c) => c.filter((x) => x !== code))}
              className="rounded-full bg-muted px-2.5 py-0.5 text-xs hover:bg-muted/70"
              aria-label={`Remove ${countryName(code)}`}
            >
              {countryName(code)} ×
            </button>
          ))}
        </div>
      )}
      {mode === 'allow' && (
        <p className="text-xs text-muted-foreground">You, travelling, and friends abroad are then refused too: use the VPN, or the allow list.</p>
      )}
      <FormError message={error} />
      <div className="flex items-center gap-3">
        <Button size="sm" disabled={busy || (mode !== '' && countries.length === 0)} onClick={() => run(() => save({ countryMode: mode, countries: mode ? countries : [] }))}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        {saved && <span className="text-xs text-muted-foreground">Saved and in place.</span>}
      </div>
      {list?.enabled && (list.updatedAt || list.error) && (
        <p className={`text-xs ${list.error ? 'text-amber-700 dark:text-amber-400' : 'text-muted-foreground'}`}>
          {list.error ? `The last download of the country list failed: ${list.error}` : `Country list fetched ${formatTimeAgo(list.updatedAt!)}, once a month.`}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        <a href="https://db-ip.com" target="_blank" rel="noreferrer" className="underline-offset-4 hover:underline">
          IP Geolocation by DB-IP
        </a>{' '}
        (IP to Country Lite, CC BY 4.0).
      </p>
    </SettingCard>
  )
}

function Fail2banCard({ status, save }: { status: PublicStatus; save: (patch: Partial<PublicSettings>) => Promise<void> }) {
  const f = status.settings.fail2ban
  const [signIns, setSignIns] = useState(String(f.signIns))
  const [refused, setRefused] = useState(String(f.refused))
  const [find, setFind] = useState(String(f.findMinutes))
  const [ban, setBan] = useState(String(f.banMinutes))
  const { busy, error, saved, run } = useSaving()
  const numbers = { signIns: Number(signIns), refused: Number(refused), findMinutes: Number(find), banMinutes: Number(ban) }
  return (
    <SettingCard title="Banning repeat offenders" status={<StatusBadge tone={f.enabled ? 'ok' : 'muted'}>{f.enabled ? 'On' : 'Off'}</StatusBadge>}>
      <div className="flex items-start justify-between gap-4">
        <p className="text-sm">
          fail2ban bans an address from the internet for a while when it fails too often: at SGC’s login on a public service, or with requests the
          public door refuses. Home addresses and the allow list are never banned.
          {!status.fail2banInstalled && ' Switching it on installs it from Debian first.'}
        </p>
        <Switch checked={f.enabled} disabled={busy} onCheckedChange={(v) => run(() => save({ fail2ban: { ...f, ...numbers, enabled: v } }))} aria-label="fail2ban" />
      </div>
      <div className="grid gap-3 text-sm sm:grid-cols-2">
        <NumberField id="f2b-signins" label="Failed sign-ins before a ban" value={signIns} onChange={setSignIns} min={1} max={100} />
        <NumberField id="f2b-refused" label="Refused requests before a ban" value={refused} onChange={setRefused} min={1} max={10000} />
        <NumberField id="f2b-find" label="Within (minutes)" value={find} onChange={setFind} min={1} max={1440} />
        <NumberField id="f2b-ban" label="Banned for (minutes)" value={ban} onChange={setBan} min={1} max={525600} />
      </div>
      <FormError message={error} />
      <div className="flex items-center gap-3">
        <Button size="sm" variant="outline" disabled={busy} onClick={() => run(() => save({ fail2ban: { ...f, ...numbers } }))}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        {saved && <span className="text-xs text-muted-foreground">Saved and in place.</span>}
      </div>
      {f.enabled && <Bans />}
    </SettingCard>
  )
}

function NumberField({ id, label, value, onChange, min, max }: { id: string; label: string; value: string; onChange: (v: string) => void; min: number; max: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="number" min={min} max={max} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  )
}

function Bans() {
  const [error, setError] = useState<string | null>(null)
  const [bans, setBans] = usePolled(api.publicBans, 30_000, (e) => setError(errorMessage(e)))
  if (!bans) return error ? <FormError message={error} /> : null
  return (
    <div className="flex flex-col gap-1.5 text-sm">
      <p className="font-medium">Banned now</p>
      {bans.length === 0 && <p className="text-xs text-muted-foreground">Nobody.</p>}
      {bans.map((b) => (
        <div key={`${b.jail}-${b.address}`} className="flex items-center justify-between gap-3">
          <span>
            <span className="font-mono">{b.address}</span>
            <span className="block text-xs text-muted-foreground">
              {b.jail === 'sgc-signin' ? 'failed sign-ins' : 'refused requests'} · until {formatDateTime(b.until)}
            </span>
          </span>
          <Button size="sm" variant="ghost" onClick={() => api.unban(b.address).then(setBans, (e) => setError(errorMessage(e)))}>
            Unban
          </Button>
        </div>
      ))}
      <FormError message={error} />
    </div>
  )
}
