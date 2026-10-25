import { useState, type FormEvent } from 'react'
import { BarChart3, Plus, QrCode } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { DeviceConfigDialog } from '@/components/device-config-dialog'
import { UsageChart } from '@/components/usage-chart'
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
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  api,
  errorMessage,
  type Person,
  type PersonInput,
  type Service,
  type VpnDevice,
  type VpnStatus,
} from '@/lib/api'
import { formatBytes, formatDate, formatTimeAgo } from '@/lib/format'

const blank: PersonInput = {
  name: '',
  network: 'services',
  allServices: true,
  serviceIds: [],
  loginEnabled: false,
  username: '',
  password: '',
  expiresAt: null,
  disabled: false,
}

/** Everybody the owner lets in, each with their devices. */
export function PeopleManager({
  people,
  services,
  vpn,
  onChanged,
}: {
  people: Person[]
  services: Service[]
  vpn: VpnStatus
  onChanged: () => void
}) {
  const [adding, setAdding] = useState(false)
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-[15px] font-semibold">People</h2>
        {!adding && (
          <Button size="sm" onClick={() => setAdding(true)}>
            <Plus />
            Add a person
          </Button>
        )}
      </div>
      {adding && (
        <Card>
          <CardContent>
            <PersonForm
              initial={blank}
              services={services}
              onCancel={() => setAdding(false)}
              onSave={async (input) => {
                await api.addPerson(input)
                setAdding(false)
                onChanged()
              }}
            />
          </CardContent>
        </Card>
      )}
      {people.length === 0 && !adding && (
        <p className="text-sm text-muted-foreground">
          Nobody yet. Add yourself first (whole home network), then family and guests.
        </p>
      )}
      {people.map((person) => (
        <PersonCard
          key={person.id}
          person={person}
          services={services}
          vpn={vpn}
          devices={vpn.devices.filter((d) => d.personId === person.id)}
          onChanged={onChanged}
        />
      ))}
    </div>
  )
}

function accessWords(person: Person, services: Service[]): string {
  if (person.network === 'full') return 'the whole home network'
  if (person.allServices) return 'all services'
  const names = services.filter((s) => person.serviceIds.includes(s.id)).map((s) => s.title || s.name)
  return names.length > 0 ? names.join(', ') : 'no services yet'
}

function PersonCard({
  person,
  services,
  vpn,
  devices,
  onChanged,
}: {
  person: Person
  services: Service[]
  vpn: VpnStatus
  devices: VpnDevice[]
  onChanged: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [newDevice, setNewDevice] = useState('')
  const [allTraffic, setAllTraffic] = useState(false)
  const [revealing, setRevealing] = useState<VpnDevice | null>(null)
  const [usageFor, setUsageFor] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function addDevice(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      const device = await api.addDevice(person.id, newDevice.trim(), allTraffic && person.network === 'full')
      setNewDevice('')
      onChanged()
      setRevealing(device)
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        {editing ? (
          <PersonForm
            initial={{ ...person, password: '' }}
            services={services}
            existing
            onCancel={() => setEditing(false)}
            onSave={async (input) => {
              await api.updatePerson(person.id, input)
              setEditing(false)
              onChanged()
            }}
          />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p className="font-medium">
                {person.name}
                {!person.active && (
                  <span className="ml-2 text-xs font-normal text-amber-700 dark:text-amber-400">
                    {person.disabled ? 'switched off' : 'past their end date'}
                  </span>
                )}
              </p>
              <p className="text-sm text-muted-foreground">
                Reaches {accessWords(person, services)}
                {person.loginEnabled && ` · login ${person.username}`}
                {person.expiresAt && ` · until ${formatDate(person.expiresAt)}`}
              </p>
            </div>
            <div className="flex gap-1">
              <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
                Change
              </Button>
              <Button size="sm" variant="ghost" className="text-muted-foreground" onClick={() => setRemoving(true)}>
                Remove
              </Button>
            </div>
          </div>
        )}

        {devices.length > 0 && (
          <ul className="flex flex-col gap-2">
            {devices.map((d) => (
              <li key={d.id} className="flex flex-col gap-2 rounded-lg bg-muted/40 p-2 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex items-center gap-2">
                    <span
                      className={`size-2 rounded-full ${d.connected ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`}
                      title={d.connected ? 'connected' : 'not connected'}
                    />
                    <span className="font-medium">{d.name}</span>
                    <span className="text-xs text-muted-foreground">
                      {d.address} · {d.allTraffic ? "uses home's internet connection too" : 'home only, its own internet'}
                      {!d.enabled && ' · switched off'}
                    </span>
                  </span>
                  <span className="flex gap-1">
                    <Button size="icon-sm" variant="ghost" aria-label={`Usage of ${d.name}`} onClick={() => setUsageFor(usageFor === d.id ? null : d.id)}>
                      <BarChart3 />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setRevealing(d)}>
                      <QrCode />
                      QR code
                    </Button>
                    <Button size="sm" variant="ghost"
                      onClick={() => api.updateDevice(d.id, d.name, d.allTraffic, !d.enabled).then(onChanged, (e) => setError(errorMessage(e)))}>
                      {d.enabled ? 'Switch off' : 'Switch on'}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => api.removeDevice(d.id).then(onChanged, (e) => setError(errorMessage(e)))}>
                      Remove
                    </Button>
                  </span>
                </div>
                {d.allTraffic && person.network !== 'full' && (
                  <div className="flex flex-col gap-1.5 rounded-md bg-amber-500/10 p-2 text-xs text-amber-800 dark:text-amber-300">
                    <p>
                      This device sends all its traffic through home, but {person.name} reaches chosen services only, so
                      it has no internet while the VPN is on. Set it to home only, then give it its new settings (QR
                      code).
                    </p>
                    <Button size="xs" variant="outline" className="self-start"
                      onClick={() => api.updateDevice(d.id, d.name, false, d.enabled).then(onChanged, (e) => setError(errorMessage(e)))}>
                      Set to home only
                    </Button>
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {d.lastSeen ? `last seen ${formatTimeAgo(d.lastSeen)}` : 'never connected'}
                  {d.endpoint && ` from ${d.endpoint.replace(/:\d+$/, '')}`}
                  {vpn.totals[String(d.id)] &&
                    ` · used ${formatBytes(vpn.totals[String(d.id)].rx + vpn.totals[String(d.id)].tx)} in all`}
                </p>
                {usageFor === d.id && <UsageChart device={d.id} />}
              </li>
            ))}
          </ul>
        )}

        {vpn.enabled && person.active && (
          <form onSubmit={addDevice} className="flex flex-wrap items-center gap-2">
            <Input placeholder="phone, laptop…" value={newDevice} maxLength={40} className="max-w-44" onChange={(e) => setNewDevice(e.target.value)} />
            {person.network === 'full' && (
              <label className="flex items-center gap-2 text-sm">
                <Switch checked={allTraffic} onCheckedChange={setAllTraffic} size="sm" />
                use home's internet connection too
              </label>
            )}
            <Button type="submit" size="sm" variant="outline" disabled={!newDevice.trim()}>
              Add a device
            </Button>
            <p className="w-full text-xs text-muted-foreground">
              {person.network === 'full'
                ? "What the device reaches at home is set for the person above. The switch is about the rest: on, all the device's traffic goes through home, as on a public Wi-Fi; off, only what is for home goes through the VPN and the device keeps its own internet."
                : `${person.name} reaches chosen services only: their devices send through the VPN only what is for home and keep their own internet connection for the rest.`}
            </p>
          </form>
        )}
        <FormError message={error} />
      </CardContent>
      {revealing && <DeviceConfigDialog device={revealing} onClose={() => setRevealing(null)} />}
      {removing && (
        <AlertDialog open onOpenChange={(open) => !open && setRemoving(false)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Remove {person.name}?</AlertDialogTitle>
              <AlertDialogDescription>
                Their devices stop working at once, and their login too.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <Button variant="outline" onClick={() => api.removePerson(person.id).then(onChanged, (e) => setError(errorMessage(e))).finally(() => setRemoving(false))}>
                Remove
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
    </Card>
  )
}

function PersonForm({
  initial,
  services,
  existing = false,
  onCancel,
  onSave,
}: {
  initial: PersonInput
  services: Service[]
  existing?: boolean
  onCancel: () => void
  onSave: (input: PersonInput) => Promise<void>
}) {
  const [input, setInput] = useState<PersonInput>(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = (patch: Partial<PersonInput>) => setInput((current) => ({ ...current, ...patch }))

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onSave(input)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const live = services.filter((s) => s.enabled && !s.pending)
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="person-name">Name</Label>
        <Input id="person-name" value={input.name} maxLength={60} onChange={(e) => set({ name: e.target.value })} />
      </div>
      <fieldset className="flex flex-col gap-1.5 text-sm">
        <legend className="mb-1 font-medium">Their VPN devices reach</legend>
        <label className="flex items-center gap-2">
          <input type="radio" checked={input.network === 'full'} onChange={() => set({ network: 'full' })} />
          The whole home network, SGC’s page included (for you)
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" checked={input.network === 'services' && input.allServices} onChange={() => set({ network: 'services', allServices: true })} />
          All services, nothing else of the home network
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" checked={input.network === 'services' && !input.allServices} onChange={() => set({ network: 'services', allServices: false })} />
          Only these services:
        </label>
      </fieldset>
      {input.network === 'services' && !input.allServices && (
        <div className="grid gap-1 pl-6 text-sm sm:grid-cols-2">
          {live.length === 0 && <p className="text-muted-foreground">No services yet.</p>}
          {live.map((s) => (
            <label key={s.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={input.serviceIds.includes(s.id)}
                onChange={(e) =>
                  set({ serviceIds: e.target.checked ? [...input.serviceIds, s.id] : input.serviceIds.filter((id) => id !== s.id) })
                }
              />
              {s.title || s.name}
            </label>
          ))}
        </div>
      )}
      <label className="flex items-center gap-2 text-sm">
        <Switch checked={input.loginEnabled} onCheckedChange={(v) => set({ loginEnabled: v })} />
        A login for services behind SGC’s login (never for SGC’s own page)
      </label>
      {input.loginEnabled && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="person-username">Username</Label>
            <Input id="person-username" value={input.username} autoCapitalize="none" maxLength={40} onChange={(e) => set({ username: e.target.value })} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="person-password">{existing ? 'New password (empty: keep it)' : 'Password'}</Label>
            <Input id="person-password" type="password" autoComplete="new-password" value={input.password} onChange={(e) => set({ password: e.target.value })} />
          </div>
          <p className="text-xs text-muted-foreground sm:col-span-2">
            They can change it themselves: on SGC's sign-in page, the address of this page with <code>/gate</code> at
            the end (https://sgc.your-domain/gate), under "Change my password". That also signs them out everywhere
            else.
          </p>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <label className="flex items-center gap-2">
          <Switch checked={input.expiresAt !== null} onCheckedChange={(v) => set({ expiresAt: v ? new Date(Date.now() + 7 * 86400_000).toISOString() : null })} />
          A guest until
        </label>
        {input.expiresAt !== null && (
          <Input type="date" className="w-40" value={input.expiresAt.slice(0, 10)}
            onChange={(e) => e.target.value && set({ expiresAt: new Date(`${e.target.value}T23:59:00`).toISOString() })} />
        )}
      </div>
      {existing && (
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={input.disabled} onCheckedChange={(v) => set({ disabled: v })} />
          Switched off (devices and login stop, nothing is removed)
        </label>
      )}
      <FormError message={error} />
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy || !input.name.trim()}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
