import { useState, type FormEvent, type ReactNode } from 'react'
import { Ellipsis, ExternalLink, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { HealthDot, ServiceIcon } from '@/components/service-icon'
import { SettingCard, StatusBadge } from '@/components/setting'
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  api,
  errorMessage,
  type IconsStatus,
  type Person,
  type Service,
  type ServiceInput,
  type ServicesResponse,
  type ServicesSettings,
} from '@/lib/api'
import { formatDate, formatTimeAgo } from '@/lib/format'

const selectClass =
  'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30'

const blank: ServiceInput = {
  name: '',
  title: '',
  kind: 'http',
  mode: 'direct',
  upstreamIp: '',
  upstreamPort: 80,
  scheme: 'http',
  verifyTls: false,
  listenPort: 0,
  category: '',
  protected: false,
  enabled: true,
}

/**
 * Every service behind SGC's names: add, change, approve, remove. One row
 * each; the rare actions are behind the row's ⋯ button. The page owns the
 * data (it is shared with the Settings tab).
 */
export function ServicesManager({
  data,
  people,
  refresh,
  onError,
}: {
  data: ServicesResponse
  people: Person[]
  refresh: () => void
  onError: (error: unknown) => void
}) {
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Service | null>(null)
  const [removing, setRemoving] = useState<Service | null>(null)

  const pending = data.services.filter((s) => s.pending)
  const listed = data.services.filter((s) => !s.pending)
  const categories = [...new Set(listed.map((s) => s.category))]
  const answering = listed.filter((s) => s.enabled && s.health.state === 'up').length

  return (
    <div className="flex flex-col gap-4">
      {pending.length > 0 && (
        <SettingCard title="Waiting for your approval" status={<StatusBadge tone="warn">{pending.length}</StatusBadge>}>
          {pending.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span>
                <span className="font-medium">{s.name}</span> at {s.upstreamIp}:{s.upstreamPort}, announced by{' '}
                {s.tokenLabel || 'a removed token'}
              </span>
              <span className="flex gap-2">
                <Button size="sm" onClick={() => api.approveService(s.id).then(refresh, onError)}>
                  Approve
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setRemoving(s)}>
                  Remove
                </Button>
              </span>
            </div>
          ))}
        </SettingCard>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {listed.length === 0
            ? 'No services yet.'
            : `${listed.length} ${listed.length === 1 ? 'service' : 'services'} · ${answering} ${answering === 1 ? 'answers' : 'answer'}`}
        </p>
        {!adding && (
          <Button onClick={() => setAdding(true)}>
            <Plus />
            Add a service
          </Button>
        )}
      </div>

      {adding && (
        <SettingCard title="A new service">
          <ServiceForm
            initial={blank}
            onCancel={() => setAdding(false)}
            onSave={async (input) => {
              await api.addService(input)
              setAdding(false)
              refresh()
            }}
          />
        </SettingCard>
      )}

      {listed.length === 0 && !adding && (
        <p className="text-sm text-muted-foreground">
          Add one here for a device that cannot announce itself (a router, a printer, a NAS), or give a server a token
          (Servers that announce) and let it announce its own.
        </p>
      )}

      {categories.map((category) => (
        <section key={category || '-'} className="flex flex-col gap-2">
          {categories.length > 1 && (
            <h2 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{category || 'Other'}</h2>
          )}
          <div className="divide-y overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
            {listed
              .filter((s) => s.category === category)
              .map((s) =>
                editing?.id === s.id ? (
                  <div key={s.id} className="p-4">
                    <ServiceForm
                      initial={s}
                      announced={s.tokenId !== null}
                      onCancel={() => setEditing(null)}
                      onSave={async (input) => {
                        await api.updateService(s.id, input)
                        setEditing(null)
                        refresh()
                      }}
                    />
                  </div>
                ) : (
                  <ServiceRow
                    key={s.id}
                    service={s}
                    people={people}
                    onEdit={() => setEditing(s)}
                    onRemove={() => setRemoving(s)}
                    onRefreshIcon={() => api.refreshServiceIcon(s.id).then(() => setTimeout(refresh, 4000), onError)}
                  />
                ),
              )}
          </div>
        </section>
      ))}

      {removing && (
        <RemoveDialog
          service={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            setRemoving(null)
            refresh()
          }}
        />
      )}
    </div>
  )
}

function describeWay(s: Service): string {
  if (s.kind === 'http') return `${s.scheme}://${s.upstreamIp}:${s.upstreamPort}`
  if (s.mode === 'proxied') return `${s.kind.toUpperCase()} via this device's port ${s.listenPort} → ${s.upstreamIp}:${s.upstreamPort}`
  return `${s.kind.toUpperCase()}, the name points at ${s.upstreamIp}:${s.upstreamPort}`
}

/** Whose list a service is on (People page): those people reach it through the VPN, and pass SGC's login for it. */
function onListsOf(s: Service, people: Person[]): string[] {
  return people.filter((p) => p.active && !p.disabled && (p.allServices || p.serviceIds.includes(s.id))).map((p) => p.name)
}

function ServiceRow({
  service: s,
  people,
  onEdit,
  onRemove,
  onRefreshIcon,
}: {
  service: Service
  people: Person[]
  onEdit: () => void
  onRemove: () => void
  onRefreshIcon: () => void
}) {
  const lists = onListsOf(s, people)
  const state = !s.enabled
    ? { text: 'Switched off', tone: 'text-muted-foreground' }
    : s.health.state === 'up'
      ? { text: 'Answers', tone: 'text-emerald-700 dark:text-emerald-400' }
      : s.health.state === 'down'
        ? {
            text: s.health.abandoned ? 'Looks abandoned' : `Does not answer · ${formatTimeAgo(s.health.since)}`,
            tone: s.health.abandoned ? 'text-muted-foreground' : 'text-red-700 dark:text-red-400',
          }
        : { text: 'Not probed', tone: 'text-muted-foreground' }
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 px-4 py-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,1fr)_10rem_auto]">
      <div className="flex min-w-0 items-center gap-3">
        <ServiceIcon service={s} />
        <span className="flex min-w-0 flex-col">
          <span className="truncate text-sm font-medium">{s.title || s.name}</span>
          {s.url && s.kind === 'http' ? (
            <a
              href={s.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex min-w-0 items-center gap-1 text-xs text-muted-foreground hover:underline"
            >
              <span className="truncate">{s.url.replace('https://', '')}</span>
              <ExternalLink className="size-3 shrink-0" aria-hidden="true" />
            </a>
          ) : (
            <span className="truncate text-xs text-muted-foreground">{s.url}</span>
          )}
        </span>
      </div>
      <div className="col-start-2 row-start-1 md:col-start-5">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={<Button variant="ghost" size="icon-sm" className="text-muted-foreground" aria-label={`More for ${s.title || s.name}`} />}
          >
            <Ellipsis />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={onEdit}>
              <Pencil />
              Change
            </DropdownMenuItem>
            {s.kind === 'http' && !s.hasIcon && (
              <DropdownMenuItem onClick={onRefreshIcon}>
                <RefreshCw />
                Look for its icon again
              </DropdownMenuItem>
            )}
            <DropdownMenuItem variant="destructive" onClick={onRemove}>
              <Trash2 />
              Remove
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div className="col-span-2 min-w-0 text-xs text-muted-foreground md:col-span-1 md:col-start-2 md:row-start-1 md:text-sm">
        <span className="block truncate md:text-foreground">{describeWay(s)}</span>
        <span className="block truncate text-xs">{s.tokenId !== null ? `announced by ${s.tokenLabel}` : 'added here'}</span>
      </div>
      <div className="col-span-2 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 md:col-span-1 md:col-start-3 md:row-start-1">
        <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{s.protected ? 'Behind SGC’s login' : 'Open in the home network'}</span>
        {lists.length > 0 && (
          <span className="truncate text-xs text-muted-foreground" title={lists.join(', ')}>
            on the list of {lists.length <= 2 ? lists.join(' and ') : `${lists.length} people`}
          </span>
        )}
      </div>
      <div className={`col-span-2 flex items-center gap-2 text-sm md:col-span-1 md:col-start-4 md:row-start-1 ${state.tone}`}>
        <HealthDot service={s} />
        <span className="truncate">{state.text}</span>
      </div>
    </div>
  )
}

function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

function ServiceForm({
  initial,
  announced = false,
  onCancel,
  onSave,
}: {
  initial: ServiceInput
  announced?: boolean
  onCancel: () => void
  onSave: (input: ServiceInput) => Promise<void>
}) {
  const [input, setInput] = useState<ServiceInput>({ ...blank, ...initial })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = (patch: Partial<ServiceInput>) => setInput((current) => ({ ...current, ...patch }))

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onSave({ ...input, name: input.name.trim().toLowerCase(), upstreamIp: input.upstreamIp.trim() })
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const web = input.kind === 'http'
  return (
    <form onSubmit={submit} className="flex flex-col gap-3 rounded-lg bg-muted/50 p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field id="svc-name" label="Name" hint="It opens at name.your-domain: lower-case letters, digits, hyphens.">
          <Input id="svc-name" value={input.name} maxLength={63} autoCapitalize="none" spellCheck={false}
            onChange={(e) => set({ name: e.target.value.toLowerCase() })} />
        </Field>
        <Field id="svc-title" label="Title on the dashboard (optional)">
          <Input id="svc-title" value={input.title} maxLength={80} onChange={(e) => set({ title: e.target.value })} />
        </Field>
        <Field id="svc-kind" label="Kind">
          <select id="svc-kind" className={selectClass} value={input.kind}
            onChange={(e) => set({ kind: e.target.value as ServiceInput['kind'], protected: false })}>
            <option value="http">Web page (http or https)</option>
            <option value="tcp">Other, TCP (a game server, …)</option>
            <option value="udp">Other, UDP</option>
          </select>
        </Field>
        <Field id="svc-category" label="Category (optional)" hint="Groups services on the dashboard.">
          <Input id="svc-category" value={input.category} maxLength={40} onChange={(e) => set({ category: e.target.value })} />
        </Field>
        <Field id="svc-ip" label="Address in the home network" hint={announced ? 'Announced by its server; its next announcement sets the port again.' : undefined}>
          <Input id="svc-ip" value={input.upstreamIp} placeholder="192.168.1.20" inputMode="decimal"
            onChange={(e) => set({ upstreamIp: e.target.value })} />
        </Field>
        <Field id="svc-port" label="Port">
          <Input id="svc-port" type="number" min={1} max={65535} value={input.upstreamPort || ''}
            onChange={(e) => set({ upstreamPort: Number(e.target.value) })} />
        </Field>
        {web ? (
          <Field id="svc-scheme" label="The device speaks">
            <select id="svc-scheme" className={selectClass} value={input.scheme}
              onChange={(e) => set({ scheme: e.target.value as ServiceInput['scheme'] })}>
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
          </Field>
        ) : (
          <Field id="svc-mode" label="Way in"
            hint={input.mode === 'direct'
              ? 'The name points at the device; nothing passes through the gateway.'
              : 'Through a port of the gateway. Switching this on restarts the proxy for a few seconds.'}>
            <select id="svc-mode" className={selectClass} value={input.mode}
              onChange={(e) => set({ mode: e.target.value as ServiceInput['mode'] })}>
              <option value="direct">Direct to the device</option>
              <option value="proxied">Through the gateway</option>
            </select>
          </Field>
        )}
        {!web && input.mode === 'proxied' && (
          <Field id="svc-listen" label="Port on the gateway" hint="Empty: the same as the device's.">
            <Input id="svc-listen" type="number" min={1} max={65535} value={input.listenPort || ''}
              onChange={(e) => set({ listenPort: Number(e.target.value) })} />
          </Field>
        )}
      </div>
      {web && input.scheme === 'https' && (
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={input.verifyTls} onCheckedChange={(v) => set({ verifyTls: v })} />
          Check the device's own certificate (only if it has a real one)
        </label>
      )}
      {web && (
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={input.protected} onCheckedChange={(v) => set({ protected: v })} />
          Behind SGC’s login (only you, and people with a login who have this service)
        </label>
      )}
      <label className="flex items-center gap-2 text-sm">
        <Switch checked={input.enabled} onCheckedChange={(v) => set({ enabled: v })} />
        In use
      </label>
      <FormError message={error} />
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy || !input.name || !input.upstreamIp || !input.upstreamPort}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  )
}

/** How services are handled: approval of announced ones, icons, when one looks abandoned. */
export function ServicesSettingsCard({ data, onSaved }: { data: ServicesResponse; onSaved: (next: ServicesResponse) => void }) {
  const [days, setDays] = useState(String(data.settings.abandonedDays))
  const [error, setError] = useState<string | null>(null)
  async function save(patch: Partial<ServicesSettings>) {
    setError(null)
    try {
      onSaved(await api.setServicesSettings({ ...data.settings, ...patch }))
    } catch (e) {
      setError(errorMessage(e))
    }
  }
  return (
    <SettingCard title="How services are handled">
        <label className="flex items-start justify-between gap-4 text-sm">
          <span>
            Announced services wait for your approval
            <span className="block text-xs text-muted-foreground">Off: a server with a token adds its services at once (you are told).</span>
          </span>
          <Switch checked={data.settings.approveNew} onCheckedChange={(v) => save({ approveNew: v })} />
        </label>
        <label className="flex items-start justify-between gap-4 text-sm">
          <span>
            Icons from the icon collection
            <span className="block text-xs text-muted-foreground">
              For a service without an icon of its own: from a copy of the dashboard-icons collection kept on this device
              (about 20 MB), so nobody outside learns your services’ names.
            </span>
          </span>
          <Switch checked={data.settings.iconCatalogue} onCheckedChange={(v) => save({ iconCatalogue: v })} />
        </label>
        {data.settings.iconCatalogue && data.icons && <IconsLine icons={data.icons} onSaved={onSaved} onError={setError} />}
        <div className="flex flex-wrap items-center gap-2 text-sm">
          A service down for
          <Input type="number" min={1} max={365} value={days} className="w-20" onChange={(e) => setDays(e.target.value)}
            onBlur={() => Number(days) !== data.settings.abandonedDays && save({ abandonedDays: Number(days) })} />
          days looks abandoned.
        </div>
        <FormError message={error} />
    </SettingCard>
  )
}

function IconsLine({
  icons,
  onSaved,
  onError,
}: {
  icons: IconsStatus
  onSaved: (next: ServicesResponse) => void
  onError: (message: string | null) => void
}) {
  const [asked, setAsked] = useState(false)
  async function update() {
    onError(null)
    setAsked(true)
    try {
      onSaved(await api.updateIcons())
    } catch (e) {
      onError(errorMessage(e))
    }
  }
  const state = icons.updating
    ? 'Looking for a new icon pack…'
    : icons.installed
      ? `${icons.count.toLocaleString('en-GB')} icons, from ${formatDate(icons.built!)}` +
        (icons.checkedAt ? ` · looked for a newer pack ${formatTimeAgo(icons.checkedAt)}` : '')
      : 'No icons on this device yet: they are fetched once there is a service.'
  return (
    <div className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3 text-xs">
      <p>{state}</p>
      {icons.problem && <p className="text-amber-700 dark:text-amber-400">{icons.problem}</p>}
      {asked && !icons.updating && (
        <p className="text-muted-foreground">SGC is looking; this line follows when the page next refreshes.</p>
      )}
      <Button size="sm" variant="outline" className="self-start" onClick={update} disabled={icons.updating}>
        <RefreshCw />
        Update icons
      </Button>
      <p className="text-muted-foreground">
        Icons:{' '}
        <a href="https://github.com/homarr-labs/dashboard-icons" target="_blank" rel="noreferrer" className="underline-offset-4 hover:underline">
          dashboard-icons
        </a>{' '}
        by homarr-labs, under the Apache License 2.0, drawn anew by SGC at 64 pixels.
      </p>
    </div>
  )
}

function RemoveDialog({ service, onClose, onDone }: { service: Service; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function act() {
    setBusy(true)
    try {
      await api.removeService(service.id)
      onDone()
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }
  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Remove {service.title || service.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            Its name stops working. The device itself is not touched.
            {service.tokenId !== null && ' If its server announces it again, it comes back; remove or keep the token to stop that.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button variant="outline" onClick={act} disabled={busy}>
            {busy ? 'Removing…' : 'Remove'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
