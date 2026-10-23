import { useState, type FormEvent, type ReactNode } from 'react'
import { ExternalLink, Plus, RefreshCw } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { HealthDot, ServiceIcon } from '@/components/service-icon'
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
  type Service,
  type ServiceInput,
  type ServicesResponse,
  type ServicesSettings,
} from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'
import { usePolled } from '@/lib/poll'

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

/** Every service behind SGC's names: add, change, approve, remove. */
export function ServicesManager({ onError }: { onError: (error: unknown) => void }) {
  const [data, setData, refresh] = usePolled(api.services, 15_000, onError)
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Service | null>(null)
  const [removing, setRemoving] = useState<Service | null>(null)

  if (data === null) {
    return (
      <Card>
        <CardContent>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  const pending = data.services.filter((s) => s.pending)
  const categories = [...new Set(data.services.map((s) => s.category))]

  return (
    <div className="flex flex-col gap-3">
      {pending.length > 0 && (
        <Card>
          <CardContent className="flex flex-col gap-2">
            <h2 className="text-sm text-muted-foreground">Waiting for your approval</h2>
            {pending.map((s) => (
              <div key={s.id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span>
                  <span className="font-medium">{s.name}</span> at {s.upstreamIp}:{s.upstreamPort},
                  announced by {s.tokenLabel || 'a removed token'}
                </span>
                <span className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={() => api.approveService(s.id).then(refresh, onError)}
                  >
                    Approve
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setRemoving(s)}>
                    Remove
                  </Button>
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm text-muted-foreground">Services</h2>
            {!adding && (
              <Button size="sm" variant="outline" onClick={() => setAdding(true)}>
                <Plus />
                Add a service
              </Button>
            )}
          </div>
          {adding && (
            <ServiceForm
              initial={blank}
              onCancel={() => setAdding(false)}
              onSave={async (input) => {
                await api.addService(input)
                setAdding(false)
                refresh()
              }}
            />
          )}
          {data.services.length === 0 && !adding && (
            <p className="text-sm text-muted-foreground">
              No services yet. Add one here for a device that cannot announce itself (a router, a
              printer, a NAS), or give a server a token below and let it announce its own.
            </p>
          )}
          {categories.map((category) => (
            <div key={category || '-'} className="flex flex-col gap-1">
              {categories.length > 1 && (
                <h3 className="pt-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  {category || 'Other'}
                </h3>
              )}
              {data.services
                .filter((s) => s.category === category && !s.pending)
                .map((s) =>
                  editing?.id === s.id ? (
                    <ServiceForm
                      key={s.id}
                      initial={s}
                      announced={s.tokenId !== null}
                      onCancel={() => setEditing(null)}
                      onSave={async (input) => {
                        await api.updateService(s.id, input)
                        setEditing(null)
                        refresh()
                      }}
                    />
                  ) : (
                    <ServiceRow
                      key={s.id}
                      service={s}
                      onEdit={() => setEditing(s)}
                      onRemove={() => setRemoving(s)}
                      onRefreshIcon={() => api.refreshServiceIcon(s.id).then(() => setTimeout(refresh, 4000), onError)}
                    />
                  ),
                )}
            </div>
          ))}
        </CardContent>
      </Card>

      <SettingsCard data={data} onSaved={setData} />

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
  if (s.mode === 'proxied') return `${s.kind.toUpperCase()} via the gateway's port ${s.listenPort} → ${s.upstreamIp}:${s.upstreamPort}`
  return `${s.kind.toUpperCase()}, the name points at ${s.upstreamIp}:${s.upstreamPort}`
}

function ServiceRow({
  service: s,
  onEdit,
  onRemove,
  onRefreshIcon,
}: {
  service: Service
  onEdit: () => void
  onRemove: () => void
  onRefreshIcon: () => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg py-1.5">
      <ServiceIcon service={s} />
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="flex items-center gap-2 text-sm font-medium">
          <HealthDot service={s} />
          {s.title || s.name}
          {!s.enabled && <span className="text-xs font-normal text-muted-foreground">switched off</span>}
          {s.protected && <span className="text-xs font-normal text-muted-foreground">· behind SGC’s login</span>}
        </span>
        <span className="truncate text-xs text-muted-foreground">
          {s.url && s.kind === 'http' ? (
            <a href={s.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">
              {s.url.replace('https://', '')}
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          ) : (
            s.url
          )}
          {' · '}
          {describeWay(s)}
          {' · '}
          {s.tokenId !== null ? `announced by ${s.tokenLabel}` : 'added here'}
          {s.health.state === 'down' && ` · down since ${formatTimeAgo(s.health.since)}`}
          {s.health.abandoned && ' · looks abandoned'}
        </span>
      </div>
      <div className="flex gap-1">
        {s.kind === 'http' && !s.hasIcon && (
          <Button size="icon-sm" variant="ghost" onClick={onRefreshIcon} aria-label={`Look for ${s.name}'s icon again`}>
            <RefreshCw />
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={onEdit}>
          Change
        </Button>
        <Button size="sm" variant="ghost" onClick={onRemove}>
          Remove
        </Button>
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

function SettingsCard({ data, onSaved }: { data: ServicesResponse; onSaved: (next: ServicesResponse) => void }) {
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
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">How services are handled</h2>
        <label className="flex items-start justify-between gap-4 text-sm">
          <span>
            Announced services wait for your approval
            <span className="block text-xs text-muted-foreground">Off: a server with a token adds its services at once (you are told).</span>
          </span>
          <Switch checked={data.settings.approveNew} onCheckedChange={(v) => save({ approveNew: v })} />
        </label>
        <label className="flex items-start justify-between gap-4 text-sm">
          <span>
            Look up icons in the public catalogue
            <span className="block text-xs text-muted-foreground">
              When a service has no icon of its own, SGC asks the dashboard-icons catalogue (on the jsDelivr CDN) by name. That tells the CDN the names of your services.
            </span>
          </span>
          <Switch checked={data.settings.iconCatalogue} onCheckedChange={(v) => save({ iconCatalogue: v })} />
        </label>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          A service down for
          <Input type="number" min={1} max={365} value={days} className="w-20" onChange={(e) => setDays(e.target.value)}
            onBlur={() => Number(days) !== data.settings.abandonedDays && save({ abandonedDays: Number(days) })} />
          days looks abandoned.
        </div>
        <FormError message={error} />
      </CardContent>
    </Card>
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
