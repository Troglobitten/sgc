import { useState, type FormEvent } from 'react'

import { FormError } from '@/components/auth-card'
import { FirewallFollowUp } from '@/components/firewall-follow-up'
import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type VpnSettings, type VpnStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

/**
 * The VPN as a whole: on or off, its port and public name, and what is
 * needed on the router for phones to get in from outside.
 */
export function VpnCard({
  status,
  lanAddress,
  onChanged,
}: {
  status: VpnStatus
  lanAddress: string
  onChanged: (next: VpnStatus) => void
}) {
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function save(next: VpnSettings) {
    setBusy(true)
    setError(null)
    try {
      onChanged(await api.setVpnSettings(next))
      setEditing(false)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const failing = status.lastApply && !status.lastApply.ok
  const healthy = status.enabled && status.up && !failing
  const state = status.publicState
  const badge = !status.enabled ? (
    <StatusBadge tone="muted">Off</StatusBadge>
  ) : healthy ? (
    <StatusBadge tone="ok">On</StatusBadge>
  ) : (
    <StatusBadge tone="warn">{status.up ? 'On, last change failed' : 'Not running'}</StatusBadge>
  )
  return (
    <SettingCard title="VPN (WireGuard)" status={badge}>
        <div className="flex items-start justify-between gap-4">
          <p className="text-sm">
            {status.enabled
              ? `People’s devices connect from anywhere at ${status.endpoint || 'your public address'}.`
              : 'Let people’s phones and laptops into the home network from anywhere, with the ad blocking of home. Each device gets its own key and QR code.'}
          </p>
          <Switch
            checked={status.enabled}
            disabled={busy}
            onCheckedChange={(enabled) => save({ ...status, enabled })}
            aria-label="VPN"
          />
        </div>

        {status.enabled && state && status.publicName && (
          <Facts
            items={[
              ['Public name', `${status.publicName} → ${state.recordIp || '…'}`],
              ...(state.publicIp ? [['Home is at', state.publicIp] as [string, string]] : []),
              ...(state.checkedAt ? [['Looked', formatTimeAgo(state.checkedAt)] as [string, string]] : []),
            ]}
          />
        )}
        {status.enabled && state?.problem && <Warning>{state.problem}</Warning>}
        {status.enabled && state?.foreign && (
          <div>
            <Button size="sm" variant="outline" onClick={() => api.takeOverVpnRecord().then(() => api.vpn().then(onChanged), (e) => setError(errorMessage(e)))}>
              Let SGC change that record
            </Button>
          </div>
        )}
        {status.enabled && status.problem && <Warning>{status.problem}</Warning>}
        {failing && status.lastApply && (
          <Warning>
            {formatTimeAgo(status.lastApply.at)}: {status.lastApply.message}
          </Warning>
        )}

        {editing ? (
          <SettingsForm status={status} busy={busy} onCancel={() => setEditing(false)} onSave={save} />
        ) : (
          <div>
            <Button variant="outline" onClick={() => setEditing(true)}>
              Change the settings
            </Button>
          </div>
        )}
        {status.enabled && (
          <More label={`On your router: forward UDP port ${status.port}`}>
            <p>
              Forward UDP port {status.port} to {lanAddress || 'this device'}. That is the only port of the home network that
              faces the internet. Whether it works from outside, only a phone on mobile data can tell.
            </p>
          </More>
        )}
        <FormError message={error} />
        {status.enabled && <FirewallFollowUp watch={`${status.up}:${status.port}`} />}
    </SettingCard>
  )
}

function SettingsForm({
  status,
  busy,
  onCancel,
  onSave,
}: {
  status: VpnStatus
  busy: boolean
  onCancel: () => void
  onSave: (next: VpnSettings) => void
}) {
  const [port, setPort] = useState(String(status.port))
  const [network, setNetwork] = useState(status.network)
  const [name, setName] = useState(status.name)
  const [mode, setMode] = useState(status.endpointMode)
  const [staticIp, setStaticIp] = useState(status.staticIp)
  function submit(event: FormEvent) {
    event.preventDefault()
    onSave({ enabled: status.enabled, port: Number(port), network: network.trim(), name: name.trim(), endpointMode: mode, staticIp: staticIp.trim() })
  }
  const hasDevices = status.devices.length > 0
  return (
    <form onSubmit={submit} className="flex flex-col gap-3 rounded-lg bg-muted/50 p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="vpn-name">Public name</Label>
          <Input id="vpn-name" value={name} onChange={(e) => setName(e.target.value.toLowerCase())} />
          <p className="text-xs text-muted-foreground">The one name SGC publishes on the internet (vpn.your-domain).</p>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="vpn-port">UDP port</Label>
          <Input id="vpn-port" type="number" min={1024} max={65535} value={port} onChange={(e) => setPort(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="vpn-network">Range inside the tunnel</Label>
          <Input id="vpn-network" value={network} disabled={hasDevices} onChange={(e) => setNetwork(e.target.value)} />
          <p className="text-xs text-muted-foreground">
            {hasDevices ? 'Fixed while there are devices: their QR codes hold an address in it.' : 'Must not be the range of the home network.'}
          </p>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="vpn-mode">Home’s public address</Label>
          <select
            id="vpn-mode"
            className="h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30"
            value={mode}
            onChange={(e) => setMode(e.target.value as VpnSettings['endpointMode'])}
          >
            <option value="dynamic">Changes now and then (SGC follows it)</option>
            <option value="static">Fixed</option>
          </select>
        </div>
        {mode === 'static' && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="vpn-static">Fixed public address</Label>
            <Input id="vpn-static" value={staticIp} placeholder="203.0.113.7" onChange={(e) => setStaticIp(e.target.value)} />
          </div>
        )}
      </div>
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
