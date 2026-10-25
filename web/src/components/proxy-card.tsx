import { useState } from 'react'

import { FormError } from '@/components/auth-card'
import { FirewallFollowUp } from '@/components/firewall-follow-up'
import { SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'
import { usePolled } from '@/lib/poll'

/**
 * The proxy (Traefik): the switch that makes the services' names open them,
 * with the certificate, at https://name.your-domain.
 */
export function ProxyCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = usePolled(api.proxy, 15_000, onError)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function toggle(enabled: boolean) {
    setBusy(true)
    setError(null)
    try {
      setStatus(await api.setProxyEnabled(enabled))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const on = status?.wanted ?? false
  const failing = status?.lastApply && !status.lastApply.ok
  const badge = !status ? undefined : !on ? (
    <StatusBadge tone="muted">Off</StatusBadge>
  ) : status.running && !failing ? (
    <StatusBadge tone="ok">Running</StatusBadge>
  ) : (
    <StatusBadge tone="warn">{status.running ? 'Last change failed' : 'Not running'}</StatusBadge>
  )
  return (
    <SettingCard title="Proxy" status={badge}>
        <div className="flex items-start justify-between gap-4">
          <p className="text-sm">
            {busy && !on
              ? 'Getting Traefik and switching it on. The first time this takes a minute or two.'
              : on
                ? 'Your services open at https://name.your-domain, with the certificate. Plain http is sent on to https.'
                : 'Switch it on to open your services at https://name.your-domain, with the certificate. SGC installs Traefik for it.'}
          </p>
          <Switch
            checked={on}
            disabled={busy || status === null || (!on && status.notReady !== '')}
            onCheckedChange={toggle}
            aria-label="Proxy"
          />
        </div>
        {status && !on && status.notReady && (
          <p className="text-sm text-muted-foreground">{status.notReady}</p>
        )}
        {status && failing && status.lastApply && (
          <Warning>
            {formatTimeAgo(status.lastApply.at)}: {status.lastApply.message}
          </Warning>
        )}
        {status && status.installed && (
          <p className="text-xs text-muted-foreground">
            Traefik {status.version}
            {status.listenPorts.length > 0 && <> · own ports: {status.listenPorts.join(', ')}</>}
            {status.applying && ' · bringing it up to date…'}
          </p>
        )}
        <FormError message={error} />
        {on && <FirewallFollowUp watch={status?.running} />}
    </SettingCard>
  )
}
