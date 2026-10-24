import { useState } from 'react'
import { CircleCheck, TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { FirewallFollowUp } from '@/components/firewall-follow-up'
import { Card, CardContent } from '@/components/ui/card'
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
  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">Proxy</h2>
          {status && on && (
            <span
              className={
                status.running && !failing
                  ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400'
                  : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'
              }
            >
              {status.running && !failing ? (
                <CircleCheck className="size-4" aria-hidden="true" />
              ) : (
                <TriangleAlert className="size-4" aria-hidden="true" />
              )}
              {status.running ? (failing ? 'Running, last change failed' : 'Running') : 'Not running'}
            </span>
          )}
        </div>
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
          <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            {formatTimeAgo(status.lastApply.at)}: {status.lastApply.message}
          </p>
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
      </CardContent>
    </Card>
  )
}
