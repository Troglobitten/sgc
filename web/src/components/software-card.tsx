import { useEffect, useState } from 'react'

import { FormError } from '@/components/auth-card'
import { More, SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Button } from '@/components/ui/button'
import { api, errorMessage, type EolState, type ProxyStatus } from '@/lib/api'
import { formatDate, formatTimeAgo } from '@/lib/format'

/**
 * The software SGC stands on: until when it gets security fixes, and the
 * versions of the programs SGC installs.
 */
export function SoftwareCard({ onError }: { onError: (error: unknown) => void }) {
  const [eol, setEol] = useState<EolState | null>(null)
  const [proxy, setProxy] = useState<ProxyStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.eol().then(setEol, onError)
    api.proxy().then(setProxy, onError)
  }, [onError])

  async function run(what: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await what()
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const looked = eol !== null && eol.items.length > 0
  const attention = eol !== null && (eol.items.some((i) => i.warning) || eol.programs.some((p) => p.behind))
  const badge = !looked ? undefined : attention ? (
    <StatusBadge tone="warn">Needs a look</StatusBadge>
  ) : (
    <StatusBadge tone="ok">All supported</StatusBadge>
  )
  // The installed Traefik differs from the one this SGC brings only after an
  // update of SGC, until the proxy is updated too.
  const traefikBehind = proxy?.installed && proxy.version !== proxy.pinnedVersion

  return (
    <SettingCard title="End of life" status={badge}>
      {eol && eol.items.length === 0 && <p className="text-sm text-muted-foreground">Not looked yet.</p>}
      {looked && (
        <ul className="divide-y text-sm">
          {eol.items.map((item) => (
            <li key={item.product} className="flex flex-wrap justify-between gap-x-4 gap-y-0.5 py-1.5">
              <span className="font-medium">
                {item.label} {item.cycle}
              </span>
              <span className="text-muted-foreground">
                {item.securityEnd ? `security fixes until ${formatDate(item.securityEnd)}` : 'no end date yet'}
              </span>
            </li>
          ))}
          {eol.programs.map((p) => (
            <li key={p.name} className="flex flex-wrap justify-between gap-x-4 gap-y-0.5 py-1.5">
              <span className="font-medium">
                {p.name} {p.pinned}
              </span>
              <span className={p.behind ? 'text-amber-700 dark:text-amber-400' : 'text-muted-foreground'}>
                {p.behind ? `${p.newest} is out` : p.newest ? 'the newest release' : p.problem ? 'could not be asked' : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
      {eol?.items
        .filter((item) => item.warning)
        .map((item) => (
          <Warning key={item.product}>{item.warning}</Warning>
        ))}
      {eol?.programs
        .filter((p) => p.behind)
        .map((p) => (
          <Warning key={p.name}>
            {p.name} {p.newest} is out; this SGC brings {p.pinned}. A newer SGC brings the newer one.
          </Warning>
        ))}
      {traefikBehind && (
        <Warning>
          <p>
            Traefik {proxy.version} is installed; this SGC brings {proxy.pinnedVersion}.
          </p>
          <div>
            <Button variant="outline" disabled={busy} onClick={() => run(async () => setProxy(await api.updateProxy()))}>
              {busy ? 'Updating…' : `Update Traefik to ${proxy.pinnedVersion}`}
            </Button>
          </div>
        </Warning>
      )}
      {eol?.problem && <Warning>{eol.problem}</Warning>}
      <FormError message={error} />
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={busy} onClick={() => run(async () => setEol(await api.checkEol()))}>
          Look again
        </Button>
        {eol?.checkedAt && <span className="text-xs text-muted-foreground">Looked {formatTimeAgo(eol.checkedAt)}</span>}
      </div>
      <More label="What about the kernel, WireGuard and SSH?">
        <p>
          They come from Debian, so Debian’s date covers them: the Linux kernel (WireGuard is part of it), the firewall
          (nftables), SSH and the rest of the system. Debian keeps fixing them until then, also where the programs’ own
          makers have stopped.
        </p>
        <p>
          AdGuard Home publishes no end-of-life dates; only its newest release gets fixes, so SGC compares with that. Dates
          come from endoflife.date, newest releases from GitHub. SGC itself comes with SGC’s own updates (above).
        </p>
      </More>
    </SettingCard>
  )
}
