import { useEffect, useState } from 'react'
import { TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { api, errorMessage, type EolState, type ProxyStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

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

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">Software and its end of life</h2>
        {eol && eol.items.length === 0 && <p className="text-sm text-muted-foreground">Not looked yet.</p>}
        {eol?.items.map((item) => (
          <div key={item.product} className="text-sm">
            <span className="font-medium">
              {item.label} {item.cycle}
            </span>
            {': '}
            {item.securityEnd
              ? `security fixes until ${new Date(item.securityEnd).toLocaleDateString()}`
              : 'no end date yet'}
            {item.end && item.end !== item.securityEnd && `, long-term until ${new Date(item.end).toLocaleDateString()}`}
            {item.warning && (
              <p className="flex gap-2 text-amber-700 dark:text-amber-400">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                {item.warning}
              </p>
            )}
          </div>
        ))}
        {eol?.problem && <p className="text-xs text-amber-700 dark:text-amber-400">{eol.problem}</p>}
        {eol?.checkedAt && <p className="text-xs text-muted-foreground">From endoflife.date, looked {formatTimeAgo(eol.checkedAt)}.</p>}
        {proxy?.installed && (
          <p className="text-sm">
            Traefik {proxy.version}
            {proxy.version !== proxy.pinnedVersion && (
              <>
                {' '}· this SGC brings {proxy.pinnedVersion}{' '}
                <Button size="xs" variant="outline" disabled={busy} onClick={() => run(async () => setProxy(await api.updateProxy()))}>
                  {busy ? 'Updating…' : 'Update'}
                </Button>
              </>
            )}
          </p>
        )}
        <FormError message={error} />
        <div>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => run(async () => setEol(await api.checkEol()))}>
            Look again
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
