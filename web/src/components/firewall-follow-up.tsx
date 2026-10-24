import { useCallback, useEffect, useState } from 'react'
import { ShieldAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { ConfirmDialog } from '@/components/firewall-card'
import { Button } from '@/components/ui/button'
import { api, errorMessage, type FirewallStatus } from '@/lib/api'
import { firewallChangedEvent } from '@/lib/events'

/**
 * For the cards of parts the firewall has to let in (the proxy, the VPN).
 * When the firewall is on and its rules were made before such a part was
 * switched on, it says so here and brings the rules up to date in one click,
 * with the usual confirmation. Before this, the owner had to find "the rules
 * are behind" on the System page (2026-10-24).
 *
 * `watch` changes when the card's part was switched on or off: the
 * firewall's state is looked at again then.
 */
export function FirewallFollowUp({ watch }: { watch: unknown }) {
  const [status, setStatus] = useState<FirewallStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const load = useCallback(() => {
    api.firewall().then(setStatus, () => setStatus(null))
  }, [])

  useEffect(() => {
    load()
  }, [load, watch])

  // While a change waits for its answer, its state is watched closely; the
  // dialog needs the countdown and sees an undo by the clock.
  const pending = status?.pending != null
  useEffect(() => {
    if (!pending) return
    const timer = setInterval(load, 2_000)
    return () => clearInterval(timer)
  }, [pending, load])

  if (status === null) return null

  async function letIn() {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      setStatus(await api.changeFirewall(true, true))
      // A firewall card on the same page looks again too.
      window.dispatchEvent(new Event(firewallChangedEvent))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  if (status.pending) {
    return (
      <ConfirmDialog
        status={status}
        onAnswered={(next, message) => {
          setNotice(message)
          if (next) setStatus(next)
          else load()
        }}
      />
    )
  }

  const behind = status.state === 'on' ? status.behind : []
  if (behind.length === 0) {
    return notice ? <p className="text-sm text-muted-foreground">{notice}</p> : null
  }
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-amber-600/40 bg-amber-500/10 p-3 text-sm">
      <p className="flex items-start gap-2">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden="true" />
        <span>
          The firewall does not let {behind.join(' and ')} in yet: its rules were made before. Bring
          them up to date now; as with every firewall change, you confirm that this page still
          answers afterwards.
        </span>
      </p>
      {notice && <p className="text-muted-foreground">{notice}</p>}
      <FormError message={error} />
      <Button size="sm" className="self-start" onClick={letIn} disabled={busy}>
        {busy ? 'One moment…' : 'Update the firewall'}
      </Button>
    </div>
  )
}
