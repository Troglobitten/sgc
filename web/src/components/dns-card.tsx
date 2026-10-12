import { useEffect, useState, type ReactNode } from 'react'
import { CircleCheck, ExternalLink, TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
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
import { api, errorMessage, type DnsStatus, type FirewallStatus } from '@/lib/api'
import { firewallChangedEvent } from '@/lib/events'

const refreshInterval = 15_000

/**
 * AdGuard Home: the DNS server for the home network, with filtering.
 *
 * SGC installs it, keeps it running and puts its own page behind SGC's
 * login. What it blocks, whom it asks and what it logs is set in that page
 * and is the owner's: SGC writes its settings once, at installation.
 */
export function DnsCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<DnsStatus | null>(null)
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null)
  const [asking, setAsking] = useState<'install' | 'remove' | null>(null)
  const [opening, setOpening] = useState(false)

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.dns().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
      api.firewall().then(
        (f) => !stopped && setFirewall(f),
        () => {},
      )
    }
    load()
    const timer = setInterval(load, refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError])

  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">DNS (AdGuard Home)</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  // With the firewall on and made before AdGuard Home was there, DNS is not
  // let in yet: only the device itself gets answers.
  const shutOut = status.installed && firewall?.state === 'on' && !firewall.dns

  async function letIn() {
    setOpening(true)
    try {
      setFirewall(await api.changeFirewall(true, true))
      // The firewall card asks for the confirmation, as for any change.
      window.dispatchEvent(new Event(firewallChangedEvent))
    } catch (e) {
      onError(e)
    } finally {
      setOpening(false)
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">DNS (AdGuard Home)</h2>
          {status.installed && (
            <span
              className={
                status.running
                  ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400'
                  : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'
              }
            >
              {status.running ? (
                <CircleCheck className="size-4" aria-hidden="true" />
              ) : (
                <TriangleAlert className="size-4" aria-hidden="true" />
              )}
              {status.running ? 'Running' : 'Stopped'}
            </span>
          )}
        </div>

        {!status.available && (
          <Notice>The device could not be asked about AdGuard Home just now.</Notice>
        )}

        {!status.installed ? (
          <>
            <p className="text-sm">
              AdGuard Home answers the name lookups of your network and leaves out advertising
              and tracking. SGC installs it and keeps it running; its settings are yours, in its
              own page.
            </p>
            {status.wanted && (
              <Notice>
                AdGuard Home was installed on the device this SGC was restored from.
                {status.restoredSettings
                  ? ' Its settings came along and are used when you install it here.'
                  : ''}
              </Notice>
            )}
            <Button onClick={() => setAsking('install')} disabled={!status.available}>
              Install AdGuard Home
            </Button>
          </>
        ) : (
          <>
            <p className="text-sm">
              AdGuard Home {status.version} answers name lookups on this device&apos;s address.
              To use it, enter that address as the DNS server in your router, or on single
              devices.
            </p>
            {!status.running && (
              <Notice>
                It is installed but not running. On the device: sudo sgc doctor says why.
              </Notice>
            )}
            {shutOut && (
              <Notice>
                The firewall was switched on before AdGuard Home was there and does not let DNS
                in yet. Until it does, only this device itself gets answers.
              </Notice>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                render={<a href="/adguard/" target="_blank" rel="noreferrer" />}
              >
                <ExternalLink />
                Open AdGuard Home
              </Button>
              {shutOut && (
                <Button onClick={letIn} disabled={opening || firewall?.pending != null}>
                  {opening ? 'Asking the firewall…' : 'Let DNS in'}
                </Button>
              )}
              {status.updateAvailable && (
                <Button onClick={() => setAsking('install')}>Update to {status.pinned}</Button>
              )}
            </div>
            <div className="border-t pt-3">
              <Button variant="ghost" size="sm" className="-ml-2" onClick={() => setAsking('remove')}>
                Remove AdGuard Home
              </Button>
            </div>
          </>
        )}

        {asking && (
          <ActionDialog
            status={status}
            action={asking}
            onClose={() => setAsking(null)}
            onDone={(next) => {
              setAsking(null)
              setStatus(next)
            }}
          />
        )}
      </CardContent>
    </Card>
  )
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-400">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}

/** Says what installing or removing means, then does it. */
function ActionDialog({
  status,
  action,
  onClose,
  onDone,
}: {
  status: DnsStatus
  action: 'install' | 'remove'
  onClose: () => void
  onDone: (next: DnsStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const updating = action === 'install' && status.installed

  async function act() {
    setBusy(true)
    setError(null)
    try {
      onDone(await (action === 'install' ? api.installDns() : api.removeDns()))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  const title =
    action === 'remove'
      ? 'Remove AdGuard Home?'
      : updating
        ? `Update AdGuard Home to ${status.pinned}?`
        : 'Install AdGuard Home?'
  const text =
    action === 'remove'
      ? 'It stops answering name lookups at once. Devices that use this device as their DNS server get no answers until you change that. Its settings stay on this device, in case you install it again.'
      : updating
        ? 'SGC downloads the newer release, checks it and puts it in place of the installed one. Name lookups stop for a few seconds. If the new one does not stay up, the old one comes back. Your settings are not touched.'
        : `SGC downloads AdGuard Home ${status.pinned} from its makers' page on GitHub, checks that it is exactly the expected file, and starts it. It asks Quad9 for answers, over an encrypted connection, and keeps its log of lookups for 7 days. You can change all of that in its own page afterwards.`

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{text}</AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={act} disabled={busy} variant={action === 'remove' ? 'outline' : 'default'}>
            {busy
              ? action === 'remove'
                ? 'Removing…'
                : 'Installing… (about a minute)'
              : action === 'remove'
                ? 'Remove'
                : updating
                  ? 'Update'
                  : 'Install'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
