import { useEffect, useId, useState, type ReactNode } from 'react'
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
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type DnsStatus, type FirewallStatus } from '@/lib/api'
import { firewallChangedEvent } from '@/lib/events'

const refreshInterval = 15_000

/** What the owner is asked about before it is done. */
type Question = 'on' | 'off' | 'update'

/**
 * AdGuard Home: the DNS server for the home network, with filtering.
 *
 * It is part of SGC: the installer puts it on the device and starts it. Here
 * it is switched off and on. What it blocks, whom it asks and what it logs is
 * set in its own page, behind SGC's login, and is the owner's: SGC writes its
 * settings once, at installation.
 */
export function DnsCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<DnsStatus | null>(null)
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null)
  const [asking, setAsking] = useState<Question | null>(null)
  const [busy, setBusy] = useState<'switch' | 'firewall' | 'restore' | null>(null)
  const switchId = useId()

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
  const shutOut = status.enabled && firewall?.state === 'on' && !firewall.dns

  async function run(what: 'switch' | 'firewall' | 'restore', work: () => Promise<void>) {
    setBusy(what)
    try {
      await work()
    } catch (e) {
      onError(e)
    } finally {
      setBusy(null)
    }
  }

  // Switching on where AdGuard Home is on the device is done at once.
  // Switching off, and switching on where it has to be downloaded first,
  // say what they mean before they happen.
  function onSwitch(checked: boolean) {
    if (checked && status?.installed) {
      void run('switch', async () => setStatus(await api.setDnsEnabled(true)))
    } else {
      setAsking(checked ? 'on' : 'off')
    }
  }

  const letIn = () =>
    run('firewall', async () => {
      setFirewall(await api.changeFirewall(true, true))
      // The firewall card asks for the confirmation, as for any change.
      window.dispatchEvent(new Event(firewallChangedEvent))
    })

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">DNS (AdGuard Home)</h2>
          {status.enabled && (
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
              {status.running ? 'Running' : 'Not running'}
            </span>
          )}
        </div>

        {!status.available && (
          <Notice>The device could not be asked about AdGuard Home just now.</Notice>
        )}

        <div className="flex items-center gap-2">
          <Switch
            id={switchId}
            checked={status.enabled}
            disabled={!status.available || busy !== null}
            onCheckedChange={onSwitch}
          />
          <Label htmlFor={switchId} className="font-normal">
            {busy === 'switch' ? 'Switching on…' : 'Answer the name lookups of my network'}
          </Label>
        </div>

        {status.enabled ? (
          <p className="text-sm">
            AdGuard Home {status.version} answers name lookups from your home network on this
            device&apos;s address, and leaves out advertising and tracking. To use it, enter that
            address as the DNS server in your router, or on single devices.
          </p>
        ) : status.installed ? (
          <p className="text-sm">
            Switched off: this device answers no name lookups. AdGuard Home and your settings
            stay on it.
          </p>
        ) : (
          <p className="text-sm">
            AdGuard Home answers the name lookups of your network and leaves out advertising and
            tracking. It is not on this device yet: switching on downloads and installs it.
          </p>
        )}

        {status.enabled && !status.running && (
          <Notice>It is switched on but not running. On the device: sudo sgc doctor says why.</Notice>
        )}
        {status.restorePending && (
          <Notice>
            The DNS settings from your export are not in place on this device yet. SGC does that
            by itself after a restore; if this stays, try it here.
          </Notice>
        )}
        {shutOut && (
          <Notice>
            The firewall was switched on before AdGuard Home was there and does not let DNS in
            yet. Until it does, only this device itself gets answers.
          </Notice>
        )}

        {(status.running || status.restorePending || shutOut || status.updateAvailable) && (
          <div className="flex flex-wrap gap-2">
            {status.running && (
              <Button
                variant="outline"
                render={<a href="/adguard/" target="_blank" rel="noreferrer" />}
              >
                <ExternalLink />
                Open AdGuard Home
              </Button>
            )}
            {status.restorePending && (
              <Button
                onClick={() => run('restore', async () => setStatus(await api.finishDnsRestore()))}
                disabled={busy !== null}
              >
                {busy === 'restore' ? 'Putting them in place…' : 'Put them in place'}
              </Button>
            )}
            {shutOut && (
              <Button onClick={letIn} disabled={busy !== null || firewall?.pending != null}>
                {busy === 'firewall' ? 'Asking the firewall…' : 'Let DNS in'}
              </Button>
            )}
            {status.enabled && status.updateAvailable && (
              <Button onClick={() => setAsking('update')} disabled={busy !== null}>
                Update to {status.pinned}
              </Button>
            )}
          </div>
        )}

        {asking && (
          <QuestionDialog
            status={status}
            question={asking}
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

/** Says what a change means, then makes it. */
function QuestionDialog({
  status,
  question,
  onClose,
  onDone,
}: {
  status: DnsStatus
  question: Question
  onClose: () => void
  onDone: (next: DnsStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function act() {
    setBusy(true)
    setError(null)
    try {
      onDone(await (question === 'update' ? api.installDns() : api.setDnsEnabled(question === 'on')))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  const words = {
    off: {
      title: 'Switch DNS off?',
      text: 'AdGuard Home stops answering name lookups at once. Devices that use this device as their DNS server get no answers until you switch it on again, or change that in your router. Nothing is removed: AdGuard Home and your settings stay on this device.',
      button: 'Switch off',
      working: 'Switching off…',
    },
    on: {
      title: 'Switch DNS on?',
      text: `AdGuard Home is not on this device yet. SGC downloads version ${status.pinned} from its makers' page on GitHub, checks that it is exactly the expected file, and starts it. It answers home-network addresses only, asks Quad9 over an encrypted connection, and keeps its log of lookups for 7 days. You can change all of that in its own page afterwards.`,
      button: 'Switch on',
      working: 'Installing… (about a minute)',
    },
    update: {
      title: `Update AdGuard Home to ${status.pinned}?`,
      text: 'SGC downloads the newer release, checks it and puts it in place of the installed one. Name lookups stop for a few seconds. If the new one does not stay up, the old one comes back. Your settings are not touched.',
      button: 'Update',
      working: 'Installing… (about a minute)',
    },
  }[question]

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{words.title}</AlertDialogTitle>
          <AlertDialogDescription>{words.text}</AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={act} disabled={busy} variant={question === 'off' ? 'outline' : 'default'}>
            {busy ? words.working : words.button}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
