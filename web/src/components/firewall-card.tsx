import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { ShieldCheck, ShieldOff, TriangleAlert } from 'lucide-react'

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
import { api, ApiError, errorMessage, type FirewallStatus } from '@/lib/api'
import { firewallChangedEvent } from '@/lib/events'

const refreshInterval = 10_000
// While a change waits for its confirmation, the state is watched closely.
const pendingRefreshInterval = 2_000

/**
 * The firewall: its state, and the way to switch it on or off.
 *
 * A change takes effect at once and then has to be confirmed from this page.
 * If the new rules keep this browser out, the confirmation never arrives and
 * SGC undoes the change by itself. That is why the confirmation step cannot
 * be skipped, and why it is this page that asks for it.
 */
export function FirewallCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<FirewallStatus | null>(null)
  const [asking, setAsking] = useState(false)
  // What became of the last change, when it was not simply confirmed.
  const [notice, setNotice] = useState<string | null>(null)
  // Raised to ask SGC for the state right away instead of at the next turn.
  const [refreshes, setRefreshes] = useState(0)
  // The change this page saw waiting, and whether it was answered here.
  const waitingFor = useRef<{ enabled: boolean; answered: boolean } | null>(null)
  // The same "answered", for drawing: the question is not asked twice.
  const [answered, setAnswered] = useState(false)

  const take = useCallback((next: FirewallStatus) => {
    const waiting = waitingFor.current
    if (next.pending) {
      if (!waiting) waitingFor.current = { enabled: next.pending.enabled, answered: false }
    } else if (waiting) {
      waitingFor.current = null
      setAnswered(false)
      // It was waiting and is gone without an answer from this page. If the
      // firewall is not what the change wanted, nobody confirmed in time.
      if (!waiting.answered && (next.state === 'on') !== waiting.enabled) {
        setNotice(
          `The change was not confirmed, so the firewall is ${next.state === 'on' ? 'on' : 'off'} again.`,
        )
      }
    }
    setStatus(next)
  }, [])

  // A change started elsewhere on the page (letting DNS in, from the DNS
  // card) is asked about here like any other: look at once.
  useEffect(() => {
    const look = () => setRefreshes((n) => n + 1)
    window.addEventListener(firewallChangedEvent, look)
    return () => window.removeEventListener(firewallChangedEvent, look)
  }, [])

  const pending = status?.state === 'pending'
  useEffect(() => {
    let stopped = false
    const load = () =>
      api.firewall().then(
        (s) => !stopped && take(s),
        // While a change waits, not reaching SGC is part of what can happen,
        // and the dialog says so. Otherwise it is a problem like any other.
        (e) => !stopped && !pending && onError(e),
      )
    load()
    const timer = setInterval(load, pending ? pendingRefreshInterval : refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError, take, pending, refreshes])

  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">Firewall</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  // What is in effect right now, confirmed or not.
  const on = status.pending ? status.pending.enabled : status.state === 'on'
  const letIn = [
    `SGC's page (port ${status.webPort})`,
    ...(status.dns ? ['DNS'] : []),
    ...(status.proxy ? ['the proxy'] : []),
    ...(status.vpnPort ? [`the VPN (from anywhere)`] : []),
    ...(status.sshPorts.length > 0 ? [`SSH (port ${status.sshPorts.join(', ')})`] : []),
  ].join(' and ')
  // Switching on from an address the firewall would refuse is not offered.
  const wouldLockOut = !on && !status.client.inside
  const awaitingAnswer = status.pending !== null && !answered

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">Firewall</h2>
          <span
            className={
              on
                ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400'
                : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'
            }
          >
            {on ? (
              <ShieldCheck className="size-4" aria-hidden="true" />
            ) : (
              <ShieldOff className="size-4" aria-hidden="true" />
            )}
            {on ? 'On' : 'Off'}
          </span>
        </div>

        {on ? (
          <p className="text-sm">
            Only devices in your home network reach {letIn}. Everything else that arrives
            uninvited is ignored.
          </p>
        ) : (
          <p className="text-sm">
            This device answers every request that reaches it. With the firewall on, SGC&apos;s
            page and SSH answer only to devices in your home network.
          </p>
        )}

        {notice && <Notice>{notice}</Notice>}
        {!on && status.wanted && !notice && (
          <Notice>
            The firewall was on in the export this SGC was restored from. It is not switched on
            here until you do it.
          </Notice>
        )}
        {wouldLockOut && (
          <Notice>
            You are connecting from {status.client.address}, which is not a home-network
            address. The firewall would keep you out, so it cannot be switched on from here. Open
            SGC by its home-network address instead.
          </Notice>
        )}

        {on && !status.pending && status.behind.length > 0 && (
          <Notice>
            The rules were made before {status.behind.join(', ')}{' '}
            {status.behind.length === 1 ? 'was' : 'were'} switched on, and do not let{' '}
            {status.behind.length === 1 ? 'it' : 'them'} in yet.
          </Notice>
        )}

        <div className="flex flex-wrap gap-2">
          {on && !status.pending && status.behind.length > 0 && (
            <Button
              onClick={async () => {
                setNotice(null)
                try {
                  take(await api.changeFirewall(true, true))
                } catch (e) {
                  setNotice(errorMessage(e))
                }
              }}
            >
              Bring the rules up to date
            </Button>
          )}
          <Button
            variant="outline"
            disabled={wouldLockOut || status.pending !== null}
            onClick={() => {
              setNotice(null)
              setAsking(true)
            }}
          >
            {on ? 'Switch off' : 'Switch on'}
          </Button>
        </div>

        {asking && (
          <ChangeDialog
            status={status}
            enable={!on}
            onClose={() => setAsking(false)}
            onChanged={(next) => {
              setAsking(false)
              take(next)
            }}
          />
        )}
        {awaitingAnswer && (
          <ConfirmDialog
            status={status}
            onAnswered={(next, message) => {
              if (waitingFor.current) waitingFor.current.answered = true
              setAnswered(true)
              setNotice(message)
              if (next) take(next)
              // No new state came with the answer: ask for it.
              else setRefreshes((n) => n + 1)
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

/** Explains what is about to happen, then makes the change. */
function ChangeDialog({
  status,
  enable,
  onClose,
  onChanged,
}: {
  status: FirewallStatus
  enable: boolean
  onClose: () => void
  onChanged: (next: FirewallStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const installing = enable && !status.softwareInstalled

  async function change() {
    setBusy(true)
    setError(null)
    try {
      onChanged(await api.changeFirewall(enable))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  let action = enable ? 'Switch on' : 'Switch off'
  if (busy) {
    action = installing ? 'Installing and switching on…' : enable ? 'Switching on…' : 'Switching off…'
  }

  return (
    <AlertDialog open onOpenChange={(next) => !next && !busy && onClose()}>
      <AlertDialogContent className="max-h-[calc(100svh-2rem)] overflow-y-auto data-[size=default]:sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle>
            {enable ? 'Switch the firewall on?' : 'Switch the firewall off?'}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {enable
              ? "SGC's page and SSH will then answer only to devices in your home network (addresses starting with 192.168, 10 or 172.16 to 172.31). What this device itself fetches from the internet is not affected."
              : 'This device will then again answer every request that reaches it, from anywhere.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <p className="rounded-lg bg-muted px-3 py-2 text-sm">
          The change takes effect at once. This page then asks you to confirm that you can still
          reach SGC. Without that confirmation within {status.confirmSeconds} seconds, SGC undoes
          the change by itself.
        </p>
        {installing && (
          <p className="text-sm text-muted-foreground">
            First SGC installs the firewall software (nftables) from Debian. That can take a
            minute or two.
          </p>
        )}
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={change} disabled={busy}>
            {action}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/**
 * Shown while a change waits for its confirmation. It cannot be dismissed:
 * the question has to be answered, by the owner or by the clock. Also used
 * by FirewallFollowUp on the cards of the proxy and the VPN.
 */
export function ConfirmDialog({
  status,
  onAnswered,
}: {
  status: FirewallStatus
  onAnswered: (next: FirewallStatus | null, message: string | null) => void
}) {
  const pending = status.pending!
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Between answers from SGC the countdown runs on this page's own clock.
  const [secondsLeft, setSecondsLeft] = useState(pending.secondsLeft)
  useEffect(() => {
    const deadline = Date.now() + pending.secondsLeft * 1000
    const timer = setInterval(
      () => setSecondsLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000))),
      250,
    )
    return () => clearInterval(timer)
  }, [pending.secondsLeft])

  const state = pending.enabled ? 'on' : 'off'

  async function keep() {
    setBusy(true)
    setError(null)
    try {
      onAnswered(await api.confirmFirewall(), null)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        // Too late: SGC has undone it, and its message says so.
        onAnswered(null, errorMessage(e))
      } else if (e instanceof ApiError && e.status === 0) {
        setError(
          'This browser cannot reach SGC right now. If the firewall is the reason, do nothing: SGC undoes the change by itself.',
        )
        setBusy(false)
      } else {
        setError(errorMessage(e))
        setBusy(false)
      }
    }
  }

  async function undo() {
    setBusy(true)
    setError(null)
    try {
      onAnswered(await api.undoFirewall(), null)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open>
      <AlertDialogContent className="data-[size=default]:sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle>Keep the firewall {state}?</AlertDialogTitle>
          <AlertDialogDescription>
            The firewall is {state} now. If you can read this and the button below works, this
            browser still reaches SGC.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <p className="rounded-lg bg-muted px-3 py-2 text-sm" aria-live="polite">
          {secondsLeft > 0
            ? `Without your confirmation SGC undoes the change in ${secondsLeft} ${secondsLeft === 1 ? 'second' : 'seconds'}.`
            : 'The time is up. SGC is undoing the change.'}
        </p>
        <FormError message={error} />
        <AlertDialogFooter>
          <Button variant="outline" onClick={undo} disabled={busy}>
            Undo
          </Button>
          <Button onClick={keep} disabled={busy || secondsLeft === 0}>
            {busy ? 'One moment…' : `Keep it ${state}`}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
