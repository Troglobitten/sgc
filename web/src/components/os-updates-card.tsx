import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { LoaderCircle, RefreshCw } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { More, SettingCard, StatusBadge, Warning } from '@/components/setting'
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
import { api, errorMessage, type OsUpdatesStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'

const refreshInterval = 30_000
// While SGC has Debian's update tool running, the state is watched closely.
const runningRefreshInterval = 3_000
// How many package names are spelled out before "and N more".
const namesShown = 8

/**
 * Updates for the device itself: Debian's packages (and Raspberry Pi's, on a
 * Pi), as opposed to SGC's own updates (the card above it).
 *
 * The owner chooses between updates that install by themselves and updates
 * started here. Either way it is Debian's own tool that installs them, and
 * the same set. Nothing here restarts the device: when an update needs a
 * restart, the card says so.
 */
export function OsUpdatesCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<OsUpdatesStatus | null>(null)
  // Which choice the owner is being asked to confirm, if any.
  const [choosing, setChoosing] = useState<'automatic' | 'by-hand' | null>(null)
  const [confirmingInstall, setConfirmingInstall] = useState(false)
  const [starting, setStarting] = useState(false)

  const running = status?.running ?? ''
  useEffect(() => {
    let stopped = false
    const load = () =>
      api.osUpdates().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
    load()
    const timer = setInterval(load, running ? runningRefreshInterval : refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError, running])

  const lookNow = useCallback(async () => {
    setStarting(true)
    try {
      setStatus(await api.checkOsUpdates())
    } catch (e) {
      onError(e)
    } finally {
      setStarting(false)
    }
  }, [onError])

  if (status === null) {
    return (
      <SettingCard title="This device (Debian)">
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
    )
  }

  const setUp = status.mode !== ''
  const automatic = status.mode === 'automatic'
  const busy = running !== '' || starting

  const badge = !setUp ? (
    <StatusBadge tone="warn">Not set up</StatusBadge>
  ) : status.problem ? (
    <StatusBadge tone="warn">Needs a look</StatusBadge>
  ) : automatic ? (
    <StatusBadge tone="ok">By themselves</StatusBadge>
  ) : (
    <StatusBadge tone="muted">By hand</StatusBadge>
  )

  return (
    <SettingCard title="This device (Debian)" status={badge}>
        {!setUp ? (
          <NotSetUp status={status} onChoose={setChoosing} />
        ) : (
          <>
            <p className="text-sm">
              {automatic
                ? 'Security fixes install by themselves, once a day.'
                : 'Security fixes install when you start them here.'}
            </p>

            {status.problem && <Notice>{status.problem}</Notice>}
            {!status.available && (
              <Notice>The device could not be asked about its updates just now.</Notice>
            )}

            <Waiting
              status={status}
              busy={busy}
              onInstall={() => setConfirmingInstall(true)}
            />

            {status.restartNeeded && (
              <Notice>
                A restart is needed for an installed update to take effect
                {status.restartPackages.length > 0
                  ? ` (${shortList(status.restartPackages, 3)})`
                  : ''}
                . Nothing restarts by itself outside the maintenance window: restart the device (under This device)
                when it suits you.
              </Notice>
            )}

            <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t pt-3">
              <Button
                variant="ghost"
                size="sm"
                className="-ml-2"
                disabled={busy}
                onClick={() => setChoosing(automatic ? 'by-hand' : 'automatic')}
              >
                {automatic ? 'Start them by hand instead' : 'Let them install by themselves'}
              </Button>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {status.checkedAt ? `Looked ${formatTimeAgo(status.checkedAt)}` : 'Not looked yet'}
                </span>
                <Button variant="outline" size="sm" onClick={lookNow} disabled={busy}>
                  <RefreshCw className={cn(running === 'check' && 'animate-spin')} />
                  Look now
                </Button>
              </div>
            </div>
            <More>
              <p>
                Security fixes and corrections for the device itself come from Debian; on a Raspberry Pi that includes its
                kernel and firmware. Either way it is Debian’s own tool that installs them, and the same set.
              </p>
            </More>
          </>
        )}

        {choosing && (
          <ChoiceDialog
            status={status}
            automatic={choosing === 'automatic'}
            onClose={() => setChoosing(null)}
            onChosen={(next) => {
              setChoosing(null)
              setStatus(next)
            }}
          />
        )}
        {confirmingInstall && (
          <InstallDialog
            status={status}
            onClose={() => setConfirmingInstall(false)}
            onStarted={(next) => {
              setConfirmingInstall(false)
              setStatus(next)
            }}
          />
        )}
    </SettingCard>
  )
}

/** Before the owner has chosen: what the device does now, and the two ways. */
function NotSetUp({
  status,
  onChoose,
}: {
  status: OsUpdatesStatus
  onChoose: (choice: 'automatic' | 'by-hand') => void
}) {
  return (
    <>
      <p className="text-sm">
        Security fixes and corrections for the device itself, from Debian. On a Raspberry Pi that
        includes its kernel and firmware. Choose how they are installed.
      </p>
      {status.available && (
        <p className="text-sm text-muted-foreground">
          {status.daily
            ? 'Right now this device installs them by itself, by its own settings.'
            : 'Right now this device does not install them by itself.'}
        </p>
      )}
      {status.wanted !== '' && (
        <Notice>
          On the device this SGC was restored from, updates{' '}
          {status.wanted === 'automatic' ? 'installed by themselves' : 'were started by hand'}.
          This device is not set up until you choose here.
        </Notice>
      )}
      {!status.available && (
        <Notice>The device could not be asked about its updates just now.</Notice>
      )}
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => onChoose('automatic')}>By themselves</Button>
        <Button variant="outline" onClick={() => onChoose('by-hand')}>
          I start them here
        </Button>
      </div>
    </>
  )
}

/** What is waiting, what is being done about it, and how the last run ended. */
function Waiting({
  status,
  busy,
  onInstall,
}: {
  status: OsUpdatesStatus
  busy: boolean
  onInstall: () => void
}) {
  const count = status.waiting.length
  const automatic = status.mode === 'automatic'
  const last = status.lastInstall

  if (status.running === 'install') {
    return (
      <Working>
        Installing{count > 0 ? ` ${count} ${count === 1 ? 'update' : 'updates'}` : ''}. This can
        take several minutes. You can leave this page; do not restart the device meanwhile.
      </Working>
    )
  }

  return (
    <>
      {status.running === 'check' && <Working>Looking for updates.</Working>}
      {status.dailyRunning && <Working>Debian&apos;s daily run is at work right now.</Working>}

      {count > 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="font-medium">
              {count} {count === 1 ? 'update is' : 'updates are'} waiting
            </p>
            <p className="text-sm text-muted-foreground [overflow-wrap:anywhere]">
              {shortList(status.waiting, namesShown)}
              {automatic ? '. They install by themselves within a day.' : ''}
            </p>
          </div>
          <Button
            variant={automatic ? 'outline' : 'default'}
            onClick={onInstall}
            // Debian's own run would be in the way, and is installing them anyway.
            disabled={busy || status.dailyRunning}
          >
            Install now
          </Button>
        </div>
      ) : (
        status.checkedAt && status.running === '' && <p className="text-sm">Nothing is waiting.</p>
      )}

      {status.checkError && (
        // A look that keeps failing must not look like "nothing is waiting".
        <Notice>Couldn&apos;t look for updates: {status.checkError}</Notice>
      )}
      {last && last.result === 'failed' && (
        <Notice>
          The last installation ({formatTimeAgo(last.finishedAt)}) did not finish:{' '}
          {last.message}
        </Notice>
      )}
      {last && last.result === 'ok' && last.packages.length > 0 && (
        <p className="text-sm text-muted-foreground">
          Installed {formatTimeAgo(last.finishedAt)}: {shortList(last.packages, namesShown)}.
        </p>
      )}
      {automatic && status.lastRun && (
        <p className="text-sm text-muted-foreground">
          Debian&apos;s daily run last ran {formatTimeAgo(status.lastRun)}.
        </p>
      )}
    </>
  )
}

// "a, b, c and 4 more"
function shortList(names: string[], shown: number): string {
  if (names.length <= shown) return names.join(', ')
  return `${names.slice(0, shown).join(', ')} and ${names.length - shown} more`
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <Warning>
      <p className="[overflow-wrap:anywhere]">{children}</p>
    </Warning>
  )
}

function Working({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm" role="status">
      <LoaderCircle className="mt-0.5 size-4 shrink-0 animate-spin" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}

/** Explains one of the two ways, then sets the device up for it. */
function ChoiceDialog({
  status,
  automatic,
  onClose,
  onChosen,
}: {
  status: OsUpdatesStatus
  automatic: boolean
  onClose: () => void
  onChosen: (next: OsUpdatesStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const installing = status.available && !status.toolInstalled

  async function choose() {
    setBusy(true)
    setError(null)
    try {
      onChosen(await api.setOsUpdatesMode(automatic))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {automatic ? 'Let updates install by themselves?' : 'Start updates by hand?'}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {automatic
              ? "Once a day, Debian's own update tool installs what is waiting. The device is never restarted by itself: when an update needs a restart, SGC tells you."
              : 'Nothing installs until you press "Install now" on this page. SGC looks once a day and shows what is waiting. Security fixes then wait for you.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {installing && (
          <p className="text-sm text-muted-foreground">
            This device does not have Debian&apos;s update tool (unattended-upgrades) yet. SGC
            installs it from Debian first, which can take a minute.
          </p>
        )}
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={choose} disabled={busy}>
            {busy
              ? installing
                ? 'Installing the update tool…'
                : 'Setting up…'
              : automatic
                ? 'By themselves'
                : 'By hand'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** Says what installing means, then starts it. */
function InstallDialog({
  status,
  onClose,
  onStarted,
}: {
  status: OsUpdatesStatus
  onClose: () => void
  onStarted: (next: OsUpdatesStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const count = status.waiting.length

  async function install() {
    setBusy(true)
    setError(null)
    try {
      onStarted(await api.installOsUpdates())
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            Install {count} {count === 1 ? 'update' : 'updates'} now?
          </AlertDialogTitle>
          <AlertDialogDescription>
            This can take several minutes. Parts of the device that are updated may stop for a
            moment while it happens. The device is not restarted; if an update needs a restart,
            SGC tells you afterwards.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={install} disabled={busy}>
            {busy ? 'Starting…' : 'Install now'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
