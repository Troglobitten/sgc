import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { CircleCheck, KeyRound, LockKeyhole, LockKeyholeOpen, Trash2, TriangleAlert } from 'lucide-react'

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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage, type SshKey, type SshStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

// Each look makes the device ask its SSH server and read that server's log,
// so the page does not look more often than it needs to.
const refreshInterval = 5_000
// While a change waits for a login with a key, it looks more often.
const watchingInterval = 2_000

// The same look as the Input component, for the two fields it does not cover.
const fieldClass =
  'w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-base outline-none transition-colors placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 md:text-sm dark:bg-input/30'

type Dialog =
  | { kind: 'add' }
  | { kind: 'install' }
  | { kind: 'remove'; key: SshKey }
  | { kind: 'keys-only'; enable: boolean }

/**
 * SSH: the keys that may log in to the device, and the switch that refuses
 * everything except a key.
 *
 * Switching to "keys only" is the one step here that could lock the owner
 * out, so it works on proof. It is only offered once SGC has seen a login
 * with a key; it takes effect at once; and it stays only if SGC then sees
 * another login with a key. Nothing on this page can skip or fake that: the
 * device itself watches its SSH server's log.
 */
export function SshCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<SshStatus | null>(null)
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const [notice, setNotice] = useState<{ good: boolean; text: string } | null>(null)
  // What the page saw waiting, to say afterwards how it ended.
  const waiting = useRef<{ what: string; keysOnly: boolean; keys: number; undone: boolean } | null>(null)

  const take = useCallback((next: SshStatus) => {
    const was = waiting.current
    if (next.pending) {
      if (!was) {
        waiting.current = {
          what: next.pending.what,
          keysOnly: next.keysOnly,
          keys: next.keys.length,
          undone: false,
        }
      }
    } else if (was) {
      waiting.current = null
      // It ended while this page was not the one ending it. Whether it was
      // kept shows in what it was about: the switch, or the number of keys.
      const kept = next.keysOnly !== was.keysOnly || next.keys.length !== was.keys
      if (kept) {
        setNotice({ good: true, text: 'SGC saw a login with a key. The change is kept.' })
      } else if (!was.undone) {
        setNotice({
          good: false,
          text: 'No login with a key was seen in time, so the change was undone.',
        })
      }
    }
    setStatus(next)
  }, [])

  const watching = status !== null && status.pending !== null
  useEffect(() => {
    let stopped = false
    const load = () =>
      api.ssh().then(
        (s) => !stopped && take(s),
        (e) => !stopped && onError(e),
      )
    load()
    const timer = setInterval(load, watching ? watchingInterval : refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError, take, watching])

  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">SSH</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  const account = status.account || (status.accounts.length === 1 ? status.accounts[0] : '')
  const command = `ssh ${account || 'your-account'}@${window.location.hostname}`
  const done = (next: SshStatus) => {
    setDialog(null)
    take(next)
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">SSH</h2>
          <StateBadge status={status} />
        </div>

        {!status.available && (
          <Notice>
            SGC could not ask this device about its SSH server, so what follows may be out of
            date.
          </Notice>
        )}
        {notice && <Notice good={notice.good}>{notice.text}</Notice>}

        <div className="flex flex-col gap-1.5">
          <p className="text-sm">
            {status.keys.length === 0
              ? 'No keys have been added here. Keys the account keeps in its own home folder work as before.'
              : `Keys that may log in as ${status.account}:`}
          </p>
          {status.keys.length > 0 && (
            <ul className="divide-y rounded-lg border">
              {status.keys.map((key) => (
                <li key={key.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                  <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium">{key.label}</p>
                    <p className="truncate text-xs text-muted-foreground" title={key.fingerprint}>
                      {key.kind} · {shortFingerprint(key.fingerprint)}
                      {key.lastLogin && ` · used ${formatTimeAgo(key.lastLogin)}`}
                      {!key.installed && ' · not on this device yet'}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove ${key.label}`}
                    disabled={status.pending !== null}
                    onClick={() => {
                      setNotice(null)
                      setDialog({ kind: 'remove', key })
                    }}
                  >
                    <Trash2 />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          {status.needsInstall && (
            <Notice>
              These keys are known from the export this SGC was restored from. They are not on
              this device until you install them.
            </Notice>
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={status.pending !== null}
              onClick={() => {
                setNotice(null)
                setDialog({ kind: 'add' })
              }}
            >
              Add a key
            </Button>
            {status.needsInstall && (
              <Button
                variant="outline"
                disabled={status.pending !== null}
                onClick={() => {
                  setNotice(null)
                  setDialog({ kind: 'install' })
                }}
              >
                Install on this device
              </Button>
            )}
          </div>
        </div>

        <div className="flex flex-col gap-2 border-t pt-3">
          {status.keysOnly ? (
            <p className="text-sm">
              Only keys get in. Passwords are refused, and nobody logs in as root.
            </p>
          ) : (
            <>
              <p className="text-sm">
                With &ldquo;keys only&rdquo;, passwords are refused and nobody logs in as root.{' '}
                {describeNow(status)}
              </p>
              {status.wanted && (
                <Notice>
                  &ldquo;Keys only&rdquo; was on in the export this SGC was restored from. It is
                  not switched on here until you do it.
                </Notice>
              )}
              {status.available && !status.loginsVisible ? (
                <Notice>
                  This device&apos;s SSH server is set up not to log logins. SGC cannot see that
                  a key works, so it does not offer the switch.
                </Notice>
              ) : status.recentLogin ? (
                <Notice good>
                  <span title={status.recentLogin.fingerprint}>
                    Seen: {status.recentLogin.account} logged in with{' '}
                    {status.recentLogin.key || 'a key of its own'},{' '}
                    {formatTimeAgo(status.recentLogin.at)}.
                  </span>
                </Notice>
              ) : (
                <p className="text-sm text-muted-foreground">
                  To switch, first log in over SSH with a key, so that SGC has seen one work:{' '}
                  <code className="rounded bg-muted px-1 py-0.5 text-foreground">{command}</code>.
                  This page notices by itself.
                </p>
              )}
            </>
          )}
          <Button
            variant="outline"
            disabled={
              status.pending !== null ||
              (!status.keysOnly && (!status.recentLogin || !status.loginsVisible))
            }
            onClick={() => {
              setNotice(null)
              setDialog({ kind: 'keys-only', enable: !status.keysOnly })
            }}
          >
            {status.keysOnly ? 'Allow passwords again' : 'Switch to keys only'}
          </Button>
        </div>

        {dialog?.kind === 'add' && (
          <AddKeyDialog status={status} onClose={() => setDialog(null)} onDone={done} />
        )}
        {dialog?.kind === 'install' && (
          <InstallDialog status={status} onClose={() => setDialog(null)} onDone={done} />
        )}
        {dialog?.kind === 'remove' && (
          <ActionDialog
            title={`Remove ${dialog.key.label}?`}
            description={
              status.keysOnly
                ? 'The key stops working at once. Because only keys get in, SGC then waits for a login with another key. Without one within two minutes, this key comes back.'
                : 'The key stops working at once.'
            }
            action="Remove"
            busyAction="Removing…"
            run={() => api.removeSshKey(dialog.key.id)}
            onClose={() => setDialog(null)}
            onDone={done}
          />
        )}
        {dialog?.kind === 'keys-only' && (
          <ActionDialog
            title={dialog.enable ? 'Switch to keys only?' : 'Allow passwords again?'}
            description={
              dialog.enable
                ? `Passwords are refused from that moment, and nobody logs in as root. Have a terminal ready: SGC then waits for a login with a key (${command}). Without one within ${Math.round(status.proofSeconds / 60)} minutes, passwords are allowed again.`
                : "Passwords get in again, as far as this device's own settings allow them. The keys keep working."
            }
            action={dialog.enable ? 'Switch to keys only' : 'Allow passwords'}
            busyAction="One moment…"
            run={() => api.setSshKeysOnly(dialog.enable)}
            onClose={() => setDialog(null)}
            onDone={done}
          />
        )}
        {status.pending && (
          <WaitingDialog
            status={status}
            command={command}
            onUndone={(next) => {
              if (waiting.current) waiting.current.undone = true
              take(next)
            }}
          />
        )}
      </CardContent>
    </Card>
  )
}

function StateBadge({ status }: { status: SshStatus }) {
  if (status.keysOnly) {
    return (
      <span className="flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400">
        <LockKeyhole className="size-4" aria-hidden="true" />
        Keys only
      </span>
    )
  }
  if (status.available && !status.passwordLogins) {
    return <span className="text-sm text-muted-foreground">No passwords</span>
  }
  return (
    <span className="flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400">
      <LockKeyholeOpen className="size-4" aria-hidden="true" />
      Passwords allowed
    </span>
  )
}

// What the SSH server allows right now, in a sentence.
function describeNow(status: SshStatus): string {
  if (!status.available) return ''
  const root =
    status.rootLogin === 'no'
      ? 'root cannot log in'
      : status.rootLogin === 'key'
        ? 'root can log in with a key'
        : 'root can log in'
  return `Right now passwords are ${status.passwordLogins ? 'accepted' : 'not accepted'}, and ${root}.`
}

/** "SHA256:AbCdEf…wXyZ": enough to compare with what ssh-keygen -l shows. */
function shortFingerprint(fingerprint: string): string {
  return fingerprint.length > 24 ? `${fingerprint.slice(0, 15)}…${fingerprint.slice(-6)}` : fingerprint
}

function Notice({ good, children }: { good?: boolean; children: ReactNode }) {
  return (
    <p
      className={
        good
          ? 'flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400'
          : 'flex items-start gap-2 text-sm text-amber-700 dark:text-amber-400'
      }
    >
      {good ? (
        <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      ) : (
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      )}
      <span className="min-w-0 [overflow-wrap:anywhere]">{children}</span>
    </p>
  )
}

/** A choice of the device's accounts, shown only where there is a choice. */
function AccountField({
  accounts,
  value,
  onChange,
}: {
  accounts: string[]
  value: string
  onChange: (account: string) => void
}) {
  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor="ssh-account">Account on this device</Label>
      <select
        id="ssh-account"
        className={fieldClass}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">Choose…</option>
        {accounts.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
    </div>
  )
}

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor="ssh-password">Your SGC password</Label>
      <Input
        id="ssh-password"
        type="password"
        autoComplete="current-password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <p className="text-xs text-muted-foreground">
        Asked again because a key is a way to log in to the device itself.
      </p>
    </div>
  )
}

function AddKeyDialog({
  status,
  onClose,
  onDone,
}: {
  status: SshStatus
  onClose: () => void
  onDone: (next: SshStatus) => void
}) {
  // The account is chosen with the first key; later keys go to the same one.
  const chooseAccount = status.keys.length === 0 && status.accounts.length !== 1
  const [key, setKey] = useState('')
  const [label, setLabel] = useState('')
  const [account, setAccount] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (key.includes('PRIVATE KEY')) {
      // Caught here so that it is not even sent.
      setError(
        'This is a private key, which must never leave your computer. Paste the public key instead: the file that ends in .pub.',
      )
      return
    }
    setError(null)
    setBusy(true)
    try {
      onDone(await api.addSshKey(password, label, key, chooseAccount ? account : ''))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(next) => !next && !busy && onClose()}>
      <AlertDialogContent className="max-h-[calc(100svh-2rem)] overflow-y-auto data-[size=default]:sm:max-w-lg">
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <AlertDialogHeader>
            <AlertDialogTitle>Add a key</AlertDialogTitle>
            <AlertDialogDescription>
              Paste your public key: one long line that starts with ssh-ed25519 or similar. On
              your computer it is in the file{' '}
              <code className="rounded bg-muted px-1 py-0.5">.ssh/id_ed25519.pub</code> in your
              home folder. If there is none yet,{' '}
              <code className="rounded bg-muted px-1 py-0.5">ssh-keygen -t ed25519</code> makes
              one.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-2">
            <Label htmlFor="ssh-key">Public key</Label>
            <textarea
              id="ssh-key"
              rows={4}
              autoFocus
              spellCheck={false}
              autoComplete="off"
              className={`${fieldClass} font-mono text-xs break-all md:text-xs`}
              value={key}
              onChange={(e) => {
                setError(null)
                setKey(e.target.value)
              }}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="ssh-label">Name for this key (optional)</Label>
            <Input
              id="ssh-label"
              placeholder="for example: laptop"
              maxLength={64}
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>
          {chooseAccount && (
            <AccountField accounts={status.accounts} value={account} onChange={setAccount} />
          )}
          <PasswordField
            value={password}
            onChange={(v) => {
              setError(null)
              setPassword(v)
            }}
          />
          <FormError message={error} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <Button
              type="submit"
              disabled={busy || !key.trim() || !password || (chooseAccount && !account)}
            >
              {busy ? 'Adding…' : 'Add key'}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

function InstallDialog({
  status,
  onClose,
  onDone,
}: {
  status: SshStatus
  onClose: () => void
  onDone: (next: SshStatus) => void
}) {
  // The account from the export may not exist on this device.
  const known = status.accounts.includes(status.account)
  const [account, setAccount] = useState(
    known ? status.account : status.accounts.length === 1 ? status.accounts[0] : '',
  )
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      onDone(await api.installSshKeys(password, account))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(next) => !next && !busy && onClose()}>
      <AlertDialogContent className="data-[size=default]:sm:max-w-md">
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <AlertDialogHeader>
            <AlertDialogTitle>Install the keys on this device?</AlertDialogTitle>
            <AlertDialogDescription>
              The {status.keys.length === 1 ? 'key' : `${status.keys.length} keys`} listed can
              then log in to this device as the account below.
              {!known &&
                status.account &&
                ` On the device the export came from, that was ${status.account}, which does not exist here.`}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AccountField accounts={status.accounts} value={account} onChange={setAccount} />
          <PasswordField
            value={password}
            onChange={(v) => {
              setError(null)
              setPassword(v)
            }}
          />
          <FormError message={error} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <Button type="submit" disabled={busy || !password || !account}>
              {busy ? 'Installing…' : 'Install'}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** A question with one action that changes something about SSH. */
function ActionDialog({
  title,
  description,
  action,
  busyAction,
  run,
  onClose,
  onDone,
}: {
  title: string
  description: string
  action: string
  busyAction: string
  run: () => Promise<SshStatus>
  onClose: () => void
  onDone: (next: SshStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function go() {
    setBusy(true)
    setError(null)
    try {
      onDone(await run())
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(next) => !next && !busy && onClose()}>
      <AlertDialogContent className="max-h-[calc(100svh-2rem)] overflow-y-auto data-[size=default]:sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={go} disabled={busy}>
            {busy ? busyAction : action}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/**
 * Shown while a change waits for a login with a key. There is nothing to
 * confirm here: the device sees the login by itself. The only button undoes
 * the change without waiting.
 */
function WaitingDialog({
  status,
  command,
  onUndone,
}: {
  status: SshStatus
  command: string
  onUndone: (next: SshStatus) => void
}) {
  const pending = status.pending!
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [secondsLeft, setSecondsLeft] = useState(pending.secondsLeft)
  useEffect(() => {
    const deadline = Date.now() + pending.secondsLeft * 1000
    const timer = setInterval(
      () => setSecondsLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000))),
      250,
    )
    return () => clearInterval(timer)
  }, [pending.secondsLeft])

  async function undo() {
    setBusy(true)
    setError(null)
    try {
      onUndone(await api.undoSsh())
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const clock = `${Math.floor(secondsLeft / 60)}:${String(secondsLeft % 60).padStart(2, '0')}`
  return (
    <AlertDialog open>
      <AlertDialogContent className="data-[size=default]:sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle>Log in with a key now</AlertDialogTitle>
          <AlertDialogDescription>
            The change is in effect ({pending.what}). In a new terminal, log in over SSH with a
            key. SGC sees it by itself and keeps the change.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <code className="rounded-lg bg-muted px-3 py-2 text-sm break-all">{command}</code>
        <p className="rounded-lg bg-muted px-3 py-2 text-sm" aria-live="polite">
          {secondsLeft > 0
            ? `Without a login with a key, SGC undoes the change in ${clock}.`
            : 'The time is up. SGC is undoing the change.'}
        </p>
        <FormError message={error} />
        <AlertDialogFooter>
          <Button variant="outline" onClick={undo} disabled={busy}>
            {busy ? 'Undoing…' : 'Undo now'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
