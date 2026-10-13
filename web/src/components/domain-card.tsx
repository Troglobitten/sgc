import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { CircleCheck, TriangleAlert } from 'lucide-react'

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
import { api, errorMessage, type DomainStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

const refreshInterval = 30_000

/**
 * The owner's domain and the Zone.eu account its DNS is in.
 *
 * SGC keeps them only after Zone.eu has said that they belong together, asks
 * Zone.eu again every few hours, and says here when the answer turns to no.
 * The API key goes to SGC and is never shown again.
 */
export function DomainCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<DomainStatus | null>(null)
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [asking, setAsking] = useState(false)

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.domain().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
    }
    load()
    const timer = setInterval(load, refreshInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError])

  const title = 'Domain (Zone.eu)'
  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">{title}</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  async function askNow() {
    setAsking(true)
    try {
      setStatus(await api.checkDomain())
    } catch (e) {
      onError(e)
    } finally {
      setAsking(false)
    }
  }

  const failing = status.configured && status.checkedAt !== null && !status.ok

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">{title}</h2>
          {status.configured && status.checkedAt !== null && (
            <span
              className={
                status.ok
                  ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400'
                  : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'
              }
            >
              {status.ok ? (
                <CircleCheck className="size-4" aria-hidden="true" />
              ) : (
                <TriangleAlert className="size-4" aria-hidden="true" />
              )}
              {status.ok ? 'Connected' : 'Problem'}
            </span>
          )}
        </div>

        {!status.configured || editing ? (
          <>
            <p className="text-sm">
              The domain your names will end in, and the Zone.eu account that holds its DNS. SGC
              will use the account to get the certificate for those names. It asks Zone.eu
              before saving, and saves nothing Zone.eu does not accept.
            </p>
            <DomainForm
              status={status}
              onCancel={editing ? () => setEditing(false) : undefined}
              onSaved={(next) => {
                setEditing(false)
                setStatus(next)
              }}
            />
          </>
        ) : (
          <>
            <p className="text-sm">
              <span className="font-medium">{status.domain}</span>, with the Zone.eu account{' '}
              {status.username}. The API key is saved and is not shown again.
            </p>
            {status.checkedAt !== null && status.ok && (
              <p className="text-sm text-muted-foreground">
                Zone.eu accepted the key when last asked, {formatTimeAgo(status.checkedAt)}.
              </p>
            )}
            {failing && (
              <Notice>
                {status.problem}
                {status.failingSince !== null && ` Since ${formatTimeAgo(status.failingSince)}.`}{' '}
                While this lasts, certificates cannot be renewed. If the key was replaced or
                withdrawn at Zone.eu, enter the new one with “Change”.
              </Notice>
            )}
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={askNow} disabled={asking}>
                {asking ? 'Asking Zone.eu…' : 'Ask Zone.eu now'}
              </Button>
              <Button variant="outline" onClick={() => setEditing(true)}>
                Change
              </Button>
              <Button variant="ghost" onClick={() => setRemoving(true)}>
                Remove
              </Button>
            </div>
          </>
        )}

        {removing && (
          <RemoveDialog
            domain={status.domain}
            onClose={() => setRemoving(false)}
            onDone={(next) => {
              setRemoving(false)
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

/** Domain, username and key. The key is always typed anew: SGC never hands it back. */
function DomainForm({
  status,
  onCancel,
  onSaved,
}: {
  status: DomainStatus
  onCancel?: () => void
  onSaved: (next: DomainStatus) => void
}) {
  const [domain, setDomain] = useState(status.domain)
  const [username, setUsername] = useState(status.username)
  const [apiKey, setApiKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onSaved(await api.saveDomain(domain, username, apiKey))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex flex-col gap-2">
        <Label htmlFor="domain-name">Domain</Label>
        <Input
          id="domain-name"
          placeholder="domain.tld"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          maxLength={253}
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="domain-username">ZoneID username</Label>
        <Input
          id="domain-username"
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          maxLength={100}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="domain-api-key">Zone.eu API key</Label>
        <Input
          id="domain-api-key"
          type="password"
          autoComplete="off"
          maxLength={200}
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          Made in your ZoneID account management at Zone.eu. It opens your whole Zone.eu
          account, so SGC keeps it to itself: it is saved on this device, travels in an export,
          and is never shown again.
        </p>
      </div>
      <FormError message={error} />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !domain || !username || !apiKey}>
          {busy ? 'Asking Zone.eu…' : 'Check and save'}
        </Button>
        {onCancel && (
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        )}
      </div>
    </form>
  )
}

function RemoveDialog({
  domain,
  onClose,
  onDone,
}: {
  domain: string
  onClose: () => void
  onDone: (next: DomainStatus) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function act() {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.removeDomain())
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Remove {domain}?</AlertDialogTitle>
          <AlertDialogDescription>
            SGC forgets the domain and the Zone.eu account with its API key. Nothing is changed
            at Zone.eu. You can enter them again at any time.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={act} disabled={busy} variant="outline">
            {busy ? 'Removing…' : 'Remove'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
