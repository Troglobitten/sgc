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
import { api, errorMessage, type DnsProviderKind, type DomainStatus } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

const refreshInterval = 30_000
const selectClass = 'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

/**
 * The owner's domain and the account at the company that holds its DNS
 * (Zone.eu, Cloudflare, Porkbun, Namecheap: the list comes from SGC).
 *
 * SGC keeps them only after the provider has said that they belong
 * together, asks it again every few hours, and says here when the answer
 * turns to no. Secrets go to SGC and are never shown again.
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

  const title = status?.configured ? `Domain (${status.providerName})` : 'Domain'
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
  const provider = status.providerName
  const username = status.shown?.username

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
              The domain your names will end in, and the account at the company that holds its
              DNS. SGC uses the account to get the certificate for those names and to keep the
              VPN&apos;s name pointing at your home. It asks the company before saving, and saves
              nothing it does not accept.
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
              <span className="font-medium">{status.domain}</span>, at {provider}
              {username ? <>, with the account {username}</> : null}. What opens the account is
              saved and is not shown again.
            </p>
            {status.checkedAt !== null && status.ok && (
              <p className="text-sm text-muted-foreground">
                {provider} accepted it when last asked, {formatTimeAgo(status.checkedAt)}.
              </p>
            )}
            {failing && (
              <Notice>
                {status.problem}
                {status.failingSince !== null && ` Since ${formatTimeAgo(status.failingSince)}.`}{' '}
                While this lasts, certificates cannot be renewed. If the key was replaced or
                withdrawn at {provider}, enter the new one with “Change”.
              </Notice>
            )}
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={askNow} disabled={asking}>
                {asking ? `Asking ${provider}…` : `Ask ${provider} now`}
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
            provider={provider}
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

/**
 * The domain, the provider, and what that provider asks for. Secrets are
 * always typed anew: SGC never hands them back.
 */
function DomainForm({
  status,
  onCancel,
  onSaved,
}: {
  status: DomainStatus
  onCancel?: () => void
  onSaved: (next: DomainStatus) => void
}) {
  const kinds = status.kinds
  const [domain, setDomain] = useState(status.domain)
  const [providerId, setProviderId] = useState(status.configured ? status.provider : (kinds[0]?.id ?? ''))
  // The values the owner typed, per provider: switching back and forth keeps them.
  const [typed, setTyped] = useState<Record<string, Record<string, string>>>(
    status.configured ? { [status.provider]: { ...status.shown } } : {},
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const kind: DnsProviderKind | undefined = kinds.find((k) => k.id === providerId)
  const values = typed[providerId] ?? {}
  const complete = kind !== undefined && kind.fields.every((f) => (values[f.key] ?? '').trim() !== '')

  function setValue(key: string, value: string) {
    setTyped((all) => ({ ...all, [providerId]: { ...all[providerId], [key]: value } }))
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!kind) return
    setBusy(true)
    setError(null)
    try {
      // Exactly the provider's fields, nothing else (lib/bodies.ts's rule).
      const body: Record<string, string> = {}
      for (const f of kind.fields) body[f.key] = values[f.key] ?? ''
      onSaved(await api.saveDomain(domain, kind.id, body))
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
        <Label htmlFor="domain-provider">Where the domain&apos;s DNS is</Label>
        <select
          id="domain-provider"
          className={selectClass}
          value={providerId}
          onChange={(e) => {
            setProviderId(e.target.value)
            setError(null)
          }}
        >
          {kinds.map((k) => (
            <option key={k.id} value={k.id}>
              {k.name}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          The company whose name servers answer for the domain. That is often where you bought
          it, but not always: if you moved the DNS elsewhere (to Cloudflare, say), pick that one.
        </p>
      </div>
      {kind && (
        <>
          <p className="text-sm text-muted-foreground">{kind.before}</p>
          {kind.fields.map((f) => (
            <div key={f.key} className="flex flex-col gap-2">
              <Label htmlFor={`domain-${kind.id}-${f.key}`}>
                {f.label.charAt(0).toUpperCase() + f.label.slice(1)}
              </Label>
              <Input
                id={`domain-${kind.id}-${f.key}`}
                type={f.secret ? 'password' : 'text'}
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                maxLength={f.max}
                value={values[f.key] ?? ''}
                onChange={(e) => setValue(f.key, e.target.value)}
              />
              {f.help && <p className="text-xs text-muted-foreground">{f.help}</p>}
            </div>
          ))}
        </>
      )}
      <FormError message={error} />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !domain || !complete}>
          {busy ? `Asking ${kind?.name ?? ''}…` : 'Check and save'}
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
  provider,
  onClose,
  onDone,
}: {
  domain: string
  provider: string
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
            SGC forgets the domain and the {provider} account with its key. Nothing is changed at{' '}
            {provider}. You can enter them again at any time.
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
