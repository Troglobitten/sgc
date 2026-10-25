import { useEffect, useState, type FormEvent } from 'react'

import { FormError } from '@/components/auth-card'
import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
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

  const title = 'Domain'
  if (status === null) {
    return (
      <SettingCard title={title}>
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
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

  const badge = !status.configured ? (
    <StatusBadge tone="muted">Not set up</StatusBadge>
  ) : status.checkedAt === null ? undefined : status.ok ? (
    <StatusBadge tone="ok">Connected</StatusBadge>
  ) : (
    <StatusBadge tone="warn">Problem</StatusBadge>
  )

  return (
    <SettingCard title={title} status={badge}>

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
            <Facts
              items={[
                ['Domain', <span key="domain" className="font-medium">{status.domain}</span>],
                ['DNS at', username ? `${provider}, account ${username}` : provider],
                [
                  'Last asked',
                  status.checkedAt === null
                    ? 'not yet'
                    : `${formatTimeAgo(status.checkedAt)}${status.ok ? `: ${provider} accepted the key` : ''}`,
                ],
              ]}
            />
            {failing && (
              <Warning>
                {status.problem}
                {status.failingSince !== null && ` Since ${formatTimeAgo(status.failingSince)}.`}{' '}
                While this lasts, certificates cannot be renewed. If the key was replaced or
                withdrawn at {provider}, enter the new one with “Change”.
              </Warning>
            )}
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={askNow} disabled={asking}>
                {asking ? `Asking ${provider}…` : `Ask ${provider} now`}
              </Button>
              <Button variant="outline" onClick={() => setEditing(true)}>
                Change
              </Button>
              <Button variant="ghost" className="text-muted-foreground" onClick={() => setRemoving(true)}>
                Remove
              </Button>
            </div>
            <More>
              <p>
                SGC uses the account to get the certificate for your names and to keep the VPN’s name pointing at your
                home. It asks {provider} every few hours whether the key still works, and says so here and on the
                dashboard when it does not. The key is saved on this device, travels in an export, and is never shown
                again.
              </p>
            </More>
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
    </SettingCard>
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
