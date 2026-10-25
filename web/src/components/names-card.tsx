import { useState, type FormEvent } from 'react'
import { ExternalLink } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage } from '@/lib/api'
import { usePolled } from '@/lib/poll'

/**
 * The gateway's own name under the domain, and the names SGC keeps in
 * AdGuard Home for it and for the services.
 */
export function NamesCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = usePolled(api.names, 30_000, onError)
  const [editing, setEditing] = useState(false)

  const title = 'Names'
  if (status === null) {
    return (
      <SettingCard title={title}>
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
    )
  }

  const problems = [
    status.lanProblem,
    status.dns.problem,
    status.dns.rewritesOff
      ? 'Rewrites are switched off in AdGuard Home’s own settings, so none of SGC’s names work. Switch them on there (Filters, DNS rewrites).'
      : '',
  ].filter(Boolean)
  const missing = status.dns.names.filter((n) => !n.inPlace)
  const badge = !status.domain ? undefined : problems.length === 0 && missing.length === 0 ? (
    <StatusBadge tone="ok">In place</StatusBadge>
  ) : (
    <StatusBadge tone="warn">Needs a look</StatusBadge>
  )

  return (
    <SettingCard title={title} status={badge}>
        {!status.domain ? (
          <p className="text-sm">
            Once your domain is set up, this device is called <span className="font-medium">{status.name}</span> under it,
            and its page opens at that name with a real certificate.
          </p>
        ) : (
          <Facts
            items={[
              [
                'This device',
                <a
                  key="url"
                  href={status.url}
                  className="inline-flex items-center gap-1 font-medium text-primary underline-offset-4 hover:underline"
                >
                  {status.url.replace('https://', '')}
                  <ExternalLink className="size-3.5" aria-hidden="true" />
                </a>,
              ],
              ...(status.lan ? [['In the home', status.lan.address] as [string, string]] : []),
              ...(status.url !== status.directUrl
                ? [
                    [
                      'Without the proxy',
                      `${status.directUrl.replace('https://', '')}${status.lan ? `, ${status.lan.address}:8443` : ''}`,
                    ] as [string, string],
                  ]
                : []),
            ]}
          />
        )}

        {problems.map((p) => (
          <Warning key={p}>{p}</Warning>
        ))}
        {missing.map((n) => (
          <Warning key={n.domain}>
            {n.domain}: {n.conflict || 'not in place yet'}
          </Warning>
        ))}

        {editing ? (
          <RenameForm
            current={status.name}
            domain={status.domain}
            onCancel={() => setEditing(false)}
            onDone={(next) => {
              setStatus(next)
              setEditing(false)
            }}
          />
        ) : (
          <div>
            <Button variant="outline" onClick={() => setEditing(true)}>
              Change the name
            </Button>
          </div>
        )}

        {status.dns.names.length > 0 && (
          <More label={`The ${status.dns.names.length} names SGC keeps in AdGuard Home`}>
            <ul className="flex flex-col gap-1">
              {status.dns.names.map((n) => (
                <li key={n.domain} className="flex flex-wrap items-baseline justify-between gap-x-3">
                  <span className="text-foreground">
                    {n.domain} <span className="text-muted-foreground">→ {n.answer}</span>
                  </span>
                  <span className={n.inPlace ? '' : 'text-amber-700 dark:text-amber-400'}>
                    {n.inPlace ? n.for : n.conflict || 'not in place yet'}
                  </span>
                </li>
              ))}
            </ul>
            <p>
              The names work on devices that use this device for DNS (the router hands it out, or the device is set to it).
              Give this device a fixed address in your router, so the names keep pointing at it.
            </p>
          </More>
        )}
    </SettingCard>
  )
}

function RenameForm({
  current,
  domain,
  onCancel,
  onDone,
}: {
  current: string
  domain: string
  onCancel: () => void
  onDone: (next: Awaited<ReturnType<typeof api.names>>) => void
}) {
  const [name, setName] = useState(current)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onDone(await api.setGatewayName(name.trim()))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-2">
      <Label htmlFor="gateway-name">Name of this device</Label>
      <div className="flex items-center gap-2">
        <Input
          id="gateway-name"
          value={name}
          maxLength={63}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onChange={(e) => setName(e.target.value.toLowerCase())}
          className="max-w-48"
        />
        {domain && <span className="text-sm text-muted-foreground">.{domain}</span>}
      </div>
      <p className="text-xs text-muted-foreground">
        Bookmarks with the old name stop working; the page by address always does.
      </p>
      <FormError message={error} />
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy || !name.trim() || name.trim() === current}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
