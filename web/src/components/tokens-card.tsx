import { useState, type FormEvent } from 'react'
import { Copy, KeyRound } from 'lucide-react'

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
import { api, errorMessage, type AnnounceToken } from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'
import { usePolled } from '@/lib/poll'

/**
 * Tokens for servers that announce their services: one per server, shown
 * once, with the block for its compose file.
 */
export function TokensCard({
  gatewayHost,
  onError,
}: {
  gatewayHost: string
  onError: (error: unknown) => void
}) {
  const [tokens, setTokens, refresh] = usePolled(api.tokens, 30_000, onError)
  const [label, setLabel] = useState('')
  const [made, setMade] = useState<{ label: string; secret: string } | null>(null)
  const [removing, setRemoving] = useState<AnnounceToken | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function create(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      const result = await api.createToken(label.trim())
      setMade({ label: result.token.label, secret: result.secret })
      setLabel('')
      refresh()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  const host = gatewayHost || 'sgc.your-domain'
  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">Servers that announce their services</h2>
        <p className="text-sm">
          A server running Docker can tell SGC about its services itself: give it a token, and add
          a small container to its compose file that announces them when it starts. Nothing of
          SGC runs on the server.
        </p>

        {made ? (
          <ShowOnce host={host} label={made.label} secret={made.secret} onDone={() => setMade(null)} />
        ) : (
          <form onSubmit={create} className="flex flex-wrap items-end gap-2">
            <div className="flex min-w-48 flex-1 flex-col gap-1.5">
              <label htmlFor="token-label" className="text-sm font-medium">
                A token for the server
              </label>
              <Input id="token-label" placeholder="media server" maxLength={60} value={label}
                onChange={(e) => setLabel(e.target.value)} />
            </div>
            <Button type="submit" size="sm" disabled={!label.trim()}>
              <KeyRound />
              Make a token
            </Button>
          </form>
        )}
        <FormError message={error} />

        {tokens && tokens.length > 0 && (
          <ul className="flex flex-col gap-2 text-sm">
            {tokens.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center justify-between gap-2">
                <span className="min-w-0">
                  <span className="font-medium">{t.label}</span>{' '}
                  <span className="text-muted-foreground">({t.hint}…)</span>
                  <span className="block text-xs text-muted-foreground">
                    {t.pinnedIp ? `from ${t.pinnedIp}` : 'not used yet'}
                    {t.lastUsedAt && ` · last ${formatTimeAgo(t.lastUsedAt)}`}
                    {t.services.length > 0 && ` · ${t.services.join(', ')}`}
                  </span>
                </span>
                <span className="flex gap-1">
                  {t.pinnedIp && (
                    <Button size="sm" variant="ghost" onClick={() => api.repinToken(t.id).then(setTokens, onError)}>
                      Server moved
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setRemoving(t)}>
                    Remove
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
      {removing && (
        <RemoveTokenDialog
          token={removing}
          onClose={() => setRemoving(null)}
          onDone={(next) => {
            setTokens(next)
            setRemoving(null)
          }}
        />
      )}
    </Card>
  )
}

function ShowOnce({ host, label, secret, onDone }: { host: string; label: string; secret: string; onDone: () => void }) {
  const [copied, setCopied] = useState('')
  const compose = `  announce:
    image: curlimages/curl
    restart: "no"
    command: >-
      --fail-with-body -sS --retry 10 --retry-delay 6 --retry-connrefused
      -H "Authorization: Bearer \${SGC_TOKEN}"
      -d service=NAME:PORT
      https://${host}/api/announce`
  const env = `SGC_TOKEN=${secret}`
  const copy = (what: string, text: string) =>
    navigator.clipboard.writeText(text).then(() => setCopied(what), () => setCopied(''))
  return (
    <div className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3 text-sm">
      <p>
        The token for <span className="font-medium">{label}</span>. It is shown only now; SGC
        keeps only a fingerprint of it. Put it in the server's <code>.env</code> file:
      </p>
      <pre className="overflow-x-auto rounded-md bg-background p-2 text-xs">{env}</pre>
      <Button size="sm" variant="outline" className="self-start" onClick={() => copy('env', env)}>
        <Copy />
        {copied === 'env' ? 'Copied' : 'Copy'}
      </Button>
      <p>
        And this under <code>services:</code> in its compose file, with your service's name and
        port (repeat <code>-d service=…</code> for several):
      </p>
      <pre className="overflow-x-auto rounded-md bg-background p-2 text-xs">{compose}</pre>
      <Button size="sm" variant="outline" className="self-start" onClick={() => copy('compose', compose)}>
        <Copy />
        {copied === 'compose' ? 'Copied' : 'Copy'}
      </Button>
      <p className="text-xs text-muted-foreground">
        Optional fields: -d category=…, -d scheme=https, -d type=tcp or udp, -d mode=proxied. The
        token works from the server's address only: the first one it is used from.
      </p>
      <Button size="sm" className="self-start" onClick={onDone}>
        Done
      </Button>
    </div>
  )
}

function RemoveTokenDialog({
  token,
  onClose,
  onDone,
}: {
  token: AnnounceToken
  onClose: () => void
  onDone: (next: AnnounceToken[]) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function act(keep: boolean) {
    setBusy(true)
    try {
      onDone(await api.removeToken(token.id, keep))
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }
  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Remove the token of {token.label}?</AlertDialogTitle>
          <AlertDialogDescription>
            The server can no longer announce anything.
            {token.services.length > 0 &&
              ` Its services (${token.services.join(', ')}) can be switched off at once, or kept as services you added yourself.`}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          {token.services.length > 0 && (
            <Button variant="outline" onClick={() => act(true)} disabled={busy}>
              Remove, keep the services
            </Button>
          )}
          <Button variant="outline" onClick={() => act(false)} disabled={busy}>
            {token.services.length > 0 ? 'Remove, switch them off' : 'Remove'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
