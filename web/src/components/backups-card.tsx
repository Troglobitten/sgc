import { useEffect, useState, type FormEvent } from 'react'
import { CircleCheck, Copy, TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type BackupSettings, type BackupStatus, type BackupTarget } from '@/lib/api'
import { formatBytes, formatTimeAgo } from '@/lib/format'

const selectClass = 'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

/**
 * Backups every day to another device, encrypted to a backup key of which
 * SGC keeps only the public half.
 */
export function BackupsCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<BackupStatus | null>(null)
  const [draft, setDraft] = useState<BackupSettings | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [secret, setSecret] = useState<string | null>(null)
  const [keyPassword, setKeyPassword] = useState('')
  const [offeredKey, setOfferedKey] = useState<string | null>(null)

  useEffect(() => {
    api.backups().then((s) => {
      setStatus(s)
      setDraft(s.settings)
    }, onError)
  }, [onError])

  if (!status || !draft) {
    return (
      <Card>
        <CardContent>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }
  const t = draft.target
  const setTarget = (patch: Partial<BackupTarget>) => setDraft({ ...draft, target: { ...t, ...patch } })

  async function act(what: string, run: () => Promise<void>) {
    setBusy(what)
    setError(null)
    setMessage(null)
    try {
      await run()
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }
  const save = (enabled = draft.enabled) =>
    act('save', async () => {
      const next = await api.saveBackups({ ...draft, enabled })
      setStatus(next)
      setDraft(next.settings)
      setMessage('Saved.')
    })
  const test = () =>
    act('test', async () => {
      const answer = await api.testBackupTarget(t)
      if (answer.ok) setMessage('SGC reached the folder and can write there.')
      else if (answer.hostKey) setOfferedKey(answer.hostKey)
      else setError(answer.message ?? 'The test failed.')
    })
  async function makeKey(event: FormEvent) {
    event.preventDefault()
    await act('key', async () => {
      const made = await api.makeBackupKey(keyPassword)
      setSecret(made.secret)
      setKeyPassword('')
      const next = await api.backups()
      setStatus(next)
      setDraft((d) => (d ? { ...d, publicKey: next.settings.publicKey } : d))
    })
  }

  const ok = status.lastSuccess && !status.overdue
  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">Backups to another device</h2>
          {status.settings.enabled && (
            <span className={ok ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400' : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'}>
              {ok ? <CircleCheck className="size-4" aria-hidden="true" /> : <TriangleAlert className="size-4" aria-hidden="true" />}
              {ok ? 'Up to date' : status.overdue ? 'Overdue' : 'No backup yet'}
            </span>
          )}
        </div>
        <p className="text-sm">
          Every day SGC makes an export and puts it on a share, an SFTP server or a WebDAV folder,
          and keeps the newest {draft.keep}. If this device breaks, a fresh install restores the
          newest one.
        </p>

        {status.last && (
          <p className={status.last.ok ? 'text-xs text-muted-foreground' : 'text-sm text-amber-700 dark:text-amber-400'}>
            Last {formatTimeAgo(status.last.at)}: {status.last.ok ? `${status.last.file} (${formatBytes(status.last.size)})` : status.last.message}
          </p>
        )}

        {secret ? (
          <div className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3 text-sm">
            <p className="font-medium">The backup key. Keep it somewhere else than this device, now.</p>
            <p>It is shown only this once. Without it no backup can be opened, by you or anyone; SGC keeps only the half that locks them.</p>
            <pre className="overflow-x-auto rounded-md bg-background p-2 text-xs">{secret}</pre>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(secret)}>
                <Copy />
                Copy
              </Button>
              <Button size="sm" onClick={() => setSecret(null)}>I have kept it</Button>
            </div>
          </div>
        ) : !status.hasKey ? (
          <form onSubmit={makeKey} className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3">
            <p className="text-sm">First, the backup key. Enter your admin password to make it.</p>
            <div className="flex flex-wrap gap-2">
              <Input type="password" autoComplete="current-password" placeholder="Admin password" value={keyPassword}
                className="max-w-56" onChange={(e) => setKeyPassword(e.target.value)} />
              <Button type="submit" size="sm" disabled={!keyPassword || busy !== null}>Make the backup key</Button>
            </div>
          </form>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="bk-kind">Where to</Label>
            <select id="bk-kind" className={selectClass} value={t.kind} onChange={(e) => setTarget({ kind: e.target.value as BackupTarget['kind'] })}>
              <option value="smb">A share (Windows, a NAS: SMB)</option>
              <option value="sftp">A server over SSH (SFTP)</option>
              <option value="webdav">A WebDAV folder (Nextcloud, a NAS)</option>
            </select>
          </div>
          {t.kind === 'webdav' ? (
            <div className="flex flex-col gap-1.5 sm:col-span-2">
              <Label htmlFor="bk-url">Folder address</Label>
              <Input id="bk-url" placeholder="https://nas.home/remote.php/dav/files/alex/sgc" value={t.url} onChange={(e) => setTarget({ url: e.target.value })} />
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="bk-host">Device</Label>
              <Input id="bk-host" placeholder="192.168.1.20" value={t.host} onChange={(e) => setTarget({ host: e.target.value })} />
            </div>
          )}
          {t.kind === 'smb' && (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="bk-share">Share</Label>
              <Input id="bk-share" placeholder="backups" value={t.share} onChange={(e) => setTarget({ share: e.target.value })} />
            </div>
          )}
          {t.kind !== 'webdav' && (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="bk-path">Folder in it (optional)</Label>
              <Input id="bk-path" placeholder="sgc" value={t.path} onChange={(e) => setTarget({ path: e.target.value })} />
            </div>
          )}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="bk-user">Username</Label>
            <Input id="bk-user" autoComplete="off" value={t.username} onChange={(e) => setTarget({ username: e.target.value })} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="bk-password">{status.hasPassword ? 'Password (empty: keep it)' : 'Password'}</Label>
            <Input id="bk-password" type="password" autoComplete="off" value={t.password ?? ''} onChange={(e) => setTarget({ password: e.target.value })} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="bk-time">Every day at</Label>
            <Input id="bk-time" type="time" value={draft.time} onChange={(e) => setDraft({ ...draft, time: e.target.value })} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="bk-keep">Keep the newest</Label>
            <Input id="bk-keep" type="number" min={1} max={100} value={draft.keep} onChange={(e) => setDraft({ ...draft, keep: Number(e.target.value) })} />
          </div>
        </div>
        {t.kind === 'webdav' && t.url.startsWith('https://') && (
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={t.skipVerify} onCheckedChange={(v) => setTarget({ skipVerify: v })} size="sm" />
            The device has a self-signed certificate (do not check it)
          </label>
        )}
        {t.kind === 'sftp' && t.hostKey && <p className="text-xs text-muted-foreground">Server's key, confirmed: {t.hostKey}</p>}
        {offeredKey && (
          <div className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3 text-sm">
            <p>
              The server shows the key <span className="font-mono">{offeredKey}</span>. Compare it with what
              <span className="font-mono"> ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span> says on the server.
            </p>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => { setTarget({ hostKey: offeredKey }); setOfferedKey(null); setMessage('Confirmed; save to keep it.') }}>They are the same</Button>
              <Button size="sm" variant="ghost" onClick={() => setOfferedKey(null)}>Cancel</Button>
            </div>
          </div>
        )}
        <FormError message={error} />
        {message && <p className="text-sm text-emerald-700 dark:text-emerald-400">{message}</p>}
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={test} disabled={busy !== null}>{busy === 'test' ? 'Testing…' : 'Test the connection'}</Button>
          <Button size="sm" onClick={() => save()} disabled={busy !== null}>{busy === 'save' ? 'Saving…' : 'Save'}</Button>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={status.settings.enabled} disabled={busy !== null || !status.hasKey} onCheckedChange={(v) => save(v)} />
            Every day
          </label>
          {status.hasKey && (
            <Button size="sm" variant="outline" disabled={busy !== null}
              onClick={() => act('run', async () => {
                const run = await api.backUpNow()
                setMessage(`Backed up: ${run.file}`)
                setStatus(await api.backups())
              })}>
              {busy === 'run' ? 'Backing up…' : 'Back up now'}
            </Button>
          )}
        </div>
        {status.hasKey && (
          <p className="text-xs text-muted-foreground">
            To restore: install SGC on a fresh device, open the setup link, choose the backup file and enter the backup key where the passphrase goes.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
