import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Copy } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { Facts, More, SettingCard, StatusBadge, Warning } from '@/components/setting'
import { Button } from '@/components/ui/button'
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
/** The start and end of a key's public half, as SGC names it (internal/backups.KeyFingerprint). */
function keyFingerprint(publicKey: string): string {
  return publicKey.length <= 20 ? publicKey : `${publicKey.slice(0, 13)}…${publicKey.slice(-6)}`
}

export function BackupsCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<BackupStatus | null>(null)
  const [draft, setDraft] = useState<BackupSettings | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [secret, setSecret] = useState<string | null>(null)
  const [keyPassword, setKeyPassword] = useState('')
  // Making a new key while there is one: the form, with what that means.
  const [replacing, setReplacing] = useState(false)
  const [offeredKey, setOfferedKey] = useState<string | null>(null)
  // Changing where and when, on a set-up device.
  const [editing, setEditing] = useState(false)

  useEffect(() => {
    api.backups().then((s) => {
      setStatus(s)
      setDraft(s.settings)
    }, onError)
  }, [onError])

  if (!status || !draft) {
    return (
      <SettingCard title="Daily backups">
        <p className="text-sm text-muted-foreground">…</p>
      </SettingCard>
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
      setEditing(false)
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
      setReplacing(false)
      const next = await api.backups()
      setStatus(next)
      setDraft((d) => (d ? { ...d, publicKey: next.settings.publicKey } : d))
    })
  }

  const ok = status.lastSuccess && !status.overdue
  const enabled = status.settings.enabled
  // Set up and working: a summary, with the form behind "Change". Not set
  // up yet: the form at once.
  const showForm = editing || !enabled
  const badge = !enabled ? (
    <StatusBadge tone="muted">Off</StatusBadge>
  ) : status.last && !status.last.ok ? (
    <StatusBadge tone="warn">The last one failed</StatusBadge>
  ) : ok ? (
    <StatusBadge tone="ok">Up to date</StatusBadge>
  ) : status.overdue ? (
    <StatusBadge tone="warn">Overdue</StatusBadge>
  ) : (
    <StatusBadge tone="muted">No backup yet</StatusBadge>
  )
  const saved = status.settings.target

  return (
    <SettingCard title="Daily backups" status={badge}>
        {!enabled && (
          <p className="text-sm">
            Every day SGC makes an export and puts it on a share, an SFTP server or a WebDAV folder, and keeps the newest
            few. If this device breaks, a fresh install restores the newest one.
          </p>
        )}

        {enabled && !editing && (
          <Facts
            items={[
              [
                'Last',
                status.last
                  ? status.last.ok
                    ? `${formatTimeAgo(status.last.at)} · ${formatBytes(status.last.size)}`
                    : `${formatTimeAgo(status.last.at)}, failed`
                  : 'none yet',
              ],
              ['Where', describeTarget(saved)],
              ['When', `every day at ${status.settings.time}, the newest ${status.settings.keep} kept`],
              ...(status.hasKey ? [['Backup key', <code key="key">{keyFingerprint(status.settings.publicKey)}</code>] as [string, ReactNode]] : []),
            ]}
          />
        )}
        {status.last && !status.last.ok && <Warning>{status.last.message}</Warning>}

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
        ) : (!status.hasKey || replacing) && (
          <form onSubmit={makeKey} className="flex flex-col gap-2 rounded-lg bg-muted/50 p-3">
            {status.hasKey ? (
              <p className="text-sm">
                A new backup key replaces the one in use. Backups made until now stay locked to the old key:
                keep the old key for as long as you keep those backups. Enter your admin password to make it.
              </p>
            ) : (
              <p className="text-sm">First, the backup key. Enter your admin password to make it.</p>
            )}
            <div className="flex flex-wrap gap-2">
              <Input type="password" autoComplete="current-password" placeholder="Admin password" value={keyPassword}
                className="max-w-56" onChange={(e) => setKeyPassword(e.target.value)} />
              <Button type="submit" size="sm" disabled={!keyPassword || busy !== null}>
                {status.hasKey ? 'Make a new backup key' : 'Make the backup key'}
              </Button>
              {status.hasKey && (
                <Button type="button" size="sm" variant="ghost" onClick={() => { setReplacing(false); setKeyPassword('') }}>
                  Cancel
                </Button>
              )}
            </div>
          </form>
        )}

        {enabled && !editing && (
          <div className="flex flex-wrap gap-2">
            {status.hasKey && (
              <Button variant="outline" disabled={busy !== null}
                onClick={() => act('run', async () => {
                  const run = await api.backUpNow()
                  setMessage(`Backed up: ${run.file}`)
                  setStatus(await api.backups())
                })}>
                {busy === 'run' ? 'Backing up…' : 'Back up now'}
              </Button>
            )}
            <Button variant="outline" onClick={() => { setDraft(status.settings); setEditing(true); setMessage(null) }}>
              Change where and when
            </Button>
          </div>
        )}

        {showForm && (
          <div className={enabled ? 'flex flex-col gap-3 border-t pt-3' : 'flex flex-col gap-3'}>
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
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="outline" onClick={test} disabled={busy !== null}>{busy === 'test' ? 'Testing…' : 'Test the connection'}</Button>
              {enabled ? (
                <>
                  <Button onClick={() => save()} disabled={busy !== null}>{busy === 'save' ? 'Saving…' : 'Save'}</Button>
                  <Button variant="ghost" disabled={busy !== null} onClick={() => { setDraft(status.settings); setEditing(false) }}>Cancel</Button>
                  <Button variant="ghost" className="text-muted-foreground" disabled={busy !== null} onClick={() => save(false)}>
                    Switch daily backups off
                  </Button>
                </>
              ) : (
                <Button onClick={() => save(true)} disabled={busy !== null || !status.hasKey}>
                  {busy === 'save' ? 'Saving…' : 'Save and switch on'}
                </Button>
              )}
            </div>
          </div>
        )}

        <FormError message={error} />
        {message && <p className="text-sm text-emerald-700 dark:text-emerald-400">{message}</p>}

        {status.hasKey && !secret && !replacing && (
          <More label="About the backup key">
            <p>
              Backups are locked to the backup key. SGC keeps only its locking half; you kept the opening half when you made
              it. Without that half a backup cannot be opened, by anyone. To restore one, enter it where the passphrase
              goes.
            </p>
            <div>
              <Button variant="outline" size="sm" onClick={() => setReplacing(true)} disabled={busy !== null}>
                Make a new backup key
              </Button>
            </div>
            <p>Keep the old key for as long as you keep backups made with it.</p>
          </More>
        )}
    </SettingCard>
  )
}

/** Where backups go, in one line. */
function describeTarget(t: BackupTarget): string {
  switch (t.kind) {
    case 'webdav':
      return `WebDAV folder · ${t.url}`
    case 'smb':
      return `share ${t.share} on ${t.host}${t.path ? `, folder ${t.path}` : ''}`
    case 'sftp':
      return `SFTP on ${t.host}${t.path ? `, folder ${t.path}` : ''}`
    default:
      return '–'
  }
}
