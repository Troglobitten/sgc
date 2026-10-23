import { useEffect, useState } from 'react'

import { FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type NotificationChannels, type NotificationSettings } from '@/lib/api'

const selectClass = 'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

/** Where SGC's notifications go besides the bell: email and ntfy, per kind. */
export function NotificationsCard({ onError }: { onError: (error: unknown) => void }) {
  const [settings, setSettings] = useState<NotificationSettings | null>(null)
  const [draft, setDraft] = useState<NotificationChannels | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.notificationSettings().then((s) => {
      setSettings(s)
      setDraft(s.channels)
    }, onError)
  }, [onError])

  if (!settings || !draft) {
    return (
      <Card>
        <CardContent>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }
  const email = draft.email
  const ntfy = draft.ntfy
  const setEmail = (patch: Partial<NotificationChannels['email']>) => setDraft({ ...draft, email: { ...email, ...patch } })
  const setNtfy = (patch: Partial<NotificationChannels['ntfy']>) => setDraft({ ...draft, ntfy: { ...ntfy, ...patch } })

  async function save() {
    if (!draft) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const next = await api.saveNotificationSettings(draft)
      setSettings(next)
      setDraft(next.channels)
      setMessage('Saved.')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  async function test(channel: 'email' | 'ntfy') {
    setError(null)
    setMessage(null)
    try {
      await api.testNotification(channel)
      setMessage(`A test message went out by ${channel}.`)
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">Notifications</h2>
        <p className="text-sm">
          The bell at the top always has them. Problems and warnings can also go out by email
          and to ntfy (an app for phones).
        </p>

        <label className="flex items-center gap-2 text-sm font-medium">
          <Switch checked={email.enabled} onCheckedChange={(v) => setEmail({ enabled: v })} />
          Email
        </label>
        {email.enabled && (
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-host">Mail server</Label>
              <Input id="mail-host" placeholder="smtp.example.com" value={email.host} onChange={(e) => setEmail({ host: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-security">Connection</Label>
              <select id="mail-security" className={selectClass} value={email.security}
                onChange={(e) => {
                  const security = e.target.value as NotificationChannels['email']['security']
                  setEmail({ security, port: security === 'tls' ? 465 : security === 'starttls' ? 587 : 25 })
                }}>
                <option value="starttls">STARTTLS (port 587)</option>
                <option value="tls">TLS (port 465)</option>
                <option value="none">Not encrypted (a relay in the home network)</option>
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-port">Port</Label>
              <Input id="mail-port" type="number" value={email.port} onChange={(e) => setEmail({ port: Number(e.target.value) })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-user">Username</Label>
              <Input id="mail-user" autoComplete="off" value={email.username} onChange={(e) => setEmail({ username: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-password">{settings.hasPassword ? 'Password (empty: keep it)' : 'Password'}</Label>
              <Input id="mail-password" type="password" autoComplete="off" value={email.password ?? ''} onChange={(e) => setEmail({ password: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-from">From</Label>
              <Input id="mail-from" placeholder="sgc@example.com" value={email.from} onChange={(e) => setEmail({ from: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="mail-to">To</Label>
              <Input id="mail-to" placeholder="you@example.com" value={email.to} onChange={(e) => setEmail({ to: e.target.value })} />
            </div>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm font-medium">
          <Switch checked={ntfy.enabled} onCheckedChange={(v) => setNtfy({ enabled: v })} />
          ntfy
        </label>
        {ntfy.enabled && (
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ntfy-server">Server</Label>
              <Input id="ntfy-server" value={ntfy.server} onChange={(e) => setNtfy({ server: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ntfy-topic">Topic</Label>
              <Input id="ntfy-topic" value={ntfy.topic} onChange={(e) => setNtfy({ topic: e.target.value })} />
              <p className="text-xs text-muted-foreground">On ntfy.sh anyone who knows the topic reads it: make it long and random, or use a token.</p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ntfy-token">{settings.hasToken ? 'Access token (empty: keep it)' : 'Access token (optional)'}</Label>
              <Input id="ntfy-token" type="password" autoComplete="off" value={ntfy.token ?? ''} onChange={(e) => setNtfy({ token: e.target.value })} />
            </div>
          </div>
        )}

        {(email.enabled || ntfy.enabled) && (
          <details className="text-sm">
            <summary className="cursor-pointer text-muted-foreground">Which kinds go where</summary>
            <table className="mt-2 w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="font-normal">Kind</th>
                  <th className="w-16 font-normal">Email</th>
                  <th className="w-16 font-normal">ntfy</th>
                </tr>
              </thead>
              <tbody>
                {settings.events.map((event) => {
                  const route = draft.routes[event.key] ?? { email: true, ntfy: true }
                  const set = (patch: Partial<typeof route>) =>
                    setDraft({ ...draft, routes: { ...draft.routes, [event.key]: { ...route, ...patch } } })
                  return (
                    <tr key={event.key}>
                      <td className="py-1">{event.label}</td>
                      <td><input type="checkbox" aria-label={`${event.label} by email`} checked={route.email} onChange={(e) => set({ email: e.target.checked })} /></td>
                      <td><input type="checkbox" aria-label={`${event.label} to ntfy`} checked={route.ntfy} onChange={(e) => set({ ntfy: e.target.checked })} /></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </details>
        )}

        <FormError message={error} />
        {message && <p className="text-sm text-emerald-700 dark:text-emerald-400">{message}</p>}
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
          {settings.channels.email.enabled && <Button size="sm" variant="outline" onClick={() => test('email')}>Send a test email</Button>}
          {settings.channels.ntfy.enabled && <Button size="sm" variant="outline" onClick={() => test('ntfy')}>Send a test to ntfy</Button>}
        </div>
      </CardContent>
    </Card>
  )
}
