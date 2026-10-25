import { useState, type FormEvent } from 'react'
import { CircleCheck } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { More, SettingCard } from '@/components/setting'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage } from '@/lib/api'

/**
 * The admin's own account: changing the password, with the current one.
 * Every other sign-in ends with it (other browsers, and the passes the
 * login gate gave the admin for services); this browser stays signed in.
 */
export function AccountCard({ username, minPasswordLength }: { username: string; minPasswordLength: number }) {
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const tooShort = [...next].length < minPasswordLength
  const mismatch = repeat.length > 0 && repeat !== next

  async function change(event: FormEvent) {
    event.preventDefault()
    setError(null)
    if (tooShort) return setError(`Choose a password of at least ${minPasswordLength} characters.`)
    if (next !== repeat) return setError("The two new passwords don't match.")
    setBusy(true)
    try {
      await api.changeAccountPassword(current, next)
      setDone(true)
      setOpen(false)
      setCurrent('')
      setNext('')
      setRepeat('')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingCard title="Your account">
        <p className="text-sm">
          Signed in as <span className="font-medium">{username}</span>, the admin.
        </p>
        {done && (
          <p className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400">
            <CircleCheck className="size-4" aria-hidden="true" />
            Your password is changed. Every other sign-in has ended.
          </p>
        )}
        {open ? (
          <form onSubmit={change} className="flex flex-col gap-3" noValidate>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="account-current">Current password</Label>
              <Input id="account-current" type="password" autoComplete="current-password" value={current}
                onChange={(e) => setCurrent(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="account-next">New password (at least {minPasswordLength} characters)</Label>
              <Input id="account-next" type="password" autoComplete="new-password" value={next}
                onChange={(e) => setNext(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="account-repeat">New password again</Label>
              <Input id="account-repeat" type="password" autoComplete="new-password" value={repeat}
                onChange={(e) => setRepeat(e.target.value)} aria-invalid={mismatch} />
            </div>
            <p className="text-xs text-muted-foreground">
              Changing it signs you out everywhere else: other browsers, and services behind SGC's login. This
              browser stays signed in.
            </p>
            <FormError message={error} />
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={busy || !current || !next || !repeat}>
                {busy ? 'Changing…' : 'Change the password'}
              </Button>
              <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => { setOpen(false); setError(null) }}>
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <Button size="sm" variant="outline" className="self-start" onClick={() => { setOpen(true); setDone(false) }}>
            Change my password
          </Button>
        )}
        <More label="Lost your password?">
          <p>
            On the device itself, over SSH: <code>sudo sgc reset-admin</code> gives you a new one and ends every sign-in.
          </p>
        </More>
    </SettingCard>
  )
}
