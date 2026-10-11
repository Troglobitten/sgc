import { useState, type FormEvent } from 'react'
import { Check } from 'lucide-react'

import { AuthCard, FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage } from '@/lib/api'
import { cn } from '@/lib/utils'
import { RestorePage } from '@/pages/restore'

// The same rule the server enforces (internal/auth). Checking here too lets
// the form explain the problem before anything is sent.
const usernamePattern = /^[a-z][a-z0-9._-]{0,31}$/

export function SetupPage({
  token,
  minPasswordLength,
  onDone,
}: {
  /** The secret from the one-time link, or '' if the page was opened without it. */
  token: string
  minPasswordLength: number
  onDone: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // A fresh install can also be restored from an export instead.
  const [restoring, setRestoring] = useState(false)

  if (!token) {
    return (
      <AuthCard title="Set up SGC" subtitle="A setup link is needed">
        <p className="text-sm text-muted-foreground">
          SGC has no admin account yet. To create one, open the one-time link that the installer
          printed.
        </p>
        <p className="text-sm text-muted-foreground">
          For a new link, run this on the device over SSH:
        </p>
        <pre className="rounded-lg bg-muted px-3 py-2 font-mono text-sm">sudo sgc setup-link</pre>
      </AuthCard>
    )
  }

  if (restoring) {
    return <RestorePage token={token} onDone={onDone} onCreateInstead={() => setRestoring(false)} />
  }

  // A message about what was wrong is out of date as soon as the user edits
  // anything, so every field clears it.
  const editing = (set: (value: string) => void) => (value: string) => {
    setError(null)
    set(value)
  }

  // Counted the way the server counts: in characters, not bytes.
  const passwordLength = [...password].length
  const longEnough = passwordLength >= minPasswordLength
  const matches = password.length > 0 && password === repeat

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!usernamePattern.test(username)) {
      setError('Use lowercase letters, digits, dot, dash or underscore, starting with a letter.')
      return
    }
    if (!longEnough) {
      setError(`Choose a password of at least ${minPasswordLength} characters.`)
      return
    }
    if (!matches) {
      setError("The two passwords don't match.")
      return
    }
    setError(null)
    setBusy(true)
    try {
      await api.setup(token, username, password)
      onDone()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AuthCard title="Set up SGC" subtitle="Create the admin account">
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            value={username}
            onChange={(e) => editing(setUsername)(e.target.value.toLowerCase())}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => editing(setPassword)(e.target.value)}
          />
          <Requirement met={longEnough}>
            At least {minPasswordLength} characters
            {passwordLength > 0 && !longEnough ? ` (${passwordLength} so far)` : ''}
          </Requirement>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="repeat">Repeat password</Label>
          <Input
            id="repeat"
            type="password"
            autoComplete="new-password"
            value={repeat}
            onChange={(e) => editing(setRepeat)(e.target.value)}
          />
          {repeat.length > 0 && <Requirement met={matches}>Passwords match</Requirement>}
        </div>
        <FormError message={error} />
        <Button type="submit" size="lg" disabled={busy}>
          {busy ? 'Creating account…' : 'Create account'}
        </Button>
        <Button type="button" variant="ghost" disabled={busy} onClick={() => setRestoring(true)}>
          Restore from an export instead
        </Button>
        <p className="text-xs text-muted-foreground">
          This link works once and stops working after setup.
        </p>
      </form>
    </AuthCard>
  )
}

function Requirement({ met, children }: { met: boolean; children: React.ReactNode }) {
  return (
    <p
      className={cn(
        'flex items-center gap-1.5 text-xs',
        met ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground',
      )}
    >
      <Check className={cn('size-3.5', met ? 'opacity-100' : 'opacity-0')} aria-hidden="true" />
      {children}
    </p>
  )
}
