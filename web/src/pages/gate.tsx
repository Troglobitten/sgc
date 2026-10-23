import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { AuthCard, FormError } from '@/components/auth-card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ApiError, errorMessage, request } from '@/lib/api'

interface GateState {
  service: string
  admin: boolean
  person: string
  allowed: boolean
  minPasswordLength: number
}

/**
 * SGC's login gate in front of a protected service. People sign in here
 * (never into SGC's own page); the admin, signed in already, passes at once.
 */
export function GatePage() {
  const rd = new URLSearchParams(window.location.search).get('rd') ?? ''
  const [state, setState] = useState<GateState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [changing, setChanging] = useState(false)

  const load = useCallback(() => {
    request<GateState>('GET', `/api/gate?rd=${encodeURIComponent(rd)}`).then(setState, (e) => setError(errorMessage(e)))
  }, [rd])
  useEffect(load, [load])

  // Signed in and allowed: on to the service.
  useEffect(() => {
    if (!state?.allowed || changing) return
    request<{ redirect: string }>('POST', '/api/gate/ticket', { rd }).then(
      (answer) => window.location.assign(answer.redirect),
      (e) => setError(errorMessage(e)),
    )
  }, [state, rd, changing])

  if (!state) {
    return (
      <AuthCard title="Sign in" subtitle="SGC's login">
        {error ? <FormError message={error} /> : <p className="text-sm text-muted-foreground">…</p>}
      </AuthCard>
    )
  }
  if (!state.service) {
    return (
      <AuthCard title="Sign in" subtitle="SGC's login">
        <p className="text-sm">
          {state.person ? `Signed in as ${state.person}. ` : ''}
          Open the service you want to use; it sends you here when it needs you to sign in.
        </p>
        {state.person && <SignOut onDone={load} />}
        {state.person && (changing ? <ChangePassword min={state.minPasswordLength} onDone={() => setChanging(false)} /> : (
          <Button variant="ghost" size="sm" onClick={() => setChanging(true)}>Change my password</Button>
        ))}
      </AuthCard>
    )
  }
  if (state.allowed) {
    return (
      <AuthCard title={state.service} subtitle="SGC's login">
        <p className="text-sm text-muted-foreground">On to {state.service}…</p>
        <FormError message={error} />
      </AuthCard>
    )
  }
  if (state.person) {
    return (
      <AuthCard title={state.service} subtitle="SGC's login">
        <p className="text-sm">
          Signed in as {state.person}, whose login does not include {state.service}. Ask the
          owner of this network.
        </p>
        <SignOut onDone={load} />
      </AuthCard>
    )
  }
  return (
    <AuthCard title={`Sign in to ${state.service}`} subtitle="With the login the owner of this network gave you">
      <SignIn onDone={setState} rd={rd} />
    </AuthCard>
  )
}

function SignIn({ rd, onDone }: { rd: string; onDone: (next: GateState) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await request('POST', '/api/gate/login', { username, password })
      onDone(await request<GateState>('GET', `/api/gate?rd=${encodeURIComponent(rd)}`))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : errorMessage(e))
      setBusy(false)
    }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex flex-col gap-2">
        <Label htmlFor="gate-username">Username</Label>
        <Input id="gate-username" autoComplete="username" autoCapitalize="none" value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="gate-password">Password</Label>
        <Input id="gate-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <FormError message={error} />
      <Button type="submit" disabled={busy || !username || !password}>
        {busy ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  )
}

function SignOut({ onDone }: { onDone: () => void }) {
  return (
    <Button variant="outline" size="sm" onClick={() => request('POST', '/api/gate/logout', {}).finally(onDone)}>
      Sign out
    </Button>
  )
}

function ChangePassword({ min, onDone }: { min: number; onDone: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      await request('POST', '/api/gate/password', { current, next })
      setDone(true)
    } catch (e) {
      setError(errorMessage(e))
    }
  }
  if (done) {
    return (
      <p className="text-sm">
        Your password is changed. <Button variant="link" size="sm" onClick={onDone}>Done</Button>
      </p>
    )
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-2">
      <Label htmlFor="gate-current">Current password</Label>
      <Input id="gate-current" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      <Label htmlFor="gate-next">New password (at least {min} characters)</Label>
      <Input id="gate-next" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
      <FormError message={error} />
      <Button type="submit" size="sm" disabled={!current || next.length < min}>Change it</Button>
    </form>
  )
}
