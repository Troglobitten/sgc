import { useCallback, useEffect, useState } from 'react'

import { Logo } from '@/components/logo'
import { Button } from '@/components/ui/button'
import { api, errorMessage, type State } from '@/lib/api'
import { DashboardPage } from '@/pages/dashboard'
import { LoginPage } from '@/pages/login'
import { SetupPage } from '@/pages/setup'

// The secret part of the one-time setup link lives after the "#", which
// browsers never send to a server. Read it once, at load.
const setupToken = window.location.pathname === '/setup' ? window.location.hash.slice(1) : ''

// SGC decides which screen to show from its own state, not from the address:
// a fresh install shows setup, a signed-out visitor the sign-in form,
// everyone else the dashboard. The address bar is only kept tidy to match.
export default function App() {
  const [state, setState] = useState<State | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(() => {
    api.state().then(
      (next) => {
        setState(next)
        setError(null)
      },
      (e) => setError(errorMessage(e)),
    )
  }, [])

  useEffect(refresh, [refresh])

  useEffect(() => {
    if (!state) return
    const path = state.setupRequired ? '/setup' : state.signedIn ? '/' : '/login'
    // Keep the setup secret in the address while it is still needed, and
    // drop it from the address bar and history as soon as it is not.
    const hash = state.setupRequired ? window.location.hash : ''
    if (window.location.pathname !== path || window.location.hash !== hash) {
      window.history.replaceState(null, '', path + hash)
    }
  }, [state])

  if (error) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-4 p-4 text-center">
        <Logo />
        <p role="alert" className="max-w-xs text-sm text-muted-foreground">
          {error}
        </p>
        <Button variant="outline" onClick={refresh}>
          Try again
        </Button>
      </div>
    )
  }
  if (!state) return null

  if (state.setupRequired) {
    return (
      <SetupPage token={setupToken} minPasswordLength={state.minPasswordLength} onDone={refresh} />
    )
  }
  if (!state.signedIn) return <LoginPage onDone={refresh} />
  return (
    <DashboardPage username={state.username ?? ''} version={state.version} onSignedOut={refresh} />
  )
}
