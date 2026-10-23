import { useCallback, useEffect, useState } from 'react'

import type { ShellProps } from '@/components/app-shell'
import { Logo } from '@/components/logo'
import { Button } from '@/components/ui/button'
import { api, errorMessage, type State } from '@/lib/api'
import { pageForPath, pages, type Page } from '@/lib/pages'
import { DashboardPage } from '@/pages/dashboard'
import { LoginPage } from '@/pages/login'
import { PeoplePage } from '@/pages/people'
import { ServicesPage } from '@/pages/services'
import { SetupPage } from '@/pages/setup'
import { SystemPage } from '@/pages/system'

// The secret part of the one-time setup link lives after the "#", which
// browsers never send to a server.
function readSetupToken(): string {
  return window.location.pathname === '/setup' ? window.location.hash.slice(1) : ''
}

// The page the address asks for, for a signed-in admin. Anything that is not
// one of SGC's pages means the dashboard.
function readPage(): Page {
  return pageForPath(window.location.pathname) ?? 'dashboard'
}

// SGC decides which screen to show from its own state, not from the address:
// a fresh install shows setup, a signed-out visitor the sign-in form. Only a
// signed-in admin has pages to choose between, and for those the address
// counts. Otherwise the address bar is only kept tidy to match.
export default function App() {
  const [state, setState] = useState<State | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [setupToken, setSetupToken] = useState(readSetupToken)
  const [page, setPage] = useState<Page>(readPage)
  const [hostname, setHostname] = useState('')

  // Pasting the setup link into a tab that already shows SGC only changes the
  // part after the "#". The browser does not reload the page for that, so the
  // app has to notice the change itself. The same goes for the browser's
  // back and forward buttons between SGC's pages.
  useEffect(() => {
    const onHashChange = () => setSetupToken(readSetupToken())
    const onPopState = () => setPage(readPage())
    window.addEventListener('hashchange', onHashChange)
    window.addEventListener('popstate', onPopState)
    return () => {
      window.removeEventListener('hashchange', onHashChange)
      window.removeEventListener('popstate', onPopState)
    }
  }, [])

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

  const signedIn = state?.signedIn ?? false
  useEffect(() => {
    if (!state) return
    const path = state.setupRequired ? '/setup' : state.signedIn ? pages[page].path : '/login'
    // Keep the setup secret in the address while it is still needed, and
    // drop it from the address bar and history as soon as it is not.
    const hash = state.setupRequired ? window.location.hash : ''
    if (window.location.pathname !== path || window.location.hash !== hash) {
      window.history.replaceState(null, '', path + hash)
    }
  }, [state, page])

  // The device's name for the top of every page. It does not change while
  // the page is open, so it is asked for once.
  useEffect(() => {
    if (!signedIn) return
    let stopped = false
    api.health().then(
      (health) => !stopped && setHostname(health.hostname),
      () => {}, // the pages report problems themselves
    )
    return () => {
      stopped = true
    }
  }, [signedIn])

  const navigate = useCallback((next: Page) => {
    if (window.location.pathname !== pages[next].path) {
      window.history.pushState(null, '', pages[next].path)
    }
    setPage(next)
  }, [])

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

  const shell: ShellProps = {
    username: state.username ?? '',
    version: state.version,
    hostname,
    onNavigate: navigate,
    onSignedOut: refresh,
  }
  if (page === 'services') return <ServicesPage shell={shell} />
  if (page === 'people') return <PeoplePage shell={shell} />
  if (page === 'system') {
    return <SystemPage shell={shell} minPassphraseLength={state.minPassphraseLength} />
  }
  return <DashboardPage shell={shell} />
}
