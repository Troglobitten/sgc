import type { MouseEvent, ReactNode } from 'react'
import { Bell, LogOut, User } from 'lucide-react'

import { Logo } from '@/components/logo'
import { ThemeMenu } from '@/components/theme-menu'
import { Button, buttonVariants } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { api } from '@/lib/api'
import { pageNames, pages, type Page, type SystemSection } from '@/lib/pages'
import { usePolled } from '@/lib/poll'
import { cn } from '@/lib/utils'

// The bell is a convenience: a failed look at it says nothing, the pages
// report their own problems.
const ignore = () => {}

/** What every page needs to draw the frame around itself. */
export interface ShellProps {
  username: string
  version: string
  hostname: string
  /** to a page, or to one of the System page's sections */
  onNavigate: (page: Page, section?: SystemSection | null) => void
  onSignedOut: () => void
}

/** The frame around every signed-in page: who and where, and the way to the other pages. */
export function AppShell({
  page,
  username,
  version,
  hostname,
  onNavigate,
  onSignedOut,
  children,
}: ShellProps & { page: Page; children: ReactNode }) {
  const [summary] = usePolled(api.notificationSummary, 30_000, ignore)

  async function signOut() {
    try {
      await api.logout()
    } finally {
      onSignedOut()
    }
  }

  return (
    <div className="min-h-svh bg-muted/40">
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-2.5 gap-y-1 px-4 py-2 sm:px-6">
        <Logo className="size-7" />
        <span className="font-medium">SGC</span>
        {hostname && <span className="text-sm text-muted-foreground">{hostname}</span>}
        <span className="rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground">
          {version}
        </span>
        {/* On a phone the page links get a row of their own: five columns, the
            icon over the word, so that the row is never wider than the screen
            (it was, once Logs came in 0.16.0). */}
        <nav
          aria-label="Pages"
          className="order-last grid w-full grid-cols-5 gap-1 sm:order-none sm:ml-2 sm:flex sm:w-auto sm:items-center"
        >
          {pageNames.map((name) => (
            <PageLink key={name} name={name} current={name === page} onNavigate={onNavigate} />
          ))}
        </nav>
        <div className="flex-1" />
        <a
          href={pages.logs.path}
          onClick={(event) => {
            if (event.button !== 0 || event.metaKey || event.ctrlKey) return
            event.preventDefault()
            onNavigate('logs')
          }}
          className={buttonVariants({ variant: 'ghost', size: 'icon' }) + ' relative'}
          aria-label={summary && summary.unread > 0 ? `Notifications: ${summary.unread} unread` : 'Notifications'}
        >
          <Bell />
          {summary && summary.unread > 0 && (
            <span className="absolute -top-0.5 -right-0.5 min-w-4 rounded-full bg-red-600 px-1 text-[10px] leading-4 font-medium text-white">
              {summary.unread > 99 ? '99+' : summary.unread}
            </span>
          )}
        </a>
        <ThemeMenu />
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" />}>
            <User />
            {/* On a phone the name is left out to keep the top row to one line. */}
            <span className="sr-only sm:not-sr-only">{username}</span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={signOut}>
              <LogOut />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        </div>
      </header>

      {/* Problems that last are listed once, on the dashboard ("Needs your
          attention"), and counted on the bell here; the card concerned shows
          its own warning where the thing is set. A banner on every page
          filled a phone's whole first screen. */}
      <main className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-5 sm:px-6 sm:py-6">{children}</main>
    </div>
  )
}

/**
 * A real link, so it can be opened in a new tab; an ordinary click switches
 * the page without loading SGC again.
 */
function PageLink({
  name,
  current,
  onNavigate,
}: {
  name: Page
  current: boolean
  onNavigate: (page: Page) => void
}) {
  const { path, label, icon: Icon } = pages[name]
  function open(event: MouseEvent) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return
    }
    event.preventDefault()
    onNavigate(name)
  }
  return (
    <a
      href={path}
      onClick={open}
      aria-current={current ? 'page' : undefined}
      className={cn(
        buttonVariants({ variant: current ? 'secondary' : 'ghost', size: 'sm' }),
        'h-auto min-h-11 min-w-0 flex-col gap-0.5 px-0 py-1 text-[11px] tracking-tight sm:h-8 sm:min-h-0 sm:flex-row sm:gap-1.5 sm:px-2.5 sm:py-0 sm:text-sm sm:tracking-normal',
      )}
    >
      <Icon />
      <span className="max-w-full truncate">{label}</span>
    </a>
  )
}
