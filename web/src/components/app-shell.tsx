import type { MouseEvent, ReactNode } from 'react'
import { LogOut, User } from 'lucide-react'

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
import { pageNames, pages, type Page } from '@/lib/pages'

/** What every page needs to draw the frame around itself. */
export interface ShellProps {
  username: string
  version: string
  hostname: string
  onNavigate: (page: Page) => void
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
  async function signOut() {
    try {
      await api.logout()
    } finally {
      onSignedOut()
    }
  }

  return (
    <div className="min-h-svh bg-muted/40">
      <header className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b bg-background px-4 py-2">
        <Logo className="size-7" />
        <span className="font-medium">SGC</span>
        {hostname && <span className="text-sm text-muted-foreground">{hostname}</span>}
        <span className="rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground">
          {version}
        </span>
        {/* On a phone the page links get a row of their own. */}
        <nav
          aria-label="Pages"
          className="order-last flex w-full items-center gap-1 sm:order-none sm:ml-2 sm:w-auto"
        >
          {pageNames.map((name) => (
            <PageLink key={name} name={name} current={name === page} onNavigate={onNavigate} />
          ))}
        </nav>
        <div className="flex-1" />
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
      </header>

      <main className="mx-auto flex max-w-5xl flex-col gap-6 p-4">{children}</main>
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
      className={buttonVariants({ variant: current ? 'secondary' : 'ghost', size: 'sm' })}
    >
      <Icon />
      {label}
    </a>
  )
}
