import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { RotateCw, TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { DnsCard } from '@/components/dns-card'
import { ExportCard } from '@/components/export-card'
import { FirewallCard } from '@/components/firewall-card'
import { Log2ramCard } from '@/components/log2ram-card'
import { MaintenanceCard } from '@/components/maintenance-card'
import { OsUpdatesCard } from '@/components/os-updates-card'
import { SshCard } from '@/components/ssh-card'
import { Logo } from '@/components/logo'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { api, ApiError, errorMessage } from '@/lib/api'

/**
 * Settings of the device itself: how it is protected, how to get everything
 * out of it in one file, and how to restart it.
 */
export function SystemPage({
  shell,
  minPassphraseLength,
}: {
  shell: ShellProps
  minPassphraseLength: number
}) {
  const [problem, setProblem] = useState<string | null>(null)
  const [restarting, setRestarting] = useState(false)

  // A 401 means the session ended (expired, or signed out in another tab).
  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )

  if (restarting) return <RestartingScreen />

  return (
    <AppShell page="system" {...shell}>
      {problem && (
        <p
          role="alert"
          className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {problem}
        </p>
      )}

      <Section title="Protection">
        <div className="grid gap-3 md:grid-cols-2">
          <FirewallCard onError={handleError} />
          <SshCard onError={handleError} />
        </div>
      </Section>

      <Section title="Network">
        <div className="grid gap-3 md:grid-cols-2">
          <DnsCard onError={handleError} />
        </div>
      </Section>

      <Section title="This device">
        <div className="grid gap-3 md:grid-cols-2">
          <OsUpdatesCard onError={handleError} />
          <MaintenanceCard onError={handleError} />
          <Log2ramCard onError={handleError} />
          <ExportCard minPassphraseLength={minPassphraseLength} />
          <Card>
            <CardContent className="flex flex-col gap-3">
              <h2 className="text-sm text-muted-foreground">Restart</h2>
              <p className="text-sm">
                Restarts the whole device. Everything running on it stops for about a minute.
              </p>
              <RestartButton onRestarting={() => setRestarting(true)} />
            </CardContent>
          </Card>
        </div>
      </Section>
    </AppShell>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2.5">
      <h2 className="text-sm text-muted-foreground">{title}</h2>
      {children}
    </section>
  )
}

function RestartButton({ onRestarting }: { onRestarting: () => void }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function restart() {
    setBusy(true)
    setError(null)
    try {
      await api.restartDevice()
      setOpen(false)
      onRestarting()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <RotateCw />
        Restart
      </Button>
      <AlertDialog open={open} onOpenChange={(next) => !busy && setOpen(next)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Restart the device?</AlertDialogTitle>
            <AlertDialogDescription>
              Everything running on this device stops for about a minute, including SGC itself.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={restart} disabled={busy}>
              {busy ? 'Restarting…' : 'Restart'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

/** Shown while the device is down; reloads the page once SGC answers again. */
function RestartingScreen() {
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    // Give the device time to actually go down first. Otherwise the first
    // check would still reach the old, about-to-stop SGC and reload too early.
    const check = () =>
      api.state().then(
        () => window.location.reload(),
        () => {
          timer = setTimeout(check, 3_000)
        },
      )
    timer = setTimeout(check, 10_000)
    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-4 bg-muted/40 p-4 text-center">
      <Logo className="size-14 animate-spin [animation-duration:6s]" />
      <h1 className="text-base font-medium">Restarting the device</h1>
      <p className="max-w-xs text-sm text-muted-foreground">
        This takes about a minute. The page comes back by itself.
      </p>
    </div>
  )
}
