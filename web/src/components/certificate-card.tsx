import { useEffect, useId, useState, type ReactNode } from 'react'
import { CircleCheck, TriangleAlert } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { api, errorMessage, type CertificateStatus } from '@/lib/api'
import { daysUntil } from '@/lib/format'

const idleInterval = 15_000
const busyInterval = 2_000

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' })
}

function formatMoment(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
}

/**
 * The certificate for every name under the owner's domain, from Let's
 * Encrypt.
 *
 * Getting one takes a few minutes and runs in the background; this card
 * follows it. SGC first goes through the same steps with Let's Encrypt's
 * test authority, and renews by itself afterwards.
 */
export function CertificateCard({ onError }: { onError: (error: unknown) => void }) {
  const [status, setStatus] = useState<CertificateStatus | null>(null)
  const [asking, setAsking] = useState(false)
  const [starting, setStarting] = useState(false)
  const busy = status?.running != null

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.certificate().then(
        (s) => !stopped && setStatus(s),
        (e) => !stopped && onError(e),
      )
    }
    load()
    const timer = setInterval(load, busy ? busyInterval : idleInterval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [onError, busy])

  const title = 'Certificate (Let’s Encrypt)'
  if (status === null) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm text-muted-foreground">{title}</h2>
          <p className="text-sm text-muted-foreground">…</p>
        </CardContent>
      </Card>
    )
  }

  const certificate = status.certificate
  const current = certificate?.forDomain ? certificate : null
  const days = current ? daysUntil(current.notAfter) : 0
  const failed = status.lastAttempt != null && !status.lastAttempt.ok ? status.lastAttempt : null

  // A renewal needs no question. The first certificate does: the owner
  // agrees to the authority's terms, and should know what becomes public.
  async function renewNow() {
    setStarting(true)
    try {
      setStatus(await api.requestCertificate(false))
    } catch (e) {
      onError(e)
    } finally {
      setStarting(false)
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm text-muted-foreground">{title}</h2>
          {current && !busy && (
            <span
              className={
                days >= 14 && !failed
                  ? 'flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-400'
                  : 'flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400'
              }
            >
              {days >= 14 && !failed ? (
                <CircleCheck className="size-4" aria-hidden="true" />
              ) : (
                <TriangleAlert className="size-4" aria-hidden="true" />
              )}
              {days < 0 ? 'Run out' : `${days} days left`}
            </span>
          )}
        </div>

        {status.disabled !== '' && <Notice>{status.disabled}</Notice>}

        {status.running && <Running status={status} />}

        {!status.running && current && (
          <>
            <p className="text-sm">
              <span className="font-medium">{current.names.join(', ')}</span>, issued by{' '}
              {current.issuer}. Valid until {formatDate(current.notAfter)}.
            </p>
            {status.renewsAt !== null && (
              <p className="text-sm text-muted-foreground">
                SGC renews it by itself, around {formatDate(status.renewsAt)}.
              </p>
            )}
          </>
        )}

        {!status.running && !current && (
          <p className="text-sm">
            One certificate for every name under your domain, from Let&apos;s Encrypt, so that
            browsers show a padlock without a warning. SGC proves that the domain is yours by
            publishing a piece of text in its DNS at Zone.eu, and removes it again.
          </p>
        )}
        {!status.running && certificate && !certificate.forDomain && status.domain !== '' && (
          <Notice>
            The certificate SGC has is for {certificate.names.join(', ')}, not for the domain
            that is set up now.
          </Notice>
        )}
        {!status.running && status.domain === '' && (
          <Notice>A certificate is for a domain. Set up the domain first.</Notice>
        )}

        {!status.running && failed && (
          <Notice>
            {failed.kind === 'renewal' ? 'Renewing by itself failed' : 'The last attempt failed'}{' '}
            ({formatMoment(failed.finishedAt)}): {failed.message}
            {failed.kind === 'renewal' && ' SGC tries again twice a day.'}
          </Notice>
        )}
        {!status.running && failed && failed.log.length > 0 && <Log lines={failed.log} />}

        {!status.running && status.disabled === '' && status.domain !== '' && (
          <div className="flex flex-wrap items-center gap-2">
            {current ? (
              <Button variant="outline" onClick={renewNow} disabled={starting || status.waitUntil !== null}>
                {starting ? 'Starting…' : 'Renew now'}
              </Button>
            ) : (
              <Button onClick={() => setAsking(true)} disabled={status.waitUntil !== null}>
                Get the certificate
              </Button>
            )}
            {status.waitUntil !== null && (
              <span className="text-xs text-muted-foreground">
                Possible again from {formatMoment(status.waitUntil)}: Let&apos;s Encrypt counts
                requests.
              </span>
            )}
          </div>
        )}

        {asking && (
          <FirstDialog
            status={status}
            onClose={() => setAsking(false)}
            onDone={(next) => {
              setAsking(false)
              setStatus(next)
            }}
          />
        )}
      </CardContent>
    </Card>
  )
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-400">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}

/** What an attempt reported, for whoever wants the details. */
function Log({ lines }: { lines: string[] }) {
  return (
    <details className="text-xs text-muted-foreground">
      <summary className="cursor-pointer">The steps, as they were reported</summary>
      <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-muted p-2 whitespace-pre-wrap">
        {lines.join('\n')}
      </pre>
    </details>
  )
}

function Running({ status }: { status: CertificateStatus }) {
  const running = status.running!
  return (
    <>
      <p className="text-sm">
        {running.phase === 'trial'
          ? 'Trying with Let’s Encrypt’s test authority first. That takes a few minutes; the real certificate follows.'
          : running.phase === 'pause'
            ? 'The trial worked. SGC waits a couple of minutes before it asks for the real certificate, so that every name server has forgotten the trial’s proof.'
            : running.kind === 'first'
              ? 'Getting the real certificate now, which takes a few minutes more.'
              : 'Renewing the certificate. That takes a few minutes.'}
      </p>
      <p className="text-xs text-muted-foreground">
        You can leave this page; it goes on by itself.
      </p>
      {running.log.length > 0 && <Log lines={running.log} />}
    </>
  )
}

/** Before the first certificate: what it means, and the owner's agreement. */
function FirstDialog({
  status,
  onClose,
  onDone,
}: {
  status: CertificateStatus
  onClose: () => void
  onDone: (next: CertificateStatus) => void
}) {
  const [agreed, setAgreed] = useState(status.termsAgreed)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const agreeId = useId()

  async function act() {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.requestCertificate(agreed))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Get a certificate for *.{status.domain}?</AlertDialogTitle>
          <AlertDialogDescription>
            SGC asks Let&apos;s Encrypt for one certificate that covers every name under{' '}
            {status.domain}. It first goes through the same steps with Let&apos;s Encrypt&apos;s
            test authority, so that a mistake in the set-up does not count against your domain.
            Altogether that takes about ten minutes, most of it waiting for name servers
            around the world to catch up. Every certificate is listed in public logs:
            that there is one for *.{status.domain} will be public. The names of your services
            are not in it.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {!status.termsAgreed && (
          <div className="flex items-start gap-2">
            <Switch id={agreeId} checked={agreed} onCheckedChange={setAgreed} disabled={busy} />
            <Label htmlFor={agreeId} className="font-normal leading-snug">
              I agree to{' '}
              <a
                className="underline"
                href="https://letsencrypt.org/repository/"
                target="_blank"
                rel="noreferrer"
              >
                Let&apos;s Encrypt&apos;s Subscriber Agreement
              </a>
              .
            </Label>
          </div>
        )}
        <FormError message={error} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button onClick={act} disabled={busy || !agreed}>
            {busy ? 'Starting…' : 'Get the certificate'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
