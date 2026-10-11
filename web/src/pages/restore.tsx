import { useEffect, useState, type FormEvent } from 'react'

import { AuthCard, FormError } from '@/components/auth-card'
import { Logo } from '@/components/logo'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage, type ExportManifest } from '@/lib/api'

/**
 * Restoring a fresh install from an export: choose the file, see what it
 * contains, confirm. Guarded by the same one-time link as creating an account.
 */
export function RestorePage({
  token,
  onDone,
  onCreateInstead,
}: {
  token: string
  onDone: () => void
  onCreateInstead: () => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [preview, setPreview] = useState<ExportManifest | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [restoring, setRestoring] = useState(false)

  async function check(event: FormEvent) {
    event.preventDefault()
    if (!file) {
      setError('Choose the export file first.')
      return
    }
    setError(null)
    setBusy(true)
    try {
      setPreview(await api.restorePreview(token, passphrase, file))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function restore() {
    setError(null)
    setBusy(true)
    try {
      await api.restoreConfirm(token)
      setRestoring(true)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  if (restoring) return <RestoringScreen onDone={onDone} />

  if (preview) {
    const made = new Date(preview.createdAt).toLocaleDateString(undefined, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    })
    return (
      <AuthCard title="Restore SGC" subtitle="Check that this is the right export">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-lg bg-muted px-3 py-2.5 text-sm">
          <dt className="text-muted-foreground">Made on</dt>
          <dd>{made}</dd>
          <dt className="text-muted-foreground">Device</dt>
          <dd>{preview.hostname || 'unknown'}</dd>
          <dt className="text-muted-foreground">SGC version</dt>
          <dd>{preview.sgcVersion}</dd>
          <dt className="text-muted-foreground">Admin account</dt>
          <dd>{preview.adminUsername}</dd>
        </dl>
        <p className="text-sm text-muted-foreground">
          After restoring, sign in as {preview.adminUsername} with the password that account had
          when the export was made.
        </p>
        <FormError message={error} />
        <div className="flex flex-col gap-2">
          <Button size="lg" onClick={restore} disabled={busy}>
            {busy ? 'Restoring…' : 'Restore'}
          </Button>
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => {
              setPreview(null)
              setError(null)
            }}
          >
            Choose another file
          </Button>
        </div>
      </AuthCard>
    )
  }

  return (
    <AuthCard title="Restore SGC" subtitle="From an export of an earlier install">
      <form onSubmit={check} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-2">
          <Label htmlFor="file">Export file</Label>
          <Input
            id="file"
            type="file"
            accept=".age"
            onChange={(e) => {
              setError(null)
              setFile(e.target.files?.[0] ?? null)
            }}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="passphrase">Passphrase of the file</Label>
          <Input
            id="passphrase"
            type="password"
            autoComplete="off"
            value={passphrase}
            onChange={(e) => {
              setError(null)
              setPassphrase(e.target.value)
            }}
          />
        </div>
        <FormError message={error} />
        <Button type="submit" size="lg" disabled={busy}>
          {busy ? 'Opening the file…' : 'Check file'}
        </Button>
        <Button type="button" variant="ghost" onClick={onCreateInstead} disabled={busy}>
          Create a new account instead
        </Button>
      </form>
    </AuthCard>
  )
}

/**
 * Shown while SGC starts over on the restored data. Done when SGC answers
 * and no longer asks for setup.
 */
function RestoringScreen({ onDone }: { onDone: () => void }) {
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    const check = () =>
      api.state().then(
        (state) => {
          if (state.setupRequired) timer = setTimeout(check, 1_000)
          else onDone()
        },
        () => {
          timer = setTimeout(check, 1_000)
        },
      )
    timer = setTimeout(check, 1_000)
    return () => clearTimeout(timer)
  }, [onDone])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-4 bg-muted/40 p-4 text-center">
      <Logo className="size-14 animate-spin [animation-duration:6s]" />
      <h1 className="text-base font-medium">Restoring SGC</h1>
      <p className="max-w-xs text-sm text-muted-foreground">
        This takes a few seconds. The sign-in screen appears by itself.
      </p>
    </div>
  )
}
