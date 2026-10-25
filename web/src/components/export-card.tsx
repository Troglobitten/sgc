import { useState, type FormEvent } from 'react'
import { CircleCheck, Download } from 'lucide-react'

import { FormError } from '@/components/auth-card'
import { SettingCard } from '@/components/setting'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage } from '@/lib/api'

/** Everything SGC holds, saved as one encrypted file. */
export function ExportCard({ minPassphraseLength }: { minPassphraseLength: number }) {
  const [open, setOpen] = useState(false)
  const [savedAs, setSavedAs] = useState<string | null>(null)

  return (
    <SettingCard title="Export">
        <p className="text-sm">
          One file with everything, locked with a passphrase you choose. For moving to a new device, or before something
          risky.
        </p>
        {savedAs && (
          <p className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
            <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <span>
              Saved as {savedAs}. Keep the file and its passphrase somewhere safe, not on this
              device.
            </span>
          </p>
        )}
        <div>
          <Button variant="outline" onClick={() => setOpen(true)}>
            <Download />
            Export…
          </Button>
        </div>
        {open && (
          <ExportDialog
            minPassphraseLength={minPassphraseLength}
            onClose={() => setOpen(false)}
            onSaved={(name) => {
              setSavedAs(name)
              setOpen(false)
            }}
          />
        )}
    </SettingCard>
  )
}

function ExportDialog({
  minPassphraseLength,
  onClose,
  onSaved,
}: {
  minPassphraseLength: number
  onClose: () => void
  onSaved: (name: string) => void
}) {
  const [password, setPassword] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if ([...passphrase].length < minPassphraseLength) {
      setError(`Choose a passphrase of at least ${minPassphraseLength} characters.`)
      return
    }
    if (passphrase !== repeat) {
      setError("The two passphrases don't match.")
      return
    }
    setError(null)
    setBusy(true)
    try {
      const { file, name } = await api.downloadExport(password, passphrase)
      saveFile(file, name)
      onSaved(name)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  // Any edit makes an earlier message out of date.
  const editing = (set: (value: string) => void) => (value: string) => {
    setError(null)
    set(value)
  }

  return (
    <AlertDialog open onOpenChange={(next) => !next && !busy && onClose()}>
      {/* On a small screen the form is taller than the screen; let it scroll. */}
      <AlertDialogContent className="max-h-[calc(100svh-2rem)] overflow-y-auto data-[size=default]:sm:max-w-md">
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <AlertDialogHeader>
            <AlertDialogTitle>Export SGC</AlertDialogTitle>
            <AlertDialogDescription>
              The file contains everything, including your login. It is encrypted with a passphrase
              you choose now. Without that passphrase nobody can open it, including you.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-2">
            <Label htmlFor="export-password">Your SGC password</Label>
            <Input
              id="export-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(e) => editing(setPassword)(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="export-passphrase">Passphrase for the file</Label>
            <Input
              id="export-passphrase"
              type="password"
              autoComplete="new-password"
              value={passphrase}
              onChange={(e) => editing(setPassphrase)(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              At least {minPassphraseLength} characters. Not your SGC password.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="export-repeat">Repeat passphrase</Label>
            <Input
              id="export-repeat"
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => editing(setRepeat)(e.target.value)}
            />
          </div>
          <FormError message={error} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <Button type="submit" disabled={busy || !password}>
              {busy ? 'Encrypting…' : 'Export'}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** Hands a file to the browser to save, as if a download link was clicked. */
function saveFile(file: Blob, name: string) {
  const url = URL.createObjectURL(file)
  const link = document.createElement('a')
  link.href = url
  link.download = name
  document.body.append(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
