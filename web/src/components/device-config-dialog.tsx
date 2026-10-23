import { useMemo, useState, type FormEvent } from 'react'
import { Download } from 'lucide-react'
import { encode } from 'uqr'

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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, errorMessage, type VpnDevice } from '@/lib/api'

/**
 * A device's settings as a QR code and a file. They hold the device's
 * private key, so the admin's password is asked first, and SGC records
 * that they were shown.
 */
export function DeviceConfigDialog({ device, onClose }: { device: VpnDevice; onClose: () => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [shown, setShown] = useState<{ config: string; filename: string } | null>(null)

  async function reveal(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setShown(await api.deviceConfig(device.id, password))
      setPassword('')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  function download() {
    if (!shown) return
    const url = URL.createObjectURL(new Blob([shown.config], { type: 'text/plain' }))
    const link = document.createElement('a')
    link.href = url
    link.download = shown.filename
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <AlertDialog open onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {device.personName}: {device.name}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {shown
              ? 'Scan this in the WireGuard app (add a tunnel, from QR code), or give a laptop the file. Close this when done: anyone who sees the code can use the device’s access.'
              : 'The QR code holds this device’s secret key. Enter your admin password to show it.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {shown ? (
          <div className="flex flex-col items-center gap-3">
            <QrCode text={shown.config} />
            <Button variant="outline" size="sm" onClick={download}>
              <Download />
              {shown.filename}
            </Button>
          </div>
        ) : (
          <form onSubmit={reveal} className="flex flex-col gap-2">
            <Label htmlFor="reveal-password">Admin password</Label>
            <Input id="reveal-password" type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} />
            <FormError message={error} />
            <Button type="submit" size="sm" className="self-start" disabled={busy || !password}>
              {busy ? 'Checking…' : 'Show the QR code'}
            </Button>
          </form>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Close</AlertDialogCancel>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** A QR code drawn as squares on a white ground (also in dark mode: scanners want it so). */
function QrCode({ text }: { text: string }) {
  const qr = useMemo(() => encode(text, { ecc: 'M', border: 2 }), [text])
  const cells: string[] = []
  qr.data.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) cells.push(`M${x} ${y}h1v1h-1z`)
    }),
  )
  return (
    <svg
      viewBox={`0 0 ${qr.size} ${qr.size}`}
      className="size-64 rounded-lg bg-white"
      shapeRendering="crispEdges"
      role="img"
      aria-label="QR code with the device's settings"
    >
      <path d={cells.join('')} fill="#000" />
    </svg>
  )
}
