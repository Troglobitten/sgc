import { useEffect, useState } from 'react'

import { Button } from '@/components/ui/button'
import { api, type UsagePoint } from '@/lib/api'
import { formatBytes } from '@/lib/format'

type Resolution = 'minute' | 'hour' | 'day'

const labels: Record<Resolution, string> = { minute: '48 hours', hour: '90 days', day: 'all' }

/** What a device (or all of them, device 0) used over time, as bars. */
export function UsageChart({ device }: { device: number }) {
  const [resolution, setResolution] = useState<Resolution>('hour')
  const [points, setPoints] = useState<UsagePoint[] | null>(null)

  useEffect(() => {
    let stopped = false
    api.vpnUsage(device, resolution).then(
      (p) => !stopped && setPoints(p),
      () => !stopped && setPoints([]),
    )
    return () => {
      stopped = true
    }
  }, [device, resolution])

  const width = 600
  const height = 120
  const max = Math.max(1, ...(points ?? []).map((p) => p.rx + p.tx))
  const bar = points && points.length > 0 ? width / points.length : 0
  const total = (points ?? []).reduce((sum, p) => sum + p.rx + p.tx, 0)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-1">
        {(Object.keys(labels) as Resolution[]).map((r) => (
          <Button key={r} size="xs" variant={r === resolution ? 'secondary' : 'ghost'} onClick={() => setResolution(r)}>
            {labels[r]}
          </Button>
        ))}
        <span className="ml-auto text-xs text-muted-foreground">{points ? formatBytes(total) : '…'}</span>
      </div>
      {points && points.length === 0 ? (
        <p className="text-xs text-muted-foreground">Nothing used in this time yet.</p>
      ) : (
        <svg viewBox={`0 0 ${width} ${height}`} className="h-24 w-full" preserveAspectRatio="none" role="img"
          aria-label={`Usage over ${labels[resolution]}: ${formatBytes(total)}`}>
          {(points ?? []).map((p, i) => {
            const rx = (p.rx / max) * height
            const tx = (p.tx / max) * height
            return (
              <g key={p.at}>
                <rect x={i * bar} y={height - rx} width={Math.max(bar - 1, 1)} height={rx} className="fill-sky-500/80" />
                <rect x={i * bar} y={height - rx - tx} width={Math.max(bar - 1, 1)} height={tx} className="fill-emerald-500/80" />
              </g>
            )
          })}
        </svg>
      )}
      <p className="text-xs text-muted-foreground">
        <span className="text-sky-600 dark:text-sky-400">■</span> to the device ·{' '}
        <span className="text-emerald-600 dark:text-emerald-400">■</span> from the device
      </p>
    </div>
  )
}
