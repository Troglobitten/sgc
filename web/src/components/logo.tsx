import { cn } from '@/lib/utils'

// SGC's mark: a ring with nine chevrons, the top one lit. An original drawing
// that nods to the name; it copies no existing artwork.
const chevronAngles = [40, 80, 120, 160, 200, 240, 280, 320]

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={cn('size-10', className)} aria-hidden="true">
      <circle cx="24" cy="24" r="19" className="fill-none stroke-foreground" strokeWidth="3" />
      <circle cx="24" cy="24" r="13" className="fill-none stroke-muted-foreground/50" strokeWidth="1" />
      <path d="M24 1 l4.5 7 h-9 z" className="fill-gate" />
      {chevronAngles.map((angle) => (
        <path
          key={angle}
          d="M24 1 l4.5 7 h-9 z"
          className="fill-foreground"
          transform={`rotate(${angle} 24 24)`}
        />
      ))}
    </svg>
  )
}
