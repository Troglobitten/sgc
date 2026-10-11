// Turning raw numbers into what a person reads at a glance.

const gigabyte = 1024 ** 3

/** 3.7 GB, 58 GB: one decimal below ten, none above. */
export function formatGigabytes(bytes: number): string {
  const value = bytes / gigabyte
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} GB`
}

export function percentOf(part: number, whole: number): number {
  return whole > 0 ? Math.round((100 * part) / whole) : 0
}

/** "3 d 4 h", "5 h 12 min", "8 min": the two largest units. */
export function formatDuration(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) return `${days} d ${hours % 24} h`
  if (hours > 0) return `${hours} h ${minutes % 60} min`
  return `${minutes} min`
}

/** "just now", "5 min ago", "3 h ago", then the date. */
export function formatTimeAgo(iso: string, now: Date = new Date()): string {
  const then = new Date(iso)
  const seconds = Math.max(0, Math.floor((now.getTime() - then.getTime()) / 1000))
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  return then.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}
