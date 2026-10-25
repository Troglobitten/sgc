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

/** Whole days from now until a moment; negative once it has passed. */
export function daysUntil(iso: string, now: Date = new Date()): number {
  return Math.floor((new Date(iso).getTime() - now.getTime()) / (24 * 60 * 60 * 1000))
}

// One way of writing dates everywhere. The page is in English, so its dates
// are too, whatever language the browser is set to ("9 August 2028", not
// "09/08/2028" here and "Aug 9" there).
const dateLocale = 'en-GB'

/** "9 August 2028". */
export function formatDate(iso: string | Date): string {
  return new Date(iso).toLocaleDateString(dateLocale, { day: 'numeric', month: 'long', year: 'numeric' })
}

/** "26 October, 22:19". */
export function formatDateTime(iso: string | Date): string {
  const d = new Date(iso)
  return `${d.toLocaleDateString(dateLocale, { day: 'numeric', month: 'long' })}, ${d.toLocaleTimeString(dateLocale, { hour: '2-digit', minute: '2-digit' })}`
}

/** "26 Oct 2026, 22:19:05", for log lines. */
export function formatLogTime(iso: string | Date): string {
  const d = new Date(iso)
  return `${d.toLocaleDateString(dateLocale, { day: 'numeric', month: 'short', year: 'numeric' })}, ${d.toLocaleTimeString(dateLocale)}`
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
  return formatDate(then)
}

/** "1.2 GB", "340 MB", "12 kB". */
export function formatBytes(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit++
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}
