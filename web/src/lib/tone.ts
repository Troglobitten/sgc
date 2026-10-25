// The colours a state is shown in: good, needs a look, broken, or just so.

export type Tone = 'ok' | 'warn' | 'bad' | 'muted'

export const toneText: Record<Tone, string> = {
  ok: 'text-emerald-700 dark:text-emerald-400',
  warn: 'text-amber-700 dark:text-amber-400',
  bad: 'text-red-700 dark:text-red-400',
  muted: 'text-muted-foreground',
}

export const toneDot: Record<Tone, string> = {
  ok: 'bg-emerald-600 dark:bg-emerald-400',
  warn: 'bg-amber-600 dark:bg-amber-400',
  bad: 'bg-red-600 dark:bg-red-400',
  muted: 'bg-muted-foreground/60',
}

export function toneClass(tone: Tone): string {
  return toneText[tone]
}
