import { useCallback, useEffect, useState } from 'react'

/**
 * Loads something now and again every `interval` milliseconds while the
 * component is shown. `load` and `onError` must be stable (an api function,
 * a useCallback). Returns the value, a way to replace it with a fresher one
 * (an answer to a change), and a way to load it again at once.
 */
export function usePolled<T>(
  load: () => Promise<T>,
  interval: number,
  onError: (error: unknown) => void,
): [T | null, (next: T) => void, () => void] {
  const [value, setValue] = useState<T | null>(null)
  const [round, setRound] = useState(0)
  useEffect(() => {
    let stopped = false
    const run = () =>
      load().then(
        (next) => !stopped && setValue(next),
        (error) => !stopped && onError(error),
      )
    run()
    const timer = setInterval(run, interval)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [load, interval, onError, round])
  const refresh = useCallback(() => setRound((r) => r + 1), [])
  return [value, setValue, refresh]
}
