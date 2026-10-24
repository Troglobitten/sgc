import { useEffect, useState } from 'react'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { api } from '@/lib/api'
import { guideSteps, stepsDone, type GuideState, type GuideStep } from '@/lib/guide'
import { StepList } from '@/pages/guide'

/**
 * On the dashboard while the guided setup is not through: what is done and
 * what is left, and the way back into it. Gone once hidden or once every
 * step is done.
 */
export function GuideChecklist({ onContinue }: { onContinue: () => void }) {
  const [state, setState] = useState<GuideState | null>(null)
  const [done, setDone] = useState<Record<GuideStep, boolean> | null>(null)

  useEffect(() => {
    let stopped = false
    api.guide().then(
      (next) => {
        if (stopped) return
        setState(next)
        if (next.active) stepsDone().then((d) => !stopped && setDone(d))
      },
      () => {}, // the dashboard reports problems itself
    )
    return () => {
      stopped = true
    }
  }, [])

  if (!state?.active || !done) return null
  const left = guideSteps.filter((s) => !done[s.key]).length
  if (left === 0) return null

  async function hide() {
    try {
      setState(await api.saveGuide({ active: false, skipped: state!.skipped }))
    } catch {
      // stays as it is; the next visit shows it again
    }
  }

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <h2 className="text-sm text-muted-foreground">Getting started</h2>
        <p className="text-sm">
          {left === 1 ? 'One step is' : `${left} steps are`} left of setting SGC up.
        </p>
        <StepList state={state} done={done} />
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={onContinue}>
            Continue the setup
          </Button>
          <Button size="sm" variant="ghost" onClick={hide}>
            Hide this list
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
