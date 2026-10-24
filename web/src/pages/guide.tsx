import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { ArrowLeft, ArrowRight, CircleCheck, CircleDashed, CircleSlash } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { CertificateCard } from '@/components/certificate-card'
import { DomainCard } from '@/components/domain-card'
import { FirewallCard } from '@/components/firewall-card'
import { NamesCard } from '@/components/names-card'
import { OsUpdatesCard } from '@/components/os-updates-card'
import { ProxyCard } from '@/components/proxy-card'
import { SshCard } from '@/components/ssh-card'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { ApiError, api, errorMessage } from '@/lib/api'
import { guideSteps, stepsDone, type GuideState, type GuideStep } from '@/lib/guide'

/**
 * The guided setup (docs/design.md §11): one step at a time, in the order
 * that works, each with the card that does it. A step can be skipped; "Next"
 * waits until the part says it is done. Leaving keeps the guide, and the
 * dashboard shows what is left.
 */
export function GuidePage({ shell, onClose }: { shell: ShellProps; onClose: () => void }) {
  const [state, setState] = useState<GuideState | null>(null)
  const [done, setDone] = useState<Record<GuideStep, boolean> | null>(null)
  // The step the owner chose; until then, the first one neither done nor
  // skipped (worked out while drawing, see below).
  const [chosen, setIndex] = useState<number | null>(null)
  const [problem, setProblem] = useState<string | null>(null)

  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )

  // The guide's state once; whether steps are done every few seconds, so
  // that "Next" follows what the card did.
  useEffect(() => {
    api.guide().then((next) => {
      if (!next.active) onClose()
      else setState(next)
    }, handleError)
  }, [handleError, onClose])
  useEffect(() => {
    let stopped = false
    const look = () => stepsDone().then((next) => !stopped && setDone(next))
    look()
    const timer = setInterval(look, 4_000)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [])

  if (!state || !done) {
    return (
      <AppShell page="dashboard" {...shell}>
        <p className="text-sm text-muted-foreground">…</p>
      </AppShell>
    )
  }

  const firstOpen = guideSteps.findIndex((s) => !done[s.key] && !state.skipped.includes(s.key))
  const index = chosen ?? (firstOpen === -1 ? guideSteps.length : firstOpen)

  async function save(next: GuideState) {
    try {
      setState(await api.saveGuide(next))
    } catch (e) {
      handleError(e)
    }
  }
  const skip = (step: GuideStep) => {
    if (!state.skipped.includes(step)) save({ ...state, skipped: [...state.skipped, step] })
    setIndex(index + 1)
  }
  const next = (step: GuideStep) => {
    // Done now: no longer "skipped", if it was.
    if (state.skipped.includes(step)) save({ ...state, skipped: state.skipped.filter((s) => s !== step) })
    setIndex(index + 1)
  }
  // The guide stays (as the dashboard's list) while steps are left.
  const finish = async () => {
    await save({ active: guideSteps.some((s) => !done[s.key]), skipped: state.skipped })
    onClose()
  }

  return (
    <AppShell page="dashboard" {...shell}>
      <div className="mx-auto flex w-full max-w-2xl flex-col gap-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="text-lg font-semibold">Setting up SGC</h1>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Leave the setup for now
          </Button>
        </div>
        <StepList state={state} done={done} current={index} onSelect={setIndex} />
        {problem && (
          <p role="alert" className="text-sm text-destructive">
            {problem}
          </p>
        )}
        {index < guideSteps.length ? (
          <StepView
            key={guideSteps[index].key}
            number={index + 1}
            step={guideSteps[index]}
            isDone={done[guideSteps[index].key]}
            onBack={index > 0 ? () => setIndex(index - 1) : undefined}
            onSkip={() => skip(guideSteps[index].key)}
            onNext={() => next(guideSteps[index].key)}
            last={index === guideSteps.length - 1}
          >
            <StepCard step={guideSteps[index].key} onError={handleError} />
          </StepView>
        ) : (
          <Finished done={done} onBack={() => setIndex(guideSteps.length - 1)} onFinish={finish}
            onNavigate={shell.onNavigate} />
        )}
      </div>
    </AppShell>
  )
}

function StepCard({ step, onError }: { step: GuideStep; onError: (e: unknown) => void }) {
  switch (step) {
    case 'domain':
      return <DomainCard onError={onError} />
    case 'certificate':
      return <CertificateCard onError={onError} />
    case 'name':
      return <NamesCard onError={onError} />
    case 'proxy':
      return <ProxyCard onError={onError} />
    case 'ssh':
      return <SshCard onError={onError} />
    case 'updates':
      return <OsUpdatesCard onError={onError} />
    case 'firewall':
      return <FirewallCard onError={onError} />
  }
}

/** The steps as a short list: where the owner is, and what is done. */
export function StepList({
  state,
  done,
  current,
  onSelect,
}: {
  state: GuideState
  done: Record<GuideStep, boolean>
  current?: number
  onSelect?: (index: number) => void
}) {
  return (
    <ol className="flex flex-col gap-1 text-sm">
      {guideSteps.map((s, i) => {
        const mark = done[s.key] ? 'done' : state.skipped.includes(s.key) ? 'skipped' : 'to do'
        const Icon = mark === 'done' ? CircleCheck : mark === 'skipped' ? CircleSlash : CircleDashed
        return (
          <li key={s.key}>
            <button
              type="button"
              disabled={!onSelect}
              onClick={() => onSelect?.(i)}
              className={
                'flex w-full items-center gap-2 rounded-md px-2 py-1 text-left disabled:cursor-default ' +
                (i === current ? 'bg-muted font-medium' : 'hover:bg-muted/50')
              }
              aria-current={i === current ? 'step' : undefined}
            >
              <Icon
                aria-hidden="true"
                className={
                  'size-4 shrink-0 ' +
                  (mark === 'done' ? 'text-emerald-700 dark:text-emerald-400' : 'text-muted-foreground')
                }
              />
              <span className="flex-1">
                {i + 1}. {s.title}
              </span>
              <span className="text-xs text-muted-foreground">{mark}</span>
            </button>
          </li>
        )
      })}
    </ol>
  )
}

function StepView({
  number,
  step,
  isDone,
  onBack,
  onSkip,
  onNext,
  last,
  children,
}: {
  number: number
  step: (typeof guideSteps)[number]
  isDone: boolean
  onBack?: () => void
  onSkip: () => void
  onNext: () => void
  last: boolean
  children: ReactNode
}) {
  return (
    <section className="flex flex-col gap-3" aria-label={step.title}>
      <div>
        <h2 className="font-medium">
          Step {number} of {guideSteps.length}: {step.title}
        </h2>
        <p className="text-sm text-muted-foreground">{step.why}</p>
      </div>
      {children}
      <div className="flex flex-wrap items-center gap-2">
        {onBack && (
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft />
            Back
          </Button>
        )}
        <span className="flex-1" />
        {!isDone && (
          <Button variant="outline" onClick={onSkip}>
            Skip this step
          </Button>
        )}
        <Button onClick={onNext} disabled={!isDone}>
          {last ? 'Finish' : 'Next'}
          <ArrowRight />
        </Button>
      </div>
      {!isDone && (
        <p className="text-xs text-muted-foreground">
          "{last ? 'Finish' : 'Next'}" can be pressed once this step is done. You can also skip it and come back later.
        </p>
      )}
    </section>
  )
}

function Finished({
  done,
  onBack,
  onFinish,
  onNavigate,
}: {
  done: Record<GuideStep, boolean>
  onBack: () => void
  onFinish: () => void
  onNavigate: ShellProps['onNavigate']
}) {
  const left = guideSteps.filter((s) => !done[s.key])
  return (
    <Card>
      <CardContent className="flex flex-col gap-3 text-sm">
        <h2 className="font-medium">{left.length === 0 ? 'SGC is set up' : 'The setup is through'}</h2>
        {left.length > 0 && (
          <p>
            Not done yet: {left.map((s) => s.title.toLowerCase()).join(', ')}. The dashboard keeps a list of
            it until you hide it.
          </p>
        )}
        <p>When you need them, later:</p>
        <ul className="ml-4 list-disc">
          <li>
            <button type="button" className="underline-offset-4 hover:underline" onClick={() => onNavigate('people')}>
              The VPN and people
            </button>
            : phones and laptops from anywhere, guests with an end date.
          </li>
          <li>
            <button type="button" className="underline-offset-4 hover:underline" onClick={() => onNavigate('services')}>
              Services
            </button>
            : add your devices, or let servers announce theirs.
          </li>
          <li>
            <button type="button" className="underline-offset-4 hover:underline" onClick={() => onNavigate('system')}>
              Backups, notifications and logs in memory
            </button>{' '}
            on the System page (logs in memory spare an SD card).
          </li>
        </ul>
        <div className="flex flex-wrap gap-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft />
            Back
          </Button>
          <span className="flex-1" />
          <Button onClick={onFinish}>Go to the dashboard</Button>
        </div>
      </CardContent>
    </Card>
  )
}
