import { useCallback, useState } from 'react'
import { TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { ProxyCard } from '@/components/proxy-card'
import { ServicesManager, ServicesSettingsCard } from '@/components/services-manager'
import { PageTitle, StatusDot } from '@/components/setting'
import { TokensCard } from '@/components/tokens-card'
import { api, ApiError, errorMessage, type ProxyStatus } from '@/lib/api'
import { usePolled } from '@/lib/poll'
import { cn } from '@/lib/utils'

type Tab = 'services' | 'announce' | 'settings'
const tabKey = 'sgc-services-tab'

function readTab(): Tab {
  try {
    const stored = sessionStorage.getItem(tabKey)
    return stored === 'announce' || stored === 'settings' ? stored : 'services'
  } catch {
    return 'services'
  }
}

/**
 * The services behind SGC's names (the list), the servers that announce
 * them, and how they are handled (the proxy, icons, approval): a tab each,
 * so that the list is not buried.
 */
export function ServicesPage({ shell }: { shell: ShellProps }) {
  const [problem, setProblem] = useState<string | null>(null)
  const [tab, setTabState] = useState<Tab>(readTab)
  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )
  const quiet = useCallback(() => {}, [])
  const [data, setData, refresh] = usePolled(api.services, 15_000, handleError)
  const [names] = usePolled(api.names, 60_000, handleError)
  const [proxy] = usePolled(api.proxy, 15_000, quiet)
  const [people] = usePolled(api.people, 30_000, quiet)
  const [tokens] = usePolled(api.tokens, 60_000, quiet)
  const [internet] = usePolled(api.publicStatus, 30_000, quiet)

  function setTab(next: Tab) {
    setTabState(next)
    try {
      sessionStorage.setItem(tabKey, next)
    } catch {
      // Remembered for this view only.
    }
  }

  const pending = data?.services.filter((s) => s.pending).length ?? 0
  const count = data?.services.filter((s) => !s.pending).length ?? 0
  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'services', label: 'Services', count: pending > 0 ? pending : count },
    { key: 'announce', label: 'Servers that announce', count: tokens?.length },
    { key: 'settings', label: 'Settings' },
  ]

  return (
    <AppShell page="services" {...shell}>
      <PageTitle title="Services" lead={<ProxyLine status={proxy} onOpen={() => setTab('settings')} />} />
      {problem && (
        <p
          role="alert"
          className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {problem}
        </p>
      )}

      <div role="tablist" aria-label="Services" className="-mt-2 flex gap-1 overflow-x-auto border-b">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              '-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium outline-none focus-visible:ring-3 focus-visible:ring-ring/50',
              tab === t.key ? 'border-foreground text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
            {t.count !== undefined && t.count > 0 && (
              <span
                className={cn(
                  'rounded-full px-1.5 text-xs',
                  t.key === 'services' && pending > 0 ? 'bg-amber-500/15 text-amber-800 dark:text-amber-300' : 'bg-muted text-muted-foreground',
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {tab === 'services' &&
        (data ? (
          <ServicesManager data={data} people={people ?? []} internet={internet} refresh={refresh} onError={handleError} />
        ) : (
          <p className="text-sm text-muted-foreground">…</p>
        ))}
      {tab === 'announce' && <TokensCard gatewayHost={names?.fqdn ?? ''} onError={handleError} />}
      {tab === 'settings' && (
        <div className="flex max-w-3xl flex-col gap-4">
          <ProxyCard onError={handleError} />
          {data && <ServicesSettingsCard data={data} onSaved={setData} />}
        </div>
      )}
    </AppShell>
  )
}

/** The proxy in one line, under the page's title. */
function ProxyLine({ status, onOpen }: { status: ProxyStatus | null; onOpen: () => void }) {
  if (!status) return null
  const failing = status.lastApply && !status.lastApply.ok
  if (!status.wanted) {
    return (
      <span className="flex flex-wrap items-center gap-2">
        <StatusDot tone="muted" />
        The proxy is off, so services do not open by name yet.
        <button type="button" onClick={onOpen} className="font-medium text-foreground hover:underline">
          Settings
        </button>
      </span>
    )
  }
  if (!status.running || failing) {
    return (
      <span className="flex flex-wrap items-center gap-2 text-amber-700 dark:text-amber-400">
        <StatusDot tone="warn" />
        {status.running ? 'The proxy’s last change failed.' : 'The proxy is not running.'}
        <button type="button" onClick={onOpen} className="font-medium hover:underline">
          Settings
        </button>
      </span>
    )
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      <StatusDot tone="ok" />
      The proxy runs (Traefik {status.version}): your services open at https://name.your-domain.
    </span>
  )
}
