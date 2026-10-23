import { useCallback, useState } from 'react'
import { TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { ProxyCard } from '@/components/proxy-card'
import { ServicesManager } from '@/components/services-manager'
import { TokensCard } from '@/components/tokens-card'
import { api, ApiError, errorMessage } from '@/lib/api'
import { usePolled } from '@/lib/poll'

/** The services behind SGC's names, the proxy that opens them, and the servers that announce them. */
export function ServicesPage({ shell }: { shell: ShellProps }) {
  const [problem, setProblem] = useState<string | null>(null)
  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )
  const [names] = usePolled(api.names, 60_000, handleError)

  return (
    <AppShell page="services" {...shell}>
      {problem && (
        <p
          role="alert"
          className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {problem}
        </p>
      )}
      <ProxyCard onError={handleError} />
      <ServicesManager onError={handleError} />
      <TokensCard gatewayHost={names?.fqdn ?? ''} onError={handleError} />
    </AppShell>
  )
}
