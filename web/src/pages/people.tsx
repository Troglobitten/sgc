import { useCallback, useEffect, useState } from 'react'
import { TriangleAlert } from 'lucide-react'

import { PageTitle, SettingCard } from '@/components/setting'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { PeopleManager } from '@/components/people-manager'
import { UsageChart } from '@/components/usage-chart'
import { VpnCard } from '@/components/vpn-card'
import { api, ApiError, errorMessage, type Person, type Service, type VpnStatus } from '@/lib/api'

/** People, their devices in the VPN, and the VPN itself. */
export function PeoplePage({ shell }: { shell: ShellProps }) {
  const [problem, setProblem] = useState<string | null>(null)
  const [vpn, setVpn] = useState<VpnStatus | null>(null)
  const [people, setPeople] = useState<Person[] | null>(null)
  const [services, setServices] = useState<Service[]>([])
  const [lanAddress, setLanAddress] = useState('')
  const [round, setRound] = useState(0)
  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )
  const refresh = useCallback(() => setRound((r) => r + 1), [])

  useEffect(() => {
    let stopped = false
    const load = () => {
      api.vpn().then((v) => !stopped && setVpn(v), (e) => !stopped && handleError(e))
      api.people().then((p) => !stopped && setPeople(p), (e) => !stopped && handleError(e))
      api.services().then((s) => !stopped && setServices(s.services), (e) => !stopped && handleError(e))
      api.names().then((n) => !stopped && setLanAddress(n.lan?.address ?? ''), () => {})
    }
    load()
    const timer = setInterval(load, 15_000)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [handleError, round])

  return (
    <AppShell page="people" {...shell}>
      <PageTitle title="People" lead="Who may come in through the VPN, with which devices, and what they reach." />
      {problem && (
        <p role="alert" className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {problem}
        </p>
      )}
      {vpn && <VpnCard status={vpn} lanAddress={lanAddress} onChanged={setVpn} />}
      {vpn && people && <PeopleManager people={people} services={services} vpn={vpn} onChanged={refresh} />}
      {vpn?.enabled && vpn.devices.length > 0 && (
        <SettingCard title="What all devices used">
          <UsageChart device={0} />
        </SettingCard>
      )}
    </AppShell>
  )
}
