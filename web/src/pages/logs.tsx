import { useCallback, useEffect, useRef, useState } from 'react'
import { TriangleAlert } from 'lucide-react'

import { AppShell, type ShellProps } from '@/components/app-shell'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  api,
  ApiError,
  errorMessage,
  type AuditEntry,
  type LogAnswer,
  type LogQuery,
  type Notification,
} from '@/lib/api'
import { formatTimeAgo } from '@/lib/format'

type Tab = 'notifications' | 'logs' | 'history'

const parts: { key: string; label: string }[] = [
  { key: 'sgc', label: 'SGC' },
  { key: 'helper', label: 'SGC’s root side and its jobs' },
  { key: 'dns', label: 'DNS (AdGuard Home)' },
  { key: 'proxy', label: 'Proxy (Traefik), with its requests' },
  { key: 'vpn', label: 'VPN (WireGuard)' },
  { key: 'firewall', label: 'Firewall' },
  { key: 'ssh', label: 'SSH' },
  { key: 'updates', label: 'Debian’s updates' },
]

const levels = [
  { value: 3, label: 'Errors' },
  { value: 4, label: 'Warnings and worse' },
  { value: 6, label: 'Everything usual' },
  { value: 7, label: 'Everything, with details' },
]

const spans = [
  { value: 3600, label: 'Last hour' },
  { value: 86400, label: 'Last day' },
  { value: 7 * 86400, label: 'Last week' },
  { value: 31 * 86400, label: 'Last month' },
]

const selectClass = 'h-8 rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

/** What SGC told the owner, what its parts logged, and the history of changes. */
export function LogsPage({ shell }: { shell: ShellProps }) {
  const [tab, setTab] = useState<Tab>('notifications')
  const [problem, setProblem] = useState<string | null>(null)
  const { onSignedOut } = shell
  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) onSignedOut()
      else setProblem(errorMessage(error))
    },
    [onSignedOut],
  )
  return (
    <AppShell page="logs" {...shell}>
      {problem && (
        <p role="alert" className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
          {problem}
        </p>
      )}
      <div className="flex gap-1" role="tablist">
        {(['notifications', 'logs', 'history'] as Tab[]).map((t) => (
          <Button key={t} size="sm" role="tab" aria-selected={tab === t} variant={tab === t ? 'secondary' : 'ghost'} onClick={() => setTab(t)}>
            {t === 'notifications' ? 'Notifications' : t === 'logs' ? 'Logs' : 'History'}
          </Button>
        ))}
      </div>
      {tab === 'notifications' && <Notifications onError={handleError} />}
      {tab === 'logs' && <Journal onError={handleError} />}
      {tab === 'history' && <History onError={handleError} />}
    </AppShell>
  )
}

function Notifications({ onError }: { onError: (e: unknown) => void }) {
  const [list, setList] = useState<Notification[] | null>(null)
  useEffect(() => {
    let stopped = false
    api.notifications(200).then(
      (l) => {
        if (stopped) return
        setList(l)
        // Seen now: the bell goes quiet.
        if (l.some((n) => !n.read)) api.markNotificationsRead().catch(() => {})
      },
      (e) => !stopped && onError(e),
    )
    return () => {
      stopped = true
    }
  }, [onError])
  if (!list) return <p className="text-sm text-muted-foreground">…</p>
  if (list.length === 0) return <p className="text-sm text-muted-foreground">Nothing to tell yet.</p>
  return (
    <Card>
      <CardContent className="flex flex-col divide-y">
        {list.map((n) => (
          <div key={n.id} className="flex flex-col gap-0.5 py-2">
            <span className="flex flex-wrap items-baseline gap-2 text-sm">
              <span
                className={
                  n.severity === 'problem'
                    ? 'font-medium text-destructive'
                    : n.severity === 'warning'
                      ? 'font-medium text-amber-700 dark:text-amber-400'
                      : 'font-medium'
                }
              >
                {n.title}
              </span>
              {!n.read && <span className="text-xs text-sky-600 dark:text-sky-400">new</span>}
              {n.ongoing && !n.resolvedAt && <span className="text-xs text-muted-foreground">still so</span>}
              {n.resolvedAt && <span className="text-xs text-muted-foreground">over {formatTimeAgo(n.resolvedAt)}</span>}
              <span className="ml-auto text-xs text-muted-foreground">{formatTimeAgo(n.at)}</span>
            </span>
            {n.body && <span className="text-sm text-muted-foreground">{n.body}</span>}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function Journal({ onError }: { onError: (e: unknown) => void }) {
  const [query, setQuery] = useState<LogQuery>({ part: 'sgc', priority: 6, sinceSeconds: 86400, text: '', limit: 300, after: '' })
  const [text, setText] = useState('')
  const [answer, setAnswer] = useState<LogAnswer | null>(null)
  const [live, setLive] = useState(false)
  const cursor = useRef('')

  useEffect(() => {
    let stopped = false
    api.logs({ ...query, after: '' }).then(
      (a) => {
        if (stopped) return
        cursor.current = a.cursor
        setAnswer(a)
      },
      (e) => !stopped && onError(e),
    )
    return () => {
      stopped = true
    }
  }, [query, onError])

  // Live: what was added since, every few seconds.
  useEffect(() => {
    if (!live) return
    const timer = setInterval(() => {
      if (!cursor.current) return
      api.logs({ ...query, after: cursor.current }).then((a) => {
        if (a.cursor) cursor.current = a.cursor
        if (a.entries.length > 0) {
          setAnswer((current) => ({ cursor: a.cursor, entries: [...(current?.entries ?? []), ...a.entries].slice(-1000) }))
        }
      }, () => {})
    }, 3000)
    return () => clearInterval(timer)
  }, [live, query])

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <select className={selectClass} value={query.part} onChange={(e) => setQuery({ ...query, part: e.target.value })} aria-label="Part">
            {parts.map((p) => (
              <option key={p.key} value={p.key}>{p.label}</option>
            ))}
          </select>
          <select className={selectClass} value={query.priority} onChange={(e) => setQuery({ ...query, priority: Number(e.target.value) })} aria-label="Level">
            {levels.map((l) => (
              <option key={l.value} value={l.value}>{l.label}</option>
            ))}
          </select>
          <select className={selectClass} value={query.sinceSeconds} onChange={(e) => setQuery({ ...query, sinceSeconds: Number(e.target.value) })} aria-label="Time">
            {spans.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); setQuery({ ...query, text: text.trim() }) }}>
            <Input placeholder="Text to look for" value={text} maxLength={100} className="w-48" onChange={(e) => setText(e.target.value)} />
            <Button type="submit" size="sm" variant="outline">Look</Button>
          </form>
          <label className="ml-auto flex items-center gap-2 text-sm">
            <Switch checked={live} onCheckedChange={setLive} size="sm" />
            Live
          </label>
        </div>
        {query.part === 'proxy' && (
          <p className="text-xs text-muted-foreground">
            The proxy logs one line per request. To see one service’s, look for its router’s name: http-name (for example http-nas).
          </p>
        )}
        {!answer ? (
          <p className="text-sm text-muted-foreground">…</p>
        ) : answer.entries.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing in this time.</p>
        ) : (
          <pre className="max-h-[70vh] overflow-auto rounded-md bg-muted/50 p-2 text-xs leading-5">
            {answer.entries.map((e, i) => (
              <div key={i} className={e.priority <= 3 ? 'text-destructive' : e.priority === 4 ? 'text-amber-700 dark:text-amber-400' : undefined}>
                {new Date(e.at).toLocaleString()} {e.unit.replace(/\.service$/, '')}: {e.message}
              </div>
            ))}
          </pre>
        )}
      </CardContent>
    </Card>
  )
}

function History({ onError }: { onError: (e: unknown) => void }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  useEffect(() => {
    let stopped = false
    api.audit(500).then((e) => !stopped && setEntries(e), (e) => !stopped && onError(e))
    return () => {
      stopped = true
    }
  }, [onError])
  if (!entries) return <p className="text-sm text-muted-foreground">…</p>
  return (
    <Card>
      <CardContent className="flex flex-col divide-y">
        {entries.map((e) => (
          <div key={e.id} className="flex flex-wrap items-baseline gap-x-2 py-1.5 text-sm">
            <span className="text-xs text-muted-foreground">{new Date(e.at).toLocaleString()}</span>
            <span className="font-medium">{e.actor}</span>
            <span className="text-muted-foreground">{e.action}</span>
            <span className="min-w-0 break-words">{e.detail}</span>
            {e.remoteAddr && <span className="ml-auto text-xs text-muted-foreground">{e.remoteAddr}</span>}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
