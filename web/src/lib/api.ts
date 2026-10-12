// The browser side of SGC's JSON API (see internal/web/server.go).

export interface State {
  version: string
  setupRequired: boolean
  signedIn: boolean
  username?: string
  minPasswordLength: number
  minPassphraseLength: number
}

/** What an export file says about itself (internal/backup). */
export interface ExportManifest {
  formatVersion: number
  sgcVersion: string
  schemaVersion: number
  createdAt: string
  hostname: string
  adminUsername: string
}

export interface Health {
  cpuPercent: number
  memoryTotalBytes: number
  memoryUsedBytes: number
  diskTotalBytes: number
  diskUsedBytes: number
  /** null when the machine has no temperature sensor */
  temperatureC: number | null
  uptimeSeconds: number
  hostname: string
  os: string
  kernel: string
  model: string
  bootMedium: 'sd-card' | 'disk' | 'unknown'
}

export interface AuditEntry {
  id: number
  at: string
  actor: string
  action: string
  detail: string
  remoteAddr: string
}

/** How the most recent update attempt ended (internal/updater). */
export interface UpdateOutcome {
  id: number
  state: 'running' | 'succeeded' | 'rolled-back' | 'failed'
  from: string
  to: string
  message: string
  startedAt: string
  finishedAt?: string
  /** false when the attempt was refused before anything was touched */
  changed: boolean
}

export interface UpdateStatus {
  current: string
  /** '' until a check has succeeded */
  latest: string
  updateAvailable: boolean
  notes: string
  publishedAt: string | null
  checkedAt: string | null
  /** why the most recent check failed, or '' */
  checkError: string
  checkFailedAt: string | null
  autoCheck: boolean
  lastUpdate: UpdateOutcome | null
}

/** The firewall as SGC reports it (internal/fwcontrol, internal/web/firewall.go). */
export interface FirewallStatus {
  /** 'pending': a change is in effect and waits for confirmation */
  state: 'off' | 'on' | 'pending'
  /** false on a clean Debian, until the firewall is first switched on */
  softwareInstalled: boolean
  /** what the owner last confirmed; true with state 'off' after a restore */
  wanted: boolean
  pending: { enabled: boolean; secondsLeft: number } | null
  /** what is let in from the home network while the firewall is on */
  sshPorts: number[]
  webPort: number
  /** how long a change waits for its confirmation */
  confirmSeconds: number
  /** this browser, as SGC sees it */
  client: { address: string; inside: boolean }
}

/** An error with a message that is fit to show to the user as it is. */
export class ApiError extends Error {
  /** HTTP status, or 0 when SGC could not be reached at all. */
  status: number
  /** SGC asks for the same request again over a new connection. */
  reconnect: boolean

  constructor(status: number, message: string, reconnect = false) {
    super(message)
    this.status = status
    this.reconnect = reconnect
  }
}

// Set at build time (vite.config.ts); 'dev' when running the dev server.
declare const __SGC_VERSION__: string

const reloadedForKey = 'sgc-reloaded-for'

/**
 * A page stays open for a long time; SGC may be updated underneath it, for
 * example over SSH. The old page would then keep running old code against a
 * newer SGC. Every answer from SGC names its version; when that differs from
 * the version this page was built for, the page reloads itself, once.
 */
function reloadIfOutdated(response: Response) {
  const running = response.headers.get('X-SGC-Version')
  if (!running || __SGC_VERSION__ === 'dev' || running === __SGC_VERSION__) return
  try {
    // Remembered so that a reload which does not help is not repeated forever.
    if (sessionStorage.getItem(reloadedForKey) === running) return
    sessionStorage.setItem(reloadedForKey, running)
  } catch {
    return // no way to remember: better an old page than an endless reload
  }
  window.location.reload()
}

/** Sends a request and returns the raw answer, or throws an ApiError. */
async function send(method: string, path: string, body?: unknown): Promise<Response> {
  // A form (file upload) is sent as it is; anything else as JSON.
  const isForm = body instanceof FormData
  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined || isForm ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, "Can't reach SGC. Check that the device is on, then try again.")
  }
  reloadIfOutdated(response)
  if (!response.ok) {
    const data: unknown = await response.json().catch(() => null)
    const message =
      data !== null && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
        ? data.error
        : `SGC answered with an error (${response.status}).`
    throw new ApiError(response.status, message, response.headers.has('X-SGC-Reconnect'))
  }
  return response
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await send(method, path, body)
  return (await response.json().catch(() => null)) as T
}

/** Asks for an export and returns the encrypted file with the name SGC gave it. */
async function downloadExport(password: string, passphrase: string) {
  const response = await send('POST', '/api/export', { password, passphrase })
  const name = /filename="?([^";]+)"?/.exec(response.headers.get('Content-Disposition') ?? '')
  return { file: await response.blob(), name: name?.[1] ?? 'sgc-export.age' }
}

/**
 * Confirms a firewall change. SGC accepts the confirmation only over a
 * connection that was opened after the change: a firewall lets existing
 * connections carry on, so only a new one shows that this browser still
 * gets in. SGC closes an older connection and says "again"; the next try
 * then has to connect afresh, through the new rules.
 */
async function confirmFirewall(): Promise<FirewallStatus> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await request<FirewallStatus>('POST', '/api/firewall/confirm', {})
    } catch (error) {
      // A browser keeps several connections; each try uses up one old one.
      if (!(error instanceof ApiError) || !error.reconnect || attempt >= 10) throw error
      await new Promise((resolve) => setTimeout(resolve, 200))
    }
  }
}

export const api = {
  state: () => request<State>('GET', '/api/state'),
  setup: (token: string, username: string, password: string) =>
    request<void>('POST', '/api/setup', { token, username, password }),
  login: (username: string, password: string) =>
    request<void>('POST', '/api/login', { username, password }),
  logout: () => request<void>('POST', '/api/logout', {}),
  health: () => request<Health>('GET', '/api/health'),
  audit: () => request<AuditEntry[]>('GET', '/api/audit'),
  restartDevice: () => request<void>('POST', '/api/device/restart', { confirm: true }),
  update: () => request<UpdateStatus>('GET', '/api/update'),
  checkForUpdate: () => request<UpdateStatus>('POST', '/api/update/check', {}),
  setAutoCheck: (autoCheck: boolean) =>
    request<UpdateStatus>('POST', '/api/update/settings', { autoCheck }),
  installUpdate: (version: string) =>
    request<void>('POST', '/api/update/install', { version, confirm: true }),
  downloadExport,
  restorePreview: (token: string, passphrase: string, file: File) => {
    // The order matters: SGC checks the setup link before it reads the file.
    const form = new FormData()
    form.append('token', token)
    form.append('passphrase', passphrase)
    form.append('file', file)
    return request<ExportManifest>('POST', '/api/setup/restore/preview', form)
  },
  restoreConfirm: (token: string) =>
    request<void>('POST', '/api/setup/restore/confirm', { token }),
  firewall: () => request<FirewallStatus>('GET', '/api/firewall'),
  changeFirewall: (enabled: boolean) =>
    request<FirewallStatus>('POST', '/api/firewall/change', { enabled }),
  confirmFirewall,
  undoFirewall: () => request<FirewallStatus>('POST', '/api/firewall/undo', {}),
}

/** The message to show for any thrown value. */
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : 'Something unexpected went wrong. Try again.'
}
