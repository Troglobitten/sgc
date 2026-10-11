// The browser side of SGC's JSON API (see internal/web/server.go).

export interface State {
  version: string
  setupRequired: boolean
  signedIn: boolean
  username?: string
  minPasswordLength: number
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

/** An error with a message that is fit to show to the user as it is. */
export class ApiError extends Error {
  /** HTTP status, or 0 when SGC could not be reached at all. */
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, "Can't reach SGC. Check that the device is on, then try again.")
  }

  const data: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const message =
      data !== null && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
        ? data.error
        : `SGC answered with an error (${response.status}).`
    throw new ApiError(response.status, message)
  }
  return data as T
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
}

/** The message to show for any thrown value. */
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : 'Something unexpected went wrong. Try again.'
}
