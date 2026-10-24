// The browser side of SGC's JSON API (see internal/web/server.go).

import {
  backupSettingsBody,
  backupTargetBody,
  logQueryBody,
  notificationChannelsBody,
  personBody,
  serviceBody,
  servicesSettingsBody,
  vpnSettingsBody,
} from '@/lib/bodies'

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
  /** DNS is let in from inside (once AdGuard Home is installed) */
  dns: boolean
  /** the proxy's ports are let in from inside, and these of proxied services */
  proxy: boolean
  proxyPorts: string[]
  /** the VPN's port, let in from anywhere; 0 if not */
  vpnPort: number
  /** what is switched on but not let in by the rules in effect, in words */
  behind: string[]
  webPort: number
  /** how long a change waits for its confirmation */
  confirmSeconds: number
  /** this browser, as SGC sees it */
  client: { address: string; inside: boolean }
}

/** One installation of device updates started in SGC's page (internal/osupdate). */
export interface OsUpdateInstall {
  id: number
  startedAt: string
  finishedAt: string
  /** what was waiting before and is not any more */
  packages: string[]
  result: 'ok' | 'failed'
  message?: string
}

/**
 * Updates for the device itself (Debian's packages, not SGC), as SGC reports
 * them (internal/oscontrol).
 */
export interface OsUpdatesStatus {
  /** false when the device could not be asked; the rest is then what is on file */
  available: boolean
  /** false on a device without Debian's update tool; it is installed on first choice */
  toolInstalled: boolean
  /** how SGC has set this device up; '' until the owner has chosen here */
  mode: '' | 'automatic' | 'by-hand'
  /** the owner's last choice, here or on the device an export came from */
  wanted: '' | 'automatic' | 'by-hand'
  /** updates install by themselves right now, whoever arranged that */
  daily: boolean
  /** why the device does not do what mode says, or '' */
  problem: string
  /** when Debian's update tool last ran */
  lastRun: string | null
  /** what SGC has the tool doing right now */
  running: '' | 'check' | 'install'
  /** Debian's own daily run is at work */
  dailyRunning: boolean
  /** null: not looked since the device started */
  checkedAt: string | null
  waiting: string[]
  checkError: string
  lastInstall: OsUpdateInstall | null
  /** an installed update takes effect only after a restart */
  restartNeeded: boolean
  restartPackages: string[]
}

/** AdGuard Home, as SGC reports it (internal/dnscontrol). */
export interface DnsStatus {
  /** false when the device could not be asked */
  available: boolean
  /** the program is on this device */
  installed: boolean
  /** switched on: what the switch shows */
  enabled: boolean
  version: string
  running: boolean
  /** the version this SGC installs */
  pinned: string
  updateAvailable: boolean
  /** restored from an export whose DNS part is not in place on this device yet */
  restorePending: boolean
}

/** The owner's domain and Zone.eu account, as SGC reports them (internal/domaincontrol). The API key is never in it. */
export interface DomainStatus {
  configured: boolean
  domain: string
  username: string
  /** when Zone.eu was last asked; null if not yet */
  checkedAt: string | null
  /** its answer, and what was wrong in words */
  ok: boolean
  problem: string
  failingSince: string | null
}

/** The certificate for the owner's domain, as SGC reports it (internal/certcontrol). No key is ever in it. */
export interface CertificateStatus {
  /** the domain that is set up, "" if none */
  domain: string
  /** why this SGC gets no certificates, "" if it does */
  disabled: string
  termsAgreed: boolean
  certificate: {
    names: string[]
    issuer: string
    notBefore: string
    notAfter: string
    serial: string
    obtainedAt: string
    /** it is for the domain that is set up now */
    forDomain: boolean
  } | null
  /** an attempt in progress: "trial" with the test authority first, then "real" */
  running: { kind: string; phase: string; since: string; log: string[] } | null
  lastAttempt: {
    kind: string
    startedAt: string
    finishedAt: string
    ok: boolean
    message: string
    log: string[]
  } | null
  /** when SGC means to renew by itself */
  renewsAt: string | null
  /** until then a request from the page is refused */
  waitUntil: string | null
}

/** Logs in memory (log2ram), as SGC reports it (internal/logcontrol). */
export interface Log2ramStatus {
  /** false when the device could not be asked */
  available: boolean
  installed: boolean
  /** switched on: what the switch shows; in effect from the next restart */
  enabled: boolean
  /** the logs are in memory right now */
  active: boolean
  /** switched and in effect differ until the device restarts */
  restartNeeded: boolean
  /** switched on, but at the last start-up the logs did not fit and stayed on the disk */
  startFailed: boolean
  /** in memory, and more than four fifths of the space used */
  nearlyFull: boolean
  /** on on the device an export came from, not switched on here */
  wanted: boolean
  /** the space in memory, and what the logs take */
  sizeBytes: number
  usedBytes: number
  /** what takes most in the log folder, largest first */
  largest: { name: string; bytes: number }[]
}

/** The maintenance window, as SGC reports it (internal/maintenance). */
export interface MaintenanceStatus {
  enabled: boolean
  /** "04:00", by the device's own clock */
  start: string
  end: string
  /** what the device's clock says now, and its time zone */
  deviceTime: string
  timeZone: string
  inWindow: boolean
  /** false: nothing happens in the window until the clock has been set */
  clockSynchronised: boolean
  restartNeeded: boolean
  /** when SGC last restarted the device by itself */
  lastRestart: string | null
  /** SGC's own updates install in the window */
  autoUpdate: boolean
  updateWaitDays: number
  /** a newer SGC this device knows of, and from when it may install by itself */
  updateVersion: string
  updateInstallableFrom: string | null
}

/** One SSH key added in SGC's page (internal/sshcontrol). */
export interface SshKey {
  id: number
  label: string
  /** "ED25519", "RSA", ... */
  kind: string
  fingerprint: string
  addedAt: string
  /** false after a restore, until the keys are installed on this device */
  installed: boolean
  /** the latest login with this key in the last quarter of an hour */
  lastLogin: string | null
}

/** SSH keys and "keys only", as SGC reports them (internal/sshcontrol). */
export interface SshStatus {
  /** false when the device could not be asked about its SSH server */
  available: boolean
  running: boolean
  /** the account the keys are for, and the accounts there are on the device */
  account: string
  accounts: string[]
  keys: SshKey[]
  needsInstall: boolean
  /** what the SSH server allows right now */
  passwordLogins: boolean
  rootLogin: 'no' | 'key' | 'yes' | ''
  /** SGC's switch as confirmed here; wanted: as last confirmed anywhere */
  keysOnly: boolean
  wanted: boolean
  loginsVisible: boolean
  /** the latest login with a key in the last quarter of an hour */
  recentLogin: {
    account: string
    /** the key's label, or '' for a key the account keeps for itself */
    key: string
    fingerprint: string
    at: string
  } | null
  /** a change that is in effect and waits for a login with a key */
  pending: { what: string; secondsLeft: number } | null
  proofSeconds: number
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

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
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

/** A name SGC keeps in AdGuard Home, and how it stands (internal/dnsnames). */
export interface DnsName {
  domain: string
  answer: string
  for: string
  inPlace: boolean
  conflict?: string
}

/** The gateway's own name and the names SGC hands out (internal/gateway). */
export interface NamesStatus {
  name: string
  domain: string
  fqdn: string
  /** without a port while the proxy is on */
  url: string
  /** with :8443: does not depend on the proxy */
  directUrl: string
  lan: { interface: string; address: string; network: string; gateway: string } | null
  lanProblem: string
  dns: { names: DnsName[]; problem: string; rewritesOff: boolean; syncedAt: string | null }
}

export type ServiceKind = 'http' | 'tcp' | 'udp'

/** What the owner sets for a service (internal/services). */
export interface ServiceInput {
  name: string
  title: string
  kind: ServiceKind
  mode: 'proxied' | 'direct'
  upstreamIp: string
  upstreamPort: number
  scheme: 'http' | 'https'
  verifyTls: boolean
  listenPort: number
  category: string
  protected: boolean
  enabled: boolean
}

export interface Service extends ServiceInput {
  id: number
  pending: boolean
  tokenId: number | null
  tokenLabel: string
  createdAt: string
  updatedAt: string
  announcedAt: string | null
  hasIcon: boolean
  health: {
    state: 'up' | 'down' | 'unknown'
    since: string
    checkedAt: string
    lastUpAt: string | null
    abandoned: boolean
  }
  /** how to open it, "" until a domain is set up */
  url: string
}

export interface ServicesSettings {
  approveNew: boolean
  iconCatalogue: boolean
  abandonedDays: number
}

/** The icon collection kept on the device (internal/iconpack). */
export interface IconsStatus {
  installed: boolean
  version: string
  count: number
  built: string | null
  size: number
  checkedAt: string | null
  problem: string
  updating: boolean
  source: string
}

export interface ServicesResponse {
  services: Service[]
  settings: ServicesSettings
  icons: IconsStatus | null
}

/** The proxy, Traefik (internal/proxycontrol). */
export interface ProxyStatus {
  installed: boolean
  version: string
  running: boolean
  wanted: boolean
  /** what is missing before it can be on, "" if nothing */
  notReady: string
  lastApply: { at: string; ok: boolean; message: string } | null
  listenPorts: string[]
  applying: boolean
  pinnedVersion: string
}

/** A server's token for announcing its services; never the token itself. */
export interface AnnounceToken {
  id: number
  label: string
  hint: string
  pinnedIp: string
  createdAt: string
  lastUsedAt: string | null
  services: string[]
}

/** A person the owner lets in (internal/people). */
export interface PersonInput {
  name: string
  network: 'full' | 'services'
  allServices: boolean
  serviceIds: number[]
  loginEnabled: boolean
  username: string
  /** empty keeps the password there is */
  password: string
  expiresAt: string | null
  disabled: boolean
}

export interface Person extends Omit<PersonInput, 'password'> {
  id: number
  hasPassword: boolean
  active: boolean
  createdAt: string
}

/** A device in the VPN; never its private key (internal/vpncontrol). */
export interface VpnDevice {
  id: number
  personId: number
  personName: string
  name: string
  address: string
  publicKey: string
  allTraffic: boolean
  enabled: boolean
  createdAt: string
  connected: boolean
  lastSeen: string | null
  endpoint: string
  rx: number
  tx: number
}

export interface VpnSettings {
  enabled: boolean
  port: number
  network: string
  name: string
  endpointMode: 'dynamic' | 'static'
  staticIp: string
}

export interface VpnEndpointState {
  publicIp: string
  checkedAt: string | null
  recordIp: string
  updatedAt: string | null
  problem: string
  foreign: boolean
}

export interface VpnStatus extends VpnSettings {
  installed: boolean
  running: boolean
  up: boolean
  problem: string
  serverKey: string
  endpoint: string
  lastApply: { at: string; ok: boolean; message: string } | null
  applying: boolean
  publicName: string
  publicState: VpnEndpointState | null
  devices: VpnDevice[]
  /** by device id: what it used in all */
  totals: Record<string, { rx: number; tx: number }>
}

export interface UsagePoint {
  at: string
  rx: number
  tx: number
}

/** One entry of the bell (internal/notify). */
export interface Notification {
  id: number
  at: string
  event: string
  severity: 'info' | 'warning' | 'problem'
  title: string
  body: string
  ongoing: boolean
  resolvedAt: string | null
  read: boolean
}

export interface NotificationSummary {
  unread: number
  banners: Notification[]
}

export interface NotificationChannels {
  email: {
    enabled: boolean
    host: string
    port: number
    security: 'starttls' | 'tls' | 'none'
    username: string
    password?: string
    from: string
    to: string
  }
  ntfy: { enabled: boolean; server: string; topic: string; token?: string }
  routes: Record<string, { email: boolean; ntfy: boolean }>
}

export interface NotificationSettings {
  channels: NotificationChannels
  hasPassword: boolean
  hasToken: boolean
  events: { key: string; label: string }[]
}

export interface LogQuery {
  part: string
  priority: number
  sinceSeconds: number
  text: string
  limit: number
  after: string
}

export interface LogAnswer {
  entries: { at: string; unit: string; priority: number; message: string }[]
  cursor: string
}

export interface BackupTarget {
  kind: 'smb' | 'sftp' | 'webdav'
  host: string
  port: number
  share: string
  path: string
  url: string
  username: string
  password?: string
  hostKey: string
  skipVerify: boolean
}

export interface BackupSettings {
  enabled: boolean
  target: BackupTarget
  time: string
  keep: number
  publicKey: string
  since: string
}

export interface BackupRun {
  at: string
  ok: boolean
  message: string
  file: string
  size: number
}

export interface BackupStatus {
  settings: BackupSettings
  hasPassword: boolean
  hasKey: boolean
  last: BackupRun | null
  lastSuccess: string | null
  overdue: boolean
  nextAt: string | null
}

export interface EolState {
  items: {
    product: string
    label: string
    cycle: string
    securityEnd: string | null
    end: string | null
    source: 'online' | 'table'
    warning: string
  }[]
  checkedAt: string | null
  problem: string
}

export const api = {
  state: () => request<State>('GET', '/api/state'),
  setup: (token: string, username: string, password: string) =>
    request<void>('POST', '/api/setup', { token, username, password }),
  login: (username: string, password: string) =>
    request<void>('POST', '/api/login', { username, password }),
  logout: () => request<void>('POST', '/api/logout', {}),
  health: () => request<Health>('GET', '/api/health'),
  audit: (limit = 20) => request<AuditEntry[]>('GET', `/api/audit?limit=${limit}`),
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
  /** again: make the rules afresh although the firewall is on (to let DNS in) */
  changeFirewall: (enabled: boolean, again = false) =>
    request<FirewallStatus>('POST', '/api/firewall/change', { enabled, again }),
  dns: () => request<DnsStatus>('GET', '/api/dns'),
  /** switching on installs AdGuard Home first where it is not on the device yet */
  setDnsEnabled: (enabled: boolean) =>
    request<DnsStatus>('POST', '/api/dns/enabled', { enabled }),
  /** replaces the installed AdGuard Home with the newer one this SGC brings */
  installDns: () => request<DnsStatus>('POST', '/api/dns/install', {}),
  finishDnsRestore: () => request<DnsStatus>('POST', '/api/dns/restore', {}),
  domain: () => request<DomainStatus>('GET', '/api/domain'),
  /** saved only if Zone.eu says that domain and account belong together */
  saveDomain: (domain: string, username: string, apiKey: string) =>
    request<DomainStatus>('POST', '/api/domain', { domain, username, apiKey }),
  checkDomain: () => request<DomainStatus>('POST', '/api/domain/check', {}),
  removeDomain: () => request<DomainStatus>('POST', '/api/domain/remove', { confirm: true }),
  certificate: () => request<CertificateStatus>('GET', '/api/certificate'),
  /** starts getting the first certificate, or a renewal; the state shows how it goes */
  requestCertificate: (agreeToTerms: boolean) =>
    request<CertificateStatus>('POST', '/api/certificate/request', { agreeToTerms }),
  log2ram: () => request<Log2ramStatus>('GET', '/api/log2ram'),
  /** in effect from the next restart; switching on installs log2ram first where it is missing */
  setLog2ramEnabled: (enabled: boolean) =>
    request<Log2ramStatus>('POST', '/api/log2ram/enabled', { enabled }),
  confirmFirewall,
  undoFirewall: () => request<FirewallStatus>('POST', '/api/firewall/undo', {}),
  ssh: () => request<SshStatus>('GET', '/api/ssh'),
  addSshKey: (password: string, label: string, key: string, account: string) =>
    request<SshStatus>('POST', '/api/ssh/keys', { password, label, key, account }),
  removeSshKey: (id: number) => request<SshStatus>('POST', '/api/ssh/keys/remove', { id }),
  installSshKeys: (password: string, account: string) =>
    request<SshStatus>('POST', '/api/ssh/keys/install', { password, account }),
  setSshKeysOnly: (enabled: boolean) =>
    request<SshStatus>('POST', '/api/ssh/keys-only', { enabled }),
  undoSsh: () => request<SshStatus>('POST', '/api/ssh/undo', {}),
  maintenance: () => request<MaintenanceStatus>('GET', '/api/maintenance'),
  setMaintenance: (enabled: boolean, start: string, end: string) =>
    request<MaintenanceStatus>('POST', '/api/maintenance', { enabled, start, end }),
  setAutoUpdate: (enabled: boolean) =>
    request<MaintenanceStatus>('POST', '/api/maintenance/auto-update', { enabled }),
  osUpdates: () => request<OsUpdatesStatus>('GET', '/api/os-updates'),
  setOsUpdatesMode: (automatic: boolean) =>
    request<OsUpdatesStatus>('POST', '/api/os-updates/mode', { automatic }),
  checkOsUpdates: () => request<OsUpdatesStatus>('POST', '/api/os-updates/check', {}),
  installOsUpdates: () => request<OsUpdatesStatus>('POST', '/api/os-updates/install', {}),
  names: () => request<NamesStatus>('GET', '/api/names'),
  setGatewayName: (name: string) => request<NamesStatus>('POST', '/api/names/gateway', { name }),
  services: () => request<ServicesResponse>('GET', '/api/services'),
  addService: (input: ServiceInput) => request<Service>('POST', '/api/services', serviceBody(input)),
  updateService: (id: number, input: ServiceInput) =>
    request<Service>('POST', `/api/services/${id}`, serviceBody(input)),
  removeService: (id: number) => request<void>('POST', `/api/services/${id}/remove`, {}),
  approveService: (id: number) => request<void>('POST', `/api/services/${id}/approve`, {}),
  refreshServiceIcon: (id: number) => request<void>('POST', `/api/services/${id}/icon`, {}),
  /** looks for a new icon pack now */
  updateIcons: () => request<ServicesResponse>('POST', '/api/icons/update', {}),
  setServicesSettings: (settings: ServicesSettings) =>
    request<ServicesResponse>('POST', '/api/services/settings', servicesSettingsBody(settings)),
  proxy: () => request<ProxyStatus>('GET', '/api/proxy'),
  /** switching on downloads and installs Traefik first where it is missing */
  setProxyEnabled: (enabled: boolean) =>
    request<ProxyStatus>('POST', '/api/proxy/enabled', { enabled }),
  tokens: () => request<AnnounceToken[]>('GET', '/api/tokens'),
  /** the secret is in this answer only */
  createToken: (label: string) =>
    request<{ token: AnnounceToken; secret: string }>('POST', '/api/tokens', { label }),
  /** keep: its services stay, as services of the page's own */
  removeToken: (id: number, keep: boolean) =>
    request<AnnounceToken[]>('POST', `/api/tokens/${id}/remove`, { keep }),
  repinToken: (id: number) => request<AnnounceToken[]>('POST', `/api/tokens/${id}/repin`, {}),
  people: () => request<Person[]>('GET', '/api/people'),
  addPerson: (input: PersonInput) => request<Person>('POST', '/api/people', personBody(input)),
  updatePerson: (id: number, input: PersonInput) =>
    request<Person>('POST', `/api/people/${id}`, personBody(input)),
  removePerson: (id: number) => request<void>('POST', `/api/people/${id}/remove`, {}),
  vpn: () => request<VpnStatus>('GET', '/api/vpn'),
  setVpnSettings: (settings: VpnSettings) =>
    request<VpnStatus>('POST', '/api/vpn/settings', vpnSettingsBody(settings)),
  addDevice: (personId: number, name: string, allTraffic: boolean) =>
    request<VpnDevice>('POST', '/api/vpn/devices', { personId, name, allTraffic, enabled: true }),
  updateDevice: (id: number, name: string, allTraffic: boolean, enabled: boolean) =>
    request<VpnDevice>('POST', `/api/vpn/devices/${id}`, { personId: 0, name, allTraffic, enabled }),
  removeDevice: (id: number) => request<void>('POST', `/api/vpn/devices/${id}/remove`, {}),
  /** the device's settings with its private key: asks for the admin's password */
  deviceConfig: (id: number, password: string) =>
    request<{ config: string; filename: string }>('POST', `/api/vpn/devices/${id}/config`, { password }),
  vpnUsage: (device: number, resolution: 'minute' | 'hour' | 'day') =>
    request<UsagePoint[]>('GET', `/api/vpn/usage?device=${device}&resolution=${resolution}`),
  checkVpnEndpoint: () => request<VpnEndpointState>('POST', '/api/vpn/endpoint/check', {}),
  takeOverVpnRecord: () => request<VpnEndpointState>('POST', '/api/vpn/endpoint/take-over', {}),
  notifications: (limit = 100) => request<Notification[]>('GET', `/api/notifications?limit=${limit}`),
  notificationSummary: () => request<NotificationSummary>('GET', '/api/notifications/summary'),
  markNotificationsRead: () => request<NotificationSummary>('POST', '/api/notifications/read', {}),
  notificationSettings: () => request<NotificationSettings>('GET', '/api/notifications/settings'),
  /** an empty password or token keeps the one SGC has */
  saveNotificationSettings: (channels: NotificationChannels) =>
    request<NotificationSettings>('POST', '/api/notifications/settings', notificationChannelsBody(channels)),
  testNotification: (channel: 'email' | 'ntfy') => request<void>('POST', '/api/notifications/test', { channel }),
  logs: (query: LogQuery) => request<LogAnswer>('POST', '/api/logs', logQueryBody(query)),
  backups: () => request<BackupStatus>('GET', '/api/backups'),
  /** an empty password keeps the one SGC has */
  saveBackups: (settings: BackupSettings) =>
    request<BackupStatus>('POST', '/api/backups/settings', backupSettingsBody(settings)),
  /** the secret half is in this answer only */
  makeBackupKey: (password: string) => request<{ secret: string }>('POST', '/api/backups/key', { password }),
  testBackupTarget: (target: BackupTarget) =>
    request<{ ok: boolean; hostKey?: string; message?: string }>('POST', '/api/backups/test', backupTargetBody(target)),
  backUpNow: () => request<BackupRun>('POST', '/api/backups/run', {}),
  eol: () => request<EolState>('GET', '/api/eol'),
  checkEol: () => request<EolState>('POST', '/api/eol/check', {}),
  updateProxy: () => request<ProxyStatus>('POST', '/api/proxy/update', {}),
}

/** The message to show for any thrown value. */
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : 'Something unexpected went wrong. Try again.'
}
