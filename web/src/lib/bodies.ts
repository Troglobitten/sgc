import type {
  BackupSettings,
  BackupTarget,
  LogQuery,
  NotificationChannels,
  PersonInput,
  PublicSettings,
  ServiceInput,
  ServicesSettings,
  VpnSettings,
} from '@/lib/api'

// What the page sends when a request carries a whole form or settings
// object. SGC refuses fields it does not know, and TypeScript lets a larger
// object (a person with its id, the VPN's state with its settings) pass as
// a smaller one, which is how switching the VPN on and editing a person or
// a service came to be refused in 0.16.0. Each body below is written out
// field by field: an object literal may not have a field its type lacks,
// and a required field that is added to a type and not here does not
// compile.

export const serviceBody = (s: ServiceInput): ServiceInput => ({
  name: s.name,
  title: s.title,
  kind: s.kind,
  mode: s.mode,
  upstreamIp: s.upstreamIp,
  upstreamPort: s.upstreamPort,
  scheme: s.scheme,
  verifyTls: s.verifyTls,
  listenPort: s.listenPort,
  category: s.category,
  protected: s.protected,
  enabled: s.enabled,
  proxyProtocol: s.proxyProtocol,
  udpTimeout: s.udpTimeout,
  srvService: s.srvService,
})

export const publicSettingsBody = (s: PublicSettings): PublicSettings => ({
  requestsPerMinute: s.requestsPerMinute,
  connectionsPerMinute: s.connectionsPerMinute,
  allow: [...s.allow],
  levels: [...s.levels],
  countryMode: s.countryMode,
  countries: [...s.countries],
  fail2ban: {
    enabled: s.fail2ban.enabled,
    signIns: s.fail2ban.signIns,
    refused: s.fail2ban.refused,
    findMinutes: s.fail2ban.findMinutes,
    banMinutes: s.fail2ban.banMinutes,
  },
})

export const servicesSettingsBody = (s: ServicesSettings): ServicesSettings => ({
  approveNew: s.approveNew,
  iconCatalogue: s.iconCatalogue,
  abandonedDays: s.abandonedDays,
})

export const personBody = (p: PersonInput): PersonInput => ({
  name: p.name,
  network: p.network,
  allServices: p.allServices,
  serviceIds: [...p.serviceIds],
  loginEnabled: p.loginEnabled,
  username: p.username,
  password: p.password,
  expiresAt: p.expiresAt,
  disabled: p.disabled,
})

export const vpnSettingsBody = (s: VpnSettings): VpnSettings => ({
  enabled: s.enabled,
  port: s.port,
  network: s.network,
  name: s.name,
  endpointMode: s.endpointMode,
  staticIp: s.staticIp,
})

export const notificationChannelsBody = (c: NotificationChannels): NotificationChannels => ({
  email: {
    enabled: c.email.enabled,
    host: c.email.host,
    port: c.email.port,
    security: c.email.security,
    username: c.email.username,
    password: c.email.password,
    from: c.email.from,
    to: c.email.to,
  },
  ntfy: { enabled: c.ntfy.enabled, server: c.ntfy.server, topic: c.ntfy.topic, token: c.ntfy.token },
  routes: Object.fromEntries(
    Object.entries(c.routes).map(([event, route]) => [event, { email: route.email, ntfy: route.ntfy }]),
  ),
})

export const logQueryBody = (q: LogQuery): LogQuery => ({
  part: q.part,
  priority: q.priority,
  sinceSeconds: q.sinceSeconds,
  text: q.text,
  limit: q.limit,
  after: q.after,
})

export const backupTargetBody = (t: BackupTarget): BackupTarget => ({
  kind: t.kind,
  host: t.host,
  port: t.port,
  share: t.share,
  path: t.path,
  url: t.url,
  username: t.username,
  password: t.password,
  hostKey: t.hostKey,
  skipVerify: t.skipVerify,
})

export const backupSettingsBody = (s: BackupSettings): BackupSettings => ({
  enabled: s.enabled,
  target: backupTargetBody(s.target),
  time: s.time,
  keep: s.keep,
  publicKey: s.publicKey,
  since: s.since,
})
