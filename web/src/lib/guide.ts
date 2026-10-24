// The guided setup's steps (internal/guide), what each is for, and how the
// page tells that one is done: by asking the part itself, never from a mark
// of its own.

import { api } from '@/lib/api'

export type GuideStep = 'domain' | 'certificate' | 'name' | 'proxy' | 'ssh' | 'updates' | 'firewall'

export interface GuideState {
  active: boolean
  skipped: GuideStep[]
}

export const guideSteps: { key: GuideStep; title: string; why: string }[] = [
  {
    key: 'domain',
    title: 'Your domain',
    why: "SGC gives your devices names under your domain (nas.your-domain and so on) and gets a certificate for them. Your domain's DNS has to be at Zone.eu; SGC uses its API key for both.",
  },
  {
    key: 'certificate',
    title: 'The certificate',
    why: 'One certificate from Let’s Encrypt for every name under your domain, renewed by SGC itself. Getting it takes a few minutes; you can go on to the next step meanwhile.',
  },
  {
    key: 'name',
    title: "This device's name",
    why: "SGC's own page opens at this name under your domain. \"sgc\" is fine for most homes; change it here if you like.",
  },
  {
    key: 'proxy',
    title: 'The proxy',
    why: 'The proxy (Traefik) opens your services by name, with the certificate, and makes this page open without a port. It needs the certificate first.',
  },
  {
    key: 'ssh',
    title: 'Your SSH key',
    why: 'Add the key of the computer you log in to this device from. With a key in place you can switch passwords off for SSH, which is safer.',
  },
  {
    key: 'updates',
    title: 'Updates for this device',
    why: "Debian's security updates for the operating system. Letting them install by themselves is the safe choice for a device that faces your network.",
  },
  {
    key: 'firewall',
    title: 'The firewall',
    why: 'Last, so that its rules let in everything you switched on before. You confirm that this page still answers; if it does not, SGC undoes the change by itself.',
  },
]

/** Which steps are done, asked of the parts themselves. */
export async function stepsDone(): Promise<Record<GuideStep, boolean>> {
  const settle = <T,>(p: Promise<T>) => p.then((v) => v, () => null)
  const [domain, certificate, proxy, ssh, updates, firewall] = await Promise.all([
    settle(api.domain()),
    settle(api.certificate()),
    settle(api.proxy()),
    settle(api.ssh()),
    settle(api.osUpdates()),
    settle(api.firewall()),
  ])
  const cert = certificate?.certificate
  return {
    domain: domain?.configured ?? false,
    certificate: !!cert && cert.forDomain && new Date(cert.notAfter) > new Date(),
    // The default name is a fine choice: there is a name once there is a domain.
    name: domain?.configured ?? false,
    proxy: (proxy?.wanted && proxy.running) ?? false,
    ssh: (ssh?.keys.length ?? 0) > 0,
    updates: (updates?.mode ?? '') !== '',
    firewall: firewall?.state === 'on',
  }
}
