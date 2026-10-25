import {
  Archive,
  Bell,
  Cpu,
  Globe,
  LayoutDashboard,
  LayoutGrid,
  RefreshCw,
  ScrollText,
  Server,
  Settings2,
  Shield,
  Users,
} from 'lucide-react'

/** The pages a signed-in admin can open, with their addresses. */
export const pages = {
  dashboard: { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  services: { path: '/services', label: 'Services', icon: LayoutGrid },
  people: { path: '/people', label: 'People', icon: Users },
  system: { path: '/system', label: 'System', icon: Settings2 },
  logs: { path: '/logs', label: 'Logs', icon: ScrollText },
} as const

export type Page = keyof typeof pages

export const pageNames = Object.keys(pages) as Page[]

/**
 * The System page's sections, each at /system/<name>. On a phone /system
 * itself is the list of them; on a wider screen the list is beside the
 * section, and /system shows the first.
 */
export const systemSections = {
  security: { label: 'Security', lead: 'Who can reach this device, and who can sign in.', icon: Shield },
  domain: {
    label: 'Domain and names',
    lead: 'Your domain, its certificate, and the names SGC hands out under it.',
    icon: Globe,
  },
  dns: { label: 'DNS', lead: 'The name server of your home network.', icon: Server },
  updates: {
    label: 'Updates',
    lead: 'SGC itself, the device’s own software, and when the device may restart for them.',
    icon: RefreshCw,
  },
  backups: { label: 'Backups', lead: 'Copies of everything SGC holds, to get it back on a new device.', icon: Archive },
  notifications: {
    label: 'Notifications',
    lead: 'The bell at the top always has them. Problems and warnings can also go out by email and to ntfy.',
    icon: Bell,
  },
  device: { label: 'This device', lead: 'The hardware SGC runs on.', icon: Cpu },
} as const

export type SystemSection = keyof typeof systemSections

export const systemSectionNames = Object.keys(systemSections) as SystemSection[]

/** The address of a page, or of one of the System page's sections. */
export function pathFor(page: Page, section?: SystemSection | null): string {
  return page === 'system' && section ? `/system/${section}` : pages[page].path
}

export function pageForPath(path: string): Page | null {
  if (path.startsWith('/system/')) return 'system'
  return pageNames.find((page) => pages[page].path === path) ?? null
}

/** The System section an address names, or null for /system itself. */
export function sectionForPath(path: string): SystemSection | null {
  const name = path.startsWith('/system/') ? path.slice('/system/'.length).replace(/\/$/, '') : ''
  return (systemSectionNames as string[]).includes(name) ? (name as SystemSection) : null
}
