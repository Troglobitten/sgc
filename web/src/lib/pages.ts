import { LayoutDashboard, LayoutGrid, Settings2, Users } from 'lucide-react'

/** The pages a signed-in admin can open, with their addresses. */
export const pages = {
  dashboard: { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  services: { path: '/services', label: 'Services', icon: LayoutGrid },
  people: { path: '/people', label: 'People', icon: Users },
  system: { path: '/system', label: 'System', icon: Settings2 },
} as const

export type Page = keyof typeof pages

export const pageNames = Object.keys(pages) as Page[]

export function pageForPath(path: string): Page | null {
  return pageNames.find((page) => pages[page].path === path) ?? null
}
