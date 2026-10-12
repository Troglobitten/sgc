import { LayoutDashboard, Settings2 } from 'lucide-react'

/** The pages a signed-in admin can open, with their addresses. */
export const pages = {
  dashboard: { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  system: { path: '/system', label: 'System', icon: Settings2 },
} as const

export type Page = keyof typeof pages

export const pageNames = Object.keys(pages) as Page[]

export function pageForPath(path: string): Page | null {
  return pageNames.find((page) => pages[page].path === path) ?? null
}
