// Light and dark appearance. By default SGC follows the device; the user can
// pin one or the other, and that choice is remembered in this browser.

export type ThemePreference = 'system' | 'light' | 'dark'

const storageKey = 'sgc-theme'
const systemDark = window.matchMedia('(prefers-color-scheme: dark)')

export function getThemePreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(storageKey)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // Storage can be unavailable (private windows, strict settings).
    // Following the device is a fine fallback.
  }
  return 'system'
}

export function setThemePreference(preference: ThemePreference) {
  try {
    if (preference === 'system') localStorage.removeItem(storageKey)
    else localStorage.setItem(storageKey, preference)
  } catch {
    // Not remembered, but still applied for this visit.
  }
  applyTheme(preference)
}

export function applyTheme(preference: ThemePreference = getThemePreference()) {
  const dark = preference === 'dark' || (preference === 'system' && systemDark.matches)
  document.documentElement.classList.toggle('dark', dark)
}

/** Applies the theme now and keeps following the device while set to "system". */
export function startTheme() {
  applyTheme()
  systemDark.addEventListener('change', () => applyTheme())
}
