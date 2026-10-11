import { useState } from 'react'
import { Monitor, Moon, Sun } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { getThemePreference, setThemePreference, type ThemePreference } from '@/lib/theme'

const icons = { system: Monitor, light: Sun, dark: Moon }

export function ThemeMenu() {
  const [preference, setPreference] = useState<ThemePreference>(getThemePreference)
  const Icon = icons[preference]

  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon" aria-label="Appearance" />}>
        <Icon />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-40">
        <DropdownMenuRadioGroup
          value={preference}
          onValueChange={(value) => {
            const next = value as ThemePreference
            setThemePreference(next)
            setPreference(next)
          }}
        >
          <DropdownMenuRadioItem value="system" closeOnClick>
            Follow device
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="light" closeOnClick>
            Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark" closeOnClick>
            Dark
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
