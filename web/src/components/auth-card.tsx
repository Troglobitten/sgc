import type { ReactNode } from 'react'

import { Logo } from '@/components/logo'
import { ThemeMenu } from '@/components/theme-menu'
import { Card, CardContent } from '@/components/ui/card'

/** The centred card shared by the setup and sign-in screens. */
export function AuthCard({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle: string
  children: ReactNode
}) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center bg-muted/40 p-4">
      <div className="absolute top-3 right-3">
        <ThemeMenu />
      </div>
      <Card className="w-full max-w-sm">
        <CardContent className="flex flex-col gap-5">
          <div className="flex items-center gap-3">
            <Logo />
            <div>
              <h1 className="text-base font-medium">{title}</h1>
              <p className="text-sm text-muted-foreground">{subtitle}</p>
            </div>
          </div>
          {children}
        </CardContent>
      </Card>
    </div>
  )
}

/** An error message under a form, announced to screen readers when it appears. */
export function FormError({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <p role="alert" className="text-sm text-destructive">
      {message}
    </p>
  )
}
