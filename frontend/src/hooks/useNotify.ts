import { useOutletContext } from 'react-router-dom'

export type NotifyKind = 'success' | 'error' | 'info'

interface ShellContext {
  push: (kind: NotifyKind, text: string) => void
}

/** Access the shell's toast queue from a page rendered inside <Outlet />. */
export function useNotify(): (kind: NotifyKind, text: string) => void {
  const context = useOutletContext<ShellContext | undefined>()
  return context?.push ?? (() => undefined)
}
