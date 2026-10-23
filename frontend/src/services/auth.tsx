import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import api, { ApiError, tokenStore } from './api'
import type { TokenPair, User } from '../types'

interface AuthState {
  user: User | null
  permissions: string[]
  loading: boolean
  error: string | null
  mustChangePassword: boolean
  signIn: (email: string, password: string, mfa?: string) => Promise<TokenPair>
  signOut: () => Promise<void>
  can: (permission: string) => boolean
  refreshMe: () => Promise<boolean>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [permissions, setPermissions] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [mustChangePassword, setMustChangePassword] = useState(false)

  const loadProfile = useCallback(async (): Promise<boolean> => {
    try {
      const me = await api.me()
      setUser(me.user)
      setPermissions(me.permissions)
      setMustChangePassword(me.user.must_change_password)
      setError(null)
      return true
    } catch (err) {
      setUser(null)
      setPermissions([])
      if (err instanceof ApiError && err.status !== 401) setError(err.message)
      return false
    }
  }, [])

  useEffect(() => {
    ;(async () => {
      if (tokenStore.access || tokenStore.refresh) {
        await loadProfile()
      }
      setLoading(false)
    })()
  }, [loadProfile])

  const signIn = useCallback(
    async (email: string, password: string, mfa?: string) => {
      const pair = await api.login(email, password, mfa)
      tokenStore.set(pair)
      setMustChangePassword(pair.must_change_password)
      const loaded = await loadProfile()
      if (!loaded) {
        // Credentials were accepted but the session could not be established.
        // Never fail silently here: the user would be bounced back to the sign-in
        // page with no explanation, which looks like a rejected password.
        tokenStore.clear()
        setUser(null)
        throw new ApiError(
          0,
          'Signed in, but your profile could not be loaded. Check the API logs, then try again.',
          'profile_load_failed',
        )
      }
      return pair
    },
    [loadProfile],
  )

  const signOut = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // Signing out locally must succeed even when the API is unreachable.
    }
    tokenStore.clear()
    setUser(null)
    setPermissions([])
  }, [])

  const value = useMemo<AuthState>(
    () => ({
      user,
      permissions,
      loading,
      error,
      mustChangePassword,
      signIn,
      signOut,
      can: (permission: string) => permissions.includes(permission),
      refreshMe: loadProfile,
    }),
    [user, permissions, loading, error, mustChangePassword, signIn, signOut, loadProfile],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
