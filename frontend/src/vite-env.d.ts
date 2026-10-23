/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Development/lab only. When set, the sign-in page offers a one-click fill for
   * that account, e.g. "admin@firestorm.example.com / Firestorm-Admin!2026".
   * Never set this for a deployment that real users can reach.
   */
  readonly VITE_DEV_LOGIN_EMAIL?: string
  readonly VITE_DEV_LOGIN_PASSWORD?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
