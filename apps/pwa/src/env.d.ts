/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_CONTROL_API_BASE?: string;
  readonly VITE_CONTROL_CSRF_COOKIE_NAME?: string;
  readonly VITE_BROWSER_WS_PATH?: string;
  readonly VITE_SUB2API_ACCESS_TOKEN_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
