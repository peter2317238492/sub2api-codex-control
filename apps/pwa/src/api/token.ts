export function readSub2ApiAccessToken(storage: Storage = window.localStorage): string | null {
  const key = import.meta.env.VITE_SUB2API_ACCESS_TOKEN_KEY?.trim() || "auth_token";
  const value = storage.getItem(key)?.trim();
  if (!value || value.startsWith("{") || value.startsWith("[")) return null;
  return value;
}
