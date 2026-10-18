/**
 * Vite dev: proxy in vite.config targets http://127.0.0.1:8000
 * so API_BASE '' hits same origin /api/...
 *
 * Optional auth: set VITE_NETGUARD_API_TOKEN to match backend NETGUARD_API_TOKEN.
 * Never hardcode secrets in source — use env only.
 */

const metaEnv = (import.meta as { env?: Record<string, string | undefined> }).env ?? {};

export const API_BASE = metaEnv.VITE_API_BASE ?? '';

/** Bearer token for protected deployments; empty in typical local dev. */
export const API_TOKEN = (metaEnv.VITE_NETGUARD_API_TOKEN ?? '').trim();

export function apiHeaders(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  if (API_TOKEN) {
    h.set('Authorization', `Bearer ${API_TOKEN}`);
  }
  return h;
}

export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const headers = apiHeaders(init?.headers);
  return fetch(input, { ...init, headers });
}
