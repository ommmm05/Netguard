import { API_BASE, apiFetch } from './config';

export type ScannedPort = {
  port: number;
  proto: string;
  service: string;
  state: string;
};

export type ScannedHost = {
  ip: string;
  mac?: string;
  hostname?: string;
  os_guess?: string;
  device_type?: string;
  ports?: ScannedPort[];
  is_gateway?: boolean;
};

export type ScanStatusResponse = {
  ok?: boolean;
  status: 'idle' | 'scanning' | 'done' | 'error' | string;
  progress: number;
  hosts: ScannedHost[];
  subnet?: string | null;
  localIp?: string | null;
  gatewayIp?: string | null;
  error?: string | null;
  message?: string | null;
  scanning?: boolean;
  elements?: unknown[];
  startedAt?: number | null;
  finishedAt?: number | null;
};

function parseDetail(j: unknown, fallback: string): string {
  if (j && typeof j === 'object' && 'detail' in j) {
    const d = (j as { detail: unknown }).detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
      return d
        .map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : JSON.stringify(x)))
        .join('; ');
    }
    return JSON.stringify(d);
  }
  return fallback;
}

async function readJsonError(r: Response): Promise<never> {
  let j: unknown = null;
  try {
    j = await r.json();
  } catch {
    j = null;
  }
  throw new Error(parseDetail(j, (await r.text().catch(() => r.statusText)) || r.statusText));
}

export async function startNetworkScan(): Promise<ScanStatusResponse> {
  const r = await apiFetch(`${API_BASE}/api/scan/start`, { method: 'POST' });
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<ScanStatusResponse>;
}

export async function fetchScanStatus(): Promise<ScanStatusResponse> {
  const r = await apiFetch(`${API_BASE}/api/scan/status`);
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<ScanStatusResponse>;
}

export async function fetchSubnetInfo(): Promise<{
  subnet: string;
  localIp: string;
  gatewayIp: string | null;
}> {
  const r = await apiFetch(`${API_BASE}/api/scan/subnet`);
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<{ subnet: string; localIp: string; gatewayIp: string | null }>;
}
