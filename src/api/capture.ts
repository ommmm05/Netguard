import { API_BASE, apiFetch } from './config';

export type CaptureInterface = {
  id: string;
  name: string;
  devicePath?: string;
  description: string;
  isLoopback: boolean;
};

export type CaptureInterfacesResponse = {
  ok: boolean;
  interfaces: CaptureInterface[];
  error?: string | null;
  captureEngine?: string;
  captureAvailable?: boolean;
  tsharkPath?: string | null;
  tsharkVersion?: string;
  tsharkDetail?: string | null;
  defaultBpf?: string;
};

export type LiveCaptureStats = {
  engine?: string;
  tsharkPath?: string | null;
  tsharkAvailable?: boolean;
  tsharkDetail?: string | null;
  running: boolean;
  interface: string | null;
  startedAt?: number | null;
  started_at?: number | null;
  elapsedSeconds?: number;
  elapsed_seconds?: number;
  packetsCaptured?: number;
  packetsParsed?: number;
  packetsProcessed?: number;
  packets?: number;
  activeFlows?: number;
  completedFlows?: number;
  threatsDetected?: number;
  benignCount?: number;
  anomalyCount?: number;
  error: string | null;
  stopReason?: string | null;
  stop_reason?: 'manual' | 'timeout' | 'error' | string | null;
  bpfFilter?: string | null;
  diagnosticInfo?: {
    executable: string;
    interface: string;
    bpfFilter: string;
    outputMode: string;
  };
};

export type CaptureStatusResponse = {
  live: LiveCaptureStats;
  source: string;
  running: boolean;
  interface: string | null;
  started_at: number | null;
  elapsed_seconds: number;
  packets: number;
  packetsProcessed?: number;
  threatsDetected?: number;
  error: string | null;
  stop_reason: 'manual' | 'timeout' | 'error' | string | null;
  diagnosticInfo?: {
    executable: string;
    interface: string;
    bpfFilter: string;
    outputMode: string;
  };
};

export type LivePacketRow = {
  frameNumber: number;
  timestamp: number;
  srcMac: string;
  dstMac: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  transportProtocol: string;
  networkProtocol: string;
  length: number;
  tcpFlags?: Record<string, boolean>;
  ttl: number;
  payloadPreview?: string;
  protocolInfo?: string;
  httpMeta?: Record<string, unknown> | null;
  dnsMeta?: Record<string, unknown> | null;
  tlsMeta?: Record<string, unknown> | null;
  icmpMeta?: Record<string, unknown> | null;
};

export type LiveAlertRow = {
  id: string;
  timestamp: string;
  severity: string;
  title: string;
  description: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  attackType: string;
  confidence: number;
  model: string;
  status: string;
  features?: Record<string, unknown>;
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
  throw new Error(parseDetail(j, await r.text().catch(() => r.statusText) || r.statusText));
}

export async function fetchCaptureInterfaces(): Promise<CaptureInterfacesResponse> {
  const r = await apiFetch(`${API_BASE}/api/capture/interfaces`);
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<CaptureInterfacesResponse>;
}

export async function fetchCaptureStatus(): Promise<CaptureStatusResponse> {
  const r = await apiFetch(`${API_BASE}/api/capture/status`);
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<CaptureStatusResponse>;
}

export async function startLiveCapture(body: {
  interface: string;
  seconds?: number;
  bpfFilter?: string;
}): Promise<{ ok: boolean; message: string; stats: LiveCaptureStats }> {
  const r = await apiFetch(`${API_BASE}/api/capture/live/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      interface: body.interface,
      seconds: body.seconds ?? 0,
      bpfFilter: body.bpfFilter?.trim() ? body.bpfFilter.trim() : null,
    }),
  });
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<{ ok: boolean; message: string; stats: LiveCaptureStats }>;
}

export async function stopLiveCapture(): Promise<{ ok: boolean; message: string; stats: LiveCaptureStats }> {
  const r = await apiFetch(`${API_BASE}/api/capture/live/stop`, { method: 'POST' });
  if (!r.ok) await readJsonError(r);
  return r.json() as Promise<{ ok: boolean; message: string; stats: LiveCaptureStats }>;
}

export async function fetchRecentLivePackets(limit = 50): Promise<LivePacketRow[]> {
  const r = await apiFetch(`${API_BASE}/api/capture/live/packets?limit=${limit}`);
  if (!r.ok) return [];
  const j = (await r.json()) as { packets?: LivePacketRow[] };
  return j.packets ?? [];
}

export async function fetchRecentLiveAlerts(limit = 50): Promise<LiveAlertRow[]> {
  const r = await apiFetch(`${API_BASE}/api/capture/live/alerts?limit=${limit}`);
  if (!r.ok) return [];
  const j = (await r.json()) as { alerts?: LiveAlertRow[] };
  return j.alerts ?? [];
}

export type CaptureSession = {
  id: string;
  filename: string;
  filepath: string;
  interface: string;
  bpfFilter?: string | null;
  startTime: string;
  endTime?: string | null;
  durationSeconds: number;
  packetCount: number;
  fileSizeBytes: number;
  fileSize: string;
  status: 'running' | 'completed' | 'stopped' | 'error' | 'missing_file';
};

export type CaptureSessionsResponse = {
  ok: boolean;
  sessions: CaptureSession[];
  total: number;
};

export async function fetchCaptureSessions(): Promise<CaptureSession[]> {
  const r = await apiFetch(`${API_BASE}/api/capture/sessions`);
  if (!r.ok) return [];
  const j = (await r.json()) as CaptureSessionsResponse;
  return j.sessions ?? [];
}

export async function deleteCaptureSession(id: string): Promise<boolean> {
  const r = await apiFetch(`${API_BASE}/api/capture/sessions/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
  return r.ok;
}

export function getCaptureDownloadUrl(id: string): string {
  return `${API_BASE}/api/capture/sessions/${encodeURIComponent(id)}/download`;
}

export function getCaptureCsvUrl(id: string): string {
  return `${API_BASE}/api/capture/sessions/${encodeURIComponent(id)}/packets.csv`;
}

export function getDevicesExportUrl(): string {
  return `${API_BASE}/api/capture/devices/export.csv`;
}

