import { API_BASE, apiFetch } from './config';

export type ModelMetrics = {
  modelType: string;          // 'cicids2017_real' | 'synthetic_fallback' | 'unknown'
  isRealTraining: boolean;
  warning: string | null;
  rf: {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    report?: Record<string, unknown>;
  } | null;
  xgb: {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    report?: Record<string, unknown>;
  } | null;
  classes: string[];
  nFeatures: number;
  featureImportances: Record<string, number>;
  trainInfo: {
    csvSource: string | null;
    nTrain: number | null;
    nTest: number | null;
  };
};

export type DashboardOverview = {
  source: string;
  kpis: {
    activeHosts: number;
    totalFlows: number;
    packetsPerSecond: number;
    bytesIngestedLabel: string;
    criticalAlerts: number;
    highAlerts: number;
    mediumAlerts: number;
    lowAlerts: number;
    threatScore: number;
    modelAccuracy: number | null;   // null = synthetic fallback, not meaningful
    modelType: string;
  };
  protocolDistribution: { protocol: string; count: number; percentage: number; color: string }[];
  attackDistribution: { attack: string; count: number; percentage: number; color: string; trend: string }[];
  trafficTimeline: { time: string; packets: number; bytes: number; alerts: number; anomalies: number }[];
  latestCriticalAlerts: Record<string, unknown>[];
  modelMeta: {
    modelType: string;
    isRealTraining: boolean;
    synthetic: boolean;
    classes?: string[];
    nFeatures?: number;
    rfAccuracy: number | null;
    xgbAccuracy: number | null;
  };
};

export async function fetchDashboardOverview(): Promise<DashboardOverview> {
  const r = await apiFetch(`${API_BASE}/api/dashboard/overview`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<DashboardOverview>;
}

export async function fetchDashboardStats(): Promise<{
  alertsTotal: number;
  hosts: number;
  flows: number;
  packets: number;
  visibilitySource: string;
}> {
  const r = await apiFetch(`${API_BASE}/api/dashboard/stats`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<{
    alertsTotal: number;
    hosts: number;
    flows: number;
    packets: number;
    visibilitySource: string;
  }>;
}

export async function fetchDashboardConfig(): Promise<Record<string, unknown>> {
  const r = await apiFetch(`${API_BASE}/api/dashboard/config`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<Record<string, unknown>>;
}

export async function fetchModelMetrics(): Promise<ModelMetrics> {
  const r = await apiFetch(`${API_BASE}/api/detection/model-metrics`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<ModelMetrics>;
}

export async function fetchTrainStatus(): Promise<{
  state: string;
  message: string;
  progress: number;
}> {
  const r = await apiFetch(`${API_BASE}/api/detection/train-status`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<{ state: string; message: string; progress: number }>;
}

function parseApiError(j: unknown, fallback: string): string {
  if (j && typeof j === 'object' && 'detail' in j) {
    const d = (j as { detail: unknown }).detail;
    if (Array.isArray(d)) return d.map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : JSON.stringify(x))).join('; ');
    if (typeof d === 'string') return d;
    return JSON.stringify(d);
  }
  return fallback;
}

export async function postUploadCicidsCsv(file: File): Promise<Record<string, unknown>> {
  const form = new FormData();
  form.append('file', file);
  const r = await apiFetch(`${API_BASE}/api/detection/upload-cicids`, { method: 'POST', body: form });
  let j: Record<string, unknown> = {};
  try { j = (await r.json()) as Record<string, unknown>; } catch { j = {}; }
  if (!r.ok) throw new Error(parseApiError(j, r.statusText));
  return j;
}

export async function postDemoLoadSample(runDetection: boolean): Promise<Record<string, unknown>> {
  const r = await apiFetch(`${API_BASE}/api/demo/load-sample`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_detection_scan: runDetection }),
  });
  let j: Record<string, unknown> = {};
  try { j = (await r.json()) as Record<string, unknown>; } catch { j = {}; }
  if (!r.ok) throw new Error(parseApiError(j, r.statusText));
  return j;
}

export async function fetchHealth(): Promise<{ status: string }> {
  const r = await apiFetch(`${API_BASE}/api/health`);
  if (!r.ok) throw new Error(r.statusText);
  return r.json() as Promise<{ status: string }>;
}
