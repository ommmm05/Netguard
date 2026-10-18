import { API_BASE, apiFetch } from './config';
import {
  type DiscoveredHost,
  type CommEdge,
  type TopTalker,
  type DnsQuery,
  type NetworkSession,
  type BandwidthPoint,
  type ProtocolSlice,
  type ArpRow,
  type TlsRow,
  type HttpObservationRow,
  type DhcpObservationRow,
} from './visibilityTypes';

export type VisibilityBundle = {
  ok: true;
  summary: {
    discoveredHostCount: number;
    suspiciousHostCount: number;
    activeSessionCount: number;
    dnsQueryTotal: number;
    dnsSuspicious: number;
    packetCount?: number;
    protocolsSeen?: string[];
    topTalker?: string | null;
    source: string;
  };
  hosts: DiscoveredHost[];
  flows: NetworkSession[];
  graph: { nodes: { id: string; ip: string; label: string; risk: number; deviceType?: string }[]; edges: CommEdge[] };
  topTalkers: TopTalker[];
  protocols: ProtocolSlice[];
  bandwidth: BandwidthPoint[];
  dns: DnsQuery[];
  arp: ArpRow[];
  tls: TlsRow[];
  http: HttpObservationRow[];
  dhcp: DhcpObservationRow[];
  patternEvents: { type: string; message: string; ip?: string }[];
};

const json = (r: Response) => {
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
};

export async function fetchVisibilityBundle(): Promise<VisibilityBundle> {
  const base = API_BASE;
  const [
    summary,
    hosts,
    flows,
    graph,
    top,
    proto,
    bw,
    dns,
    arpTls,
    l7,
    patterns,
  ] = await Promise.all([
    json(await apiFetch(`${base}/api/visibility/summary`)),
    json(await apiFetch(`${base}/api/visibility/hosts`)),
    json(await apiFetch(`${base}/api/visibility/flows`)),
    json(await apiFetch(`${base}/api/visibility/graph`)),
    json(await apiFetch(`${base}/api/visibility/top-talkers`)),
    json(await apiFetch(`${base}/api/visibility/protocols`)),
    json(await apiFetch(`${base}/api/visibility/bandwidth`)),
    json(await apiFetch(`${base}/api/visibility/dns`)),
    json(await apiFetch(`${base}/api/visibility/arp-tls`)),
    json(await apiFetch(`${base}/api/visibility/l7-passive`)),
    json(await apiFetch(`${base}/api/visibility/patterns`)),
  ]);

  return {
    ok: true,
    summary,
    hosts: (hosts as { hosts: DiscoveredHost[] }).hosts,
    flows: (flows as { flows: NetworkSession[] }).flows,
    graph: graph as VisibilityBundle['graph'],
    topTalkers: (top as { items: TopTalker[] }).items,
    protocols: (proto as { items: ProtocolSlice[] }).items,
    bandwidth: (bw as { series: BandwidthPoint[] }).series,
    dns: (dns as { queries: DnsQuery[] }).queries,
    arp: (arpTls as { arp: ArpRow[] }).arp,
    tls: (arpTls as { tls: TlsRow[] }).tls,
    http: (l7 as { http?: HttpObservationRow[] }).http ?? [],
    dhcp: (l7 as { dhcp?: DhcpObservationRow[] }).dhcp ?? [],
    patternEvents: (patterns as { events: { type: string; message: string; ip?: string }[] }).events,
  };
}

export async function uploadPcap(file: File): Promise<Record<string, unknown>> {
  const fd = new FormData();
  fd.append('file', file);
  const r = await apiFetch(`${API_BASE}/api/capture/pcap`, { method: 'POST', body: fd });
  if (!r.ok) throw new Error(await r.text() || r.statusText);
  return r.json() as Promise<Record<string, unknown>>;
}
