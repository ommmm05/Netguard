export type DiscoveredHost = {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  os: string;
  role: string;
  deviceType?: string;
  openPorts: number[];
  lastSeen: string;
  riskScore: number;
  status: 'active' | 'stale' | 'suspicious' | 'malicious' | string;
};

export type CommEdge = {
  source: string;
  target: string;
  bytes: number;
  protocol: string;
  suspicious: boolean;
};

export type TopTalker = {
  rank: number;
  ip: string;
  hostname: string;
  totalBytes: number;
  pctOfTotal: number;
  role: string;
};

export type DnsQuery = {
  domain: string;
  queryType: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  resolvedIp: string;
  category: string;
  suspicious: boolean;
};

export type NetworkSession = {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  duration: number;
  packets: number;
  bytes: number;
  startTime: string;
  endTime: string;
  state: string;
  threat: string | null;
  severity: string;
  suspicious: boolean;
};

export type BandwidthPoint = { time: string; inbound: number; outbound: number };
export type ProtocolSlice = { protocol: string; count: number; percentage: number; color?: string };
export type ArpRow = { ip: string; mac: string; type: string; ttl: number | null; suspicious: boolean };
export type TlsRow = {
  srcIp: string;
  dstIp: string;
  sni: string;
  version: string;
  cipherSuite: string;
  certIssuer: string;
  suspicious: boolean;
};

/** Passive HTTP `Host:` aggregation (Phase 1). */
export type HttpObservationRow = {
  srcIp: string;
  dstIp: string;
  hostHeader: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
};

/** Passive DHCP hostname / client IP (Phase 1). */
export type DhcpObservationRow = {
  clientIp: string;
  hostname: string;
  serverIp: string;
  seenAt: string;
};
