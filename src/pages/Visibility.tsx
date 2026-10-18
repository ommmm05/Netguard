import { useCallback, useEffect, useRef, useState, type ReactNode, type ChangeEventHandler } from 'react';
import {
  Server, Activity, Eye, AlertTriangle, Globe, Wifi, Upload, RefreshCw,
  Square, Play, Radar, Download, FileSpreadsheet, HardDrive, Trash2, Shield
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from 'recharts';
import { fetchVisibilityBundle, uploadPcap, type VisibilityBundle } from '../api/visibilityData';
import {
  fetchCaptureInterfaces,
  fetchCaptureStatus,
  fetchCaptureSessions,
  deleteCaptureSession,
  getCaptureDownloadUrl,
  getCaptureCsvUrl,
  getDevicesExportUrl,
  startLiveCapture,
  stopLiveCapture,
  type CaptureInterface,
  type CaptureStatusResponse,
  type CaptureSession,
} from '../api/capture';
import {
  startNetworkScan,
  fetchScanStatus,
  type ScanStatusResponse,
  type ScannedHost,
} from '../api/scan';
import type { DiscoveredHost, CommEdge, TopTalker, DnsQuery, NetworkSession, BandwidthPoint, ProtocolSlice, ArpRow, TlsRow } from '../api/visibilityTypes';
import StatusBadge from '../components/shared/StatusBadge';
import MetricCard from '../components/shared/MetricCard';

const tabs = ['Asset Discovery', 'Host Comms Graph', 'Traffic Flows', 'DNS Analysis', 'ARP / TLS / HTTP / DHCP', 'Bandwidth'];

const R_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#06b6d4', '#8b5cf6', '#f97316', '#ef4444', '#ec4899'];

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs shadow-xl">
      <p className="text-slate-400 mb-1 font-mono">{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.color }} className="font-mono">{p.name}: {typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</p>
      ))}
    </div>
  );
};

type GraphNode = { id: string; ip: string; label: string; risk: number; deviceType?: string };

const DEVICE_COLORS: Record<string, string> = {
  Gateway: '#1D9E75',
  'PLC/OT': '#E24B4A',
  Server: '#378ADD',
  Workstation: '#7F77DD',
  'IoT/Sensor': '#EF9F27',
  Unknown: '#888780',
};

function HostCommGraph({
  nodes,
  edges,
  selectedIp,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: CommEdge[];
  selectedIp?: string | null;
  onSelect?: (ip: string | null) => void;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const n = Math.max(1, nodes.length);
  const cx = 400;
  const cy = 220;
  const r = 190;
  const pos = (i: number) => {
    const a = (2 * Math.PI * i) / n - Math.PI / 2;
    return { x: cx + r * Math.cos(a), y: cy + (r * 0.75) * Math.sin(a) };
  };
  const nodeMap = Object.fromEntries(nodes.map((p, i) => {
    const { x, y } = pos(i);
    const color = (p.deviceType && DEVICE_COLORS[p.deviceType])
      || (p.risk > 80 ? '#ef4444' : p.risk > 50 ? '#f59e0b' : R_COLORS[i % R_COLORS.length]);
    return [p.id, { ...p, x, y, color }];
  }));

  if (!nodes.length) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-sm border border-slate-800 rounded-lg bg-slate-900/40">
        No host / flow data. Upload a PCAP or run Scan Network to build the graph.
      </div>
    );
  }

  return (
    <div className="w-full">
      <svg viewBox="0 0 800 480" className="w-full h-auto" style={{ minHeight: 260 }}>
        <defs>
          <marker id="arrowRed" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#ef4444" opacity={0.8} />
          </marker>
          <marker id="arrowGray" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#475569" opacity={0.6} />
          </marker>
        </defs>
        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
          <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
        </pattern>
        <rect width="100%" height="100%" fill="url(#grid)" />
        {edges.map((e, i) => {
          const src = nodeMap[e.source];
          const tgt = nodeMap[e.target];
          if (!src || !tgt) return null;
          const isHovered = hover === e.source || hover === e.target;
          return (
            <line key={i} x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
              stroke={e.suspicious ? '#ef4444' : '#334155'}
              strokeWidth={isHovered ? 2.5 : e.suspicious ? 2 : 1.5}
              strokeDasharray={e.suspicious ? '6,3' : undefined}
              opacity={isHovered ? 1 : 0.7}
              markerEnd={e.suspicious ? 'url(#arrowRed)' : 'url(#arrowGray)'}
            />
          );
        })}
        {Object.values(nodeMap).map((node) => {
          if (!('x' in node)) return null;
          const nx = node as GraphNode & { x: number; y: number; color: string };
          const isHovered = hover === nx.id;
          const isSelected = selectedIp === nx.ip;
          const isCritical = nx.risk > 80;
          return (
            <g
              key={nx.id}
              onMouseEnter={() => setHover(nx.id)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onSelect?.(isSelected ? null : nx.ip)}
              style={{ cursor: 'pointer' }}
            >
              {isCritical && (
                <circle cx={nx.x} cy={nx.y} r={24} fill={nx.color} opacity={0.12}>
                  <animate attributeName="r" values="24;32;24" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.12;0.04;0.12" dur="2s" repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={nx.x} cy={nx.y} r={isHovered || isSelected ? 22 : 18}
                fill={nx.color} fillOpacity={0.15}
                stroke={isSelected ? '#f1f5f9' : nx.color} strokeWidth={isSelected ? 3 : isHovered ? 2.5 : 1.5}
              />
              <text x={nx.x} y={nx.y + 1} textAnchor="middle" dominantBaseline="middle"
                fill={nx.color} fontSize={8} fontWeight={700} fontFamily="monospace">
                {nx.label}
              </text>
              {isHovered && (
                <g>
                  <rect x={nx.x + 24} y={nx.y - 28} width={110} height={48} rx={6} fill="#0f172a" stroke="#334155" strokeWidth={1} />
                  <text x={nx.x + 30} y={nx.y - 12} fill="#f1f5f9" fontSize={9} fontWeight={600}>{nx.deviceType || `Risk: ${nx.risk}`}</text>
                  <text x={nx.x + 30} y={nx.y + 4} fill="#94a3b8" fontSize={8} fontFamily="monospace">{nx.ip}</text>
                </g>
              )}
            </g>
          );
        })}
        <g transform="translate(10, 10)">
          <rect width="170" height={55 + Object.keys(DEVICE_COLORS).length * 12} rx="6" fill="#0f172a" fillOpacity={0.85} stroke="#1e293b" />
          <text x="10" y="18" fill="#64748b" fontSize={9} fontWeight={600}>HOST COMMS GRAPH</text>
          {Object.entries(DEVICE_COLORS).map(([k, c], i) => (
            <g key={k} transform={`translate(10, ${28 + i * 12})`}>
              <circle cx="4" cy="0" r="4" fill={c} />
              <text x="14" y="3" fill="#94a3b8" fontSize={8}>{k}</text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}



function EmptyHint({ children }: { children: ReactNode }) {
  return (
    <tr>
      <td colSpan={12} className="px-3 py-8 text-center text-slate-500 text-sm">
        {children}
      </td>
    </tr>
  );
}

function LiveCapturePanel({
  onChanged,
  captureStatus,
  setCaptureStatus,
}: {
  onChanged: () => Promise<void>;
  captureStatus: CaptureStatusResponse | null;
  setCaptureStatus: (s: CaptureStatusResponse | null) => void;
}) {
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([]);
  const [iface, setIface] = useState('');
  const [seconds, setSeconds] = useState(0);
  const [bpf, setBpf] = useState('');
  const [busy, setBusy] = useState<'start' | 'stop' | 'ifaces' | null>(null);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [captureAvailable, setCaptureAvailable] = useState<boolean | null>(null);
  const [tsharkPath, setTsharkPath] = useState<string | null>(null);
  const [tsharkVersion, setTsharkVersion] = useState<string | null>(null);
  const [captureDetail, setCaptureDetail] = useState<string | null>(null);
  const [showDiagnostic, setShowDiagnostic] = useState(false);

  const loadIfaces = useCallback(async () => {
    setBusy('ifaces');
    setLocalErr(null);
    try {
      const res = await fetchCaptureInterfaces();
      setIfaces(res.interfaces || []);
      setCaptureAvailable(res.captureAvailable ?? null);
      setTsharkPath(res.tsharkPath ?? null);
      setTsharkVersion(res.tsharkVersion ?? null);
      setCaptureDetail(res.tsharkDetail ?? res.error ?? null);
      setIface((prev) => {
        if (prev && res.interfaces.some((i) => i.id === prev || i.name === prev)) return prev;
        const wifi = res.interfaces.find((i) => i.description.toLowerCase().includes('wi-fi') || i.name.toLowerCase().includes('wi-fi'));
        if (wifi) return wifi.id || wifi.name;
        const preferred = res.interfaces.find((i) => !i.isLoopback) || res.interfaces[0];
        return preferred?.id || preferred?.name || '';
      });
    } catch (e) {
      setLocalErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => { void loadIfaces(); }, [loadIfaces]);

  const running = !!captureStatus?.running;
  const live = captureStatus?.live;
  const isAvailable = captureAvailable === true;

  const onStart = async () => {
    if (!iface) {
      setLocalErr('Select a capture interface');
      return;
    }
    setBusy('start');
    setLocalErr(null);
    try {
      await startLiveCapture({ interface: iface, seconds, bpfFilter: bpf });
      const st = await fetchCaptureStatus();
      setCaptureStatus(st);
      await onChanged();
    } catch (e) {
      setLocalErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const onStop = async () => {
    setBusy('stop');
    setLocalErr(null);
    try {
      await stopLiveCapture();
      const st = await fetchCaptureStatus();
      setCaptureStatus(st);
      await onChanged();
    } catch (e) {
      setLocalErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const statusLabel = running
    ? 'RUNNING'
    : !isAvailable
      ? 'UNAVAILABLE'
      : live?.stop_reason === 'timeout'
        ? 'STOPPED (timeout)'
        : live?.error
          ? 'ERROR'
          : 'STOPPED';

  const threatCount = live?.threatsDetected ?? 0;

  return (
    <div className="bg-[#111827] border border-[#243244] rounded-lg p-4 space-y-4">
      {/* 1. Top Header with Clean Status Indicator */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#243244] pb-3">
        <div>
          <h3 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider flex items-center gap-2">
            <Wifi className="w-4 h-4 text-[#06B6D4]" />
            Live Capture Control
          </h3>
          <p className="text-[11px] text-[#94A3B8] font-mono mt-0.5">
            Engine: <span className="text-[#06B6D4] font-medium">TShark</span>
            {tsharkPath && <span className="text-[#64748B] ml-2 hidden sm:inline truncate max-w-xs">({tsharkPath})</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowDiagnostic(!showDiagnostic)}
            className="text-[11px] font-mono px-2 py-1 rounded bg-[#172033] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#E5E7EB] border border-[#243244] transition-colors"
          >
            {showDiagnostic ? 'Hide Diagnostics' : 'Diagnostics'}
          </button>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-[#243244] bg-[#0F172A] font-mono text-xs font-semibold">
            <span className={`w-2 h-2 rounded-full ${running ? 'bg-[#22C55E]' : isAvailable ? 'bg-[#64748B]' : 'bg-[#EF4444]'}`} />
            <span className={running ? 'text-[#22C55E]' : isAvailable ? 'text-[#94A3B8]' : 'text-[#EF4444]'}>
              {statusLabel}
            </span>
          </div>
        </div>
      </div>

      {/* Diagnostic view toggle */}
      {showDiagnostic && (
        <div className="bg-[#0F172A] border border-[#243244] rounded p-3 text-xs font-mono space-y-1">
          <p className="text-[#94A3B8] font-semibold mb-1">TShark Execution Environment:</p>
          <p><span className="text-[#64748B]">Executable:</span> <span className="text-[#06B6D4]">{tsharkPath || 'Not Found'}</span></p>
          <p><span className="text-[#64748B]">Version:</span> <span className="text-[#E5E7EB]">{tsharkVersion || 'N/A'}</span></p>
          <p><span className="text-[#64748B]">Interface Selected:</span> <span className="text-[#E5E7EB]">{iface || 'None'}</span></p>
          <p><span className="text-[#64748B]">Capture Filter:</span> <span className="text-[#E5E7EB]">{bpf || 'None (all traffic)'}</span></p>
          <p><span className="text-[#64748B]">Output Pipeline:</span> <span className="text-[#06B6D4]">-w &lt;capture.pcapng&gt; -P -l -T ek (PCAPNG file + live NDJSON stream)</span></p>
        </div>
      )}

      {/* 2. Controls Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        <div>
          <label htmlFor="live-iface" className="text-xs font-medium text-[#E5E7EB] block mb-1">
            Capture Interface
          </label>
          <div className="flex gap-1.5">
            <select
              id="live-iface"
              className="flex-1 min-w-0 h-9 bg-[#172033] border border-[#243244] rounded px-2.5 text-xs text-[#E5E7EB] font-mono truncate focus:outline-none focus:border-[#06B6D4] disabled:opacity-50 disabled:cursor-not-allowed"
              value={iface}
              disabled={running || busy !== null || !isAvailable}
              onChange={(e) => setIface(e.target.value)}
              title={ifaces.find((i) => i.id === iface || i.name === iface)?.description || iface}
            >
              {!ifaces.length && <option value="">No interfaces discovered</option>}
              {ifaces.map((i) => (
                <option key={i.id} value={i.id} title={i.description}>
                  {i.id}. {i.description}
                </option>
              ))}
            </select>
            <button
              type="button"
              aria-label="Refresh interfaces"
              disabled={busy !== null || !isAvailable}
              onClick={() => void loadIfaces()}
              className="h-9 w-9 flex items-center justify-center rounded border border-[#243244] bg-[#172033] text-[#94A3B8] hover:text-[#E5E7EB] hover:bg-[#1E293B] disabled:opacity-50 transition-colors"
              title="Refresh interfaces list"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${busy === 'ifaces' ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <p className="text-[10px] text-[#94A3B8] mt-1">Select adapter for live capture</p>
        </div>

        <div>
          <label htmlFor="live-bpf" className="text-xs font-medium text-[#E5E7EB] block mb-1">
            Capture Filter
          </label>
          <input
            id="live-bpf"
            type="text"
            placeholder="tcp or udp, port 443"
            value={bpf}
            disabled={running || busy !== null || !isAvailable}
            onChange={(e) => setBpf(e.target.value)}
            className="w-full h-9 bg-[#172033] border border-[#243244] rounded px-2.5 text-xs text-[#E5E7EB] font-mono focus:outline-none focus:border-[#06B6D4] disabled:opacity-50 disabled:cursor-not-allowed placeholder-[#64748B]"
          />
          <p className="text-[10px] text-[#94A3B8] mt-1">BPF/libpcap syntax (e.g. port 80, host 192.168.1.1)</p>
        </div>

        <div>
          <label htmlFor="live-seconds" className="text-xs font-medium text-[#E5E7EB] block mb-1">
            Duration
          </label>
          <input
            id="live-seconds"
            type="number"
            min={0}
            max={86400}
            value={seconds}
            placeholder="0"
            disabled={running || busy !== null || !isAvailable}
            onChange={(e) => setSeconds(Math.max(0, Math.min(86400, Number(e.target.value) || 0)))}
            className="w-full h-9 bg-[#172033] border border-[#243244] rounded px-2.5 text-xs text-[#E5E7EB] font-mono focus:outline-none focus:border-[#06B6D4] disabled:opacity-50 disabled:cursor-not-allowed"
          />
          <p className="text-[10px] text-[#94A3B8] mt-1">Seconds (0 = continuous until stopped)</p>
        </div>
      </div>

      {/* 3. Action Buttons with Full Width & No Text Clipping */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
        <button
          type="button"
          disabled={running || busy !== null || !iface || !isAvailable}
          onClick={() => void onStart()}
          className="h-9 px-4 rounded text-xs font-semibold flex items-center justify-center gap-2 bg-[#06B6D4] hover:bg-[#0891B2] text-slate-950 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Play className={`w-3.5 h-3.5 fill-current ${busy === 'start' ? 'animate-spin' : ''}`} />
          <span>{busy === 'start' ? 'Starting live capture...' : 'Start Live Capture'}</span>
        </button>
        <button
          type="button"
          disabled={!running || busy !== null}
          onClick={() => void onStop()}
          className="h-9 px-4 rounded text-xs font-semibold flex items-center justify-center gap-2 border border-[#EF4444]/40 bg-[#EF4444]/10 hover:bg-[#EF4444]/20 text-[#EF4444] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Square className="w-3.5 h-3.5 fill-current" />
          <span>{busy === 'stop' ? 'Stopping capture...' : 'Stop Capture'}</span>
        </button>
      </div>

      {/* 4. Statistics Grid: 6 Uniform Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-1 font-mono">
        <div className="bg-[#0F172A] border border-[#243244] rounded p-2 text-center">
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Captured</p>
          <p className="text-base font-bold text-[#E5E7EB] mt-0.5">{live?.packetsCaptured ?? live?.packets ?? 0}</p>
        </div>
        <div className="bg-[#0F172A] border border-[#243244] rounded p-2 text-center">
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Parsed</p>
          <p className="text-base font-bold text-[#06B6D4] mt-0.5">{live?.packetsParsed ?? 0}</p>
        </div>
        <div className="bg-[#0F172A] border border-[#243244] rounded p-2 text-center">
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Processed</p>
          <p className="text-base font-bold text-[#38BDF8] mt-0.5">{live?.packetsProcessed ?? 0}</p>
        </div>
        <div className="bg-[#0F172A] border border-[#243244] rounded p-2 text-center">
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Active Flows</p>
          <p className="text-base font-bold text-[#A855F7] mt-0.5">{live?.activeFlows ?? 0}</p>
        </div>
        <div className="bg-[#0F172A] border border-[#243244] rounded p-2 text-center">
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Completed Flows</p>
          <p className="text-base font-bold text-[#22C55E] mt-0.5">{live?.completedFlows ?? 0}</p>
        </div>
        <div className={`rounded p-2 text-center border ${threatCount > 0 ? 'bg-[#EF4444]/10 border-[#EF4444]/30' : 'bg-[#0F172A] border-[#243244]'}`}>
          <p className="text-[10px] text-[#94A3B8] uppercase font-medium tracking-wider">Threats</p>
          <p className={`text-base font-bold mt-0.5 ${threatCount > 0 ? 'text-[#EF4444]' : 'text-[#94A3B8]'}`}>{threatCount}</p>
        </div>
      </div>

      {/* Error / Availability Alert */}
      {(localErr || live?.error || !isAvailable) && (
        <div className="text-xs text-[#F59E0B] border border-[#F59E0B]/30 rounded p-3 bg-[#F59E0B]/5 space-y-1 font-mono">
          {localErr && <p>⚠ {localErr}</p>}
          {live?.error && <p>⚠ Backend Error: {live.error}</p>}
          {!isAvailable && (
            <div>
              <p className="font-semibold text-[#F59E0B]">TShark executable not found on this system.</p>
              <p className="text-[#94A3B8] mt-0.5 text-xs">
                {captureDetail || 'Please verify Wireshark installation or configure NETGUARD_TSHARK_PATH.'}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SavedCapturesPanel({
  activeCaptureRunning,
  activeSessionId,
  onRefreshParent,
}: {
  activeCaptureRunning: boolean;
  activeSessionId?: string | null;
  onRefreshParent?: () => Promise<void>;
}) {
  const [sessions, setSessions] = useState<CaptureSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadSessions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchCaptureSessions();
      setSessions(data);
    } catch {
      setSessions([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    const t = setInterval(() => {
      void loadSessions();
    }, 4000);
    return () => clearInterval(t);
  }, [loadSessions]);

  const onDelete = async (id: string) => {
    if (!window.confirm(`Delete capture session ${id}?`)) return;
    setDeletingId(id);
    try {
      await deleteCaptureSession(id);
      await loadSessions();
      if (onRefreshParent) await onRefreshParent();
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="bg-[#111827] border border-[#243244] rounded-lg p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#243244] pb-3">
        <div>
          <h3 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-[#06B6D4]" />
            Saved Captures (Wireshark PCAPNG Export)
          </h3>
          <p className="text-[11px] text-[#94A3B8] mt-0.5">
            Download genuine PCAPNG traffic captures openable directly in Wireshark
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadSessions()}
          disabled={loading}
          className="text-[11px] font-mono px-2.5 py-1 rounded border border-[#243244] bg-[#172033] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#E5E7EB] flex items-center gap-1.5 transition-colors"
          title="Refresh capture history"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {activeCaptureRunning && (
        <div className="px-3 py-2 rounded bg-[#0F172A] border border-[#06B6D4]/30 text-xs text-[#94A3B8] flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#22C55E]" />
            <span className="text-[#E5E7EB] font-mono text-xs">Live capture session in progress:</span>
            <span className="text-[#06B6D4] font-mono font-semibold text-xs">{activeSessionId || 'Active'}</span>
          </div>
          <span className="text-[#94A3B8] text-[11px] italic">
            Stop capture to finalize and download the complete PCAPNG.
          </span>
        </div>
      )}

      <div className="overflow-x-auto max-h-72">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#243244] text-[#94A3B8] text-left">
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Capture Time</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Interface</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Packets</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Size</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Duration</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px]">Status</th>
              <th className="px-3 py-2 font-medium uppercase tracking-wider text-[11px] text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-[#64748B] text-xs">
                  No saved capture sessions yet. Start a live capture above to record traffic.
                </td>
              </tr>
            ) : (
              sessions.map((sess) => {
                const isRunning = sess.status === 'running';
                const formattedTime = sess.startTime ? new Date(sess.startTime).toLocaleString(undefined, {
                  month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
                }) : sess.id;
                return (
                  <tr key={sess.id} className="border-b border-[#243244]/60 hover:bg-[#172033]/60 transition-colors">
                    <td className="px-3 py-2.5 font-mono text-[#E5E7EB] whitespace-nowrap">
                      {formattedTime}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[#94A3B8] whitespace-nowrap">
                      {sess.interface}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[#06B6D4] whitespace-nowrap font-semibold">
                      {sess.packetCount.toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[#94A3B8] whitespace-nowrap">
                      {sess.fileSize}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[#94A3B8] whitespace-nowrap">
                      {sess.durationSeconds > 0 ? `${sess.durationSeconds.toFixed(1)}s` : '—'}
                    </td>
                    <td className="px-3 py-2.5 whitespace-nowrap">
                      <StatusBadge status={sess.status} size="xs" />
                    </td>
                    <td className="px-3 py-2.5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        {isRunning ? (
                          <span className="text-[11px] text-[#94A3B8] italic">Recording…</span>
                        ) : (
                          <>
                            <a
                              href={getCaptureDownloadUrl(sess.id)}
                              download={sess.filename}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#06B6D4]/10 hover:bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/30 text-[11px] font-semibold transition-colors"
                              title="Download PCAPNG for Wireshark inspection"
                            >
                              <Download className="w-3 h-3" />
                              <span>PCAPNG</span>
                            </a>
                            <a
                              href={getCaptureCsvUrl(sess.id)}
                              download={`${sess.id}_packets.csv`}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#172033] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#E5E7EB] border border-[#243244] text-[11px] transition-colors"
                              title="Download packet summary as CSV"
                            >
                              <FileSpreadsheet className="w-3 h-3" />
                              <span>CSV</span>
                            </a>
                            <button
                              type="button"
                              onClick={() => void onDelete(sess.id)}
                              disabled={deletingId === sess.id}
                              className="p-1 rounded hover:bg-[#EF4444]/10 text-[#64748B] hover:text-[#EF4444] transition-colors"
                              title="Delete capture session"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function NetworkScanPanel({
  onChanged,
  scanStatus,
  setScanStatus,
}: {
  onChanged: () => Promise<void>;
  scanStatus: ScanStatusResponse | null;
  setScanStatus: (s: ScanStatusResponse | null) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [localErr, setLocalErr] = useState<string | null>(null);

  const scanning = scanStatus?.status === 'scanning' || !!scanStatus?.scanning;

  const onScan = async () => {
    setBusy(true);
    setLocalErr(null);
    try {
      const st = await startNetworkScan();
      setScanStatus(st);
      if (st.error && st.status === 'error') {
        setLocalErr(st.message || st.error);
      }
      await onChanged();
    } catch (e) {
      setLocalErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const progress = scanStatus?.progress ?? 0;
  const hosts = scanStatus?.hosts ?? [];

  return (
    <div className="bg-[#111827] border border-[#243244] rounded-lg p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#243244] pb-3">
        <div>
          <h3 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider flex items-center gap-2">
            <Radar className="w-4 h-4 text-[#22C55E]" />
            Local Network Scanner
          </h3>
          <p className="text-[11px] text-[#94A3B8] mt-0.5">
            Passive ARP sweep + rapid discovery of LAN hosts and open services
          </p>
        </div>
        <span className={`text-xs font-mono px-2.5 py-1 rounded border ${
          scanning
            ? 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/30'
            : scanStatus?.status === 'error'
              ? 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30'
              : scanStatus?.status === 'done'
                ? 'bg-[#06B6D4]/10 text-[#06B6D4] border-[#06B6D4]/30'
                : 'bg-[#172033] text-[#94A3B8] border-[#243244]'
        }`}>
          {scanning ? 'SCANNING…' : (scanStatus?.status || 'IDLE').toUpperCase()}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-3 pt-1">
        <button
          type="button"
          disabled={busy || scanning}
          onClick={() => void onScan()}
          className="h-9 px-4 rounded text-xs font-semibold flex items-center gap-2 bg-[#22C55E] hover:bg-[#16A34A] text-slate-950 disabled:opacity-50 transition-colors"
        >
          <Radar className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
          <span>{busy || scanning ? 'Scanning Network…' : 'Scan Network'}</span>
        </button>
        <div className="flex-1 min-w-[160px] max-w-xs">
          <div className="h-2 bg-[#172033] rounded overflow-hidden border border-[#243244]">
            <div
              className="h-full bg-[#22C55E] transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
            />
          </div>
          <p className="text-[10px] text-[#94A3B8] font-mono mt-1">{progress}% · {hosts.length} host(s) discovered</p>
        </div>
        {scanStatus?.subnet && (
          <span className="text-xs text-[#94A3B8] font-mono">
            {scanStatus.subnet}
            {scanStatus.gatewayIp ? ` · gw ${scanStatus.gatewayIp}` : ''}
          </span>
        )}
      </div>

      {scanStatus?.message && (
        <p className="text-xs text-[#94A3B8] font-mono">{scanStatus.message}</p>
      )}
      {(localErr || scanStatus?.error) && (
        <div className="text-xs text-[#F59E0B] border border-[#F59E0B]/30 rounded p-2.5 bg-[#F59E0B]/5 font-mono">
          {localErr || scanStatus?.error}
        </div>
      )}
    </div>
  );
}

function useVisibilityData() {
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [b, setB] = useState<VisibilityBundle | null>(null);
  const [source, setSource] = useState<string>('—');

  const reload = useCallback(async (opts?: { quiet?: boolean }) => {
    if (!opts?.quiet) setLoading(true);
    setErr(null);
    try {
      const v = await fetchVisibilityBundle();
      setB(v);
      setSource(v.summary?.source || '—');
    } catch (e) {
      setErr((e as Error).message);
      setB(null);
    } finally {
      if (!opts?.quiet) setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  return { loading, err, b, source, reload, setB, setSource };
}

export default function Visibility() {
  const { loading, err, b, source, reload } = useVisibilityData();
  const [activeTab, setActiveTab] = useState(0);
  const [upBusy, setUpBusy] = useState(false);
  const [captureStatus, setCaptureStatus] = useState<CaptureStatusResponse | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const scanPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const inFlight = useRef(false);

  const refreshStatus = useCallback(async () => {
    try {
      const st = await fetchCaptureStatus();
      setCaptureStatus(st);
      return st;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    void fetchScanStatus().then(setScanStatus).catch(() => undefined);
  }, [refreshStatus]);

  // Poll visibility + capture status every 2s while live capture is running
  useEffect(() => {
    const running = !!captureStatus?.running;
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
    if (!running) return undefined;

    pollingRef.current = setInterval(() => {
      if (inFlight.current) return;
      inFlight.current = true;
      void (async () => {
        try {
          const st = await fetchCaptureStatus();
          setCaptureStatus(st);
          await reload({ quiet: true });
        } catch {
          /* ignore transient poll errors */
        } finally {
          inFlight.current = false;
        }
      })();
    }, 2000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [captureStatus?.running, reload]);

  // Poll scan progress while LAN scan is running
  useEffect(() => {
    const scanning = scanStatus?.status === 'scanning' || !!scanStatus?.scanning;
    if (scanPollRef.current) {
      clearInterval(scanPollRef.current);
      scanPollRef.current = null;
    }
    if (!scanning) return undefined;

    scanPollRef.current = setInterval(() => {
      void (async () => {
        try {
          const st = await fetchScanStatus();
          setScanStatus(st);
          await reload({ quiet: true });
        } catch {
          /* ignore */
        }
      })();
    }, 1500);

    return () => {
      if (scanPollRef.current) {
        clearInterval(scanPollRef.current);
        scanPollRef.current = null;
      }
    };
  }, [scanStatus?.status, scanStatus?.scanning, reload]);

  const onUpload: ChangeEventHandler<HTMLInputElement> = async (e) => {
    const f = e.target.files?.[0];
    e.target.value = '';
    if (!f) return;
    setUpBusy(true);
    try {
      await uploadPcap(f);
      await reload();
      await refreshStatus();
    } catch (ex) {
      alert((ex as Error).message);
    } finally {
      setUpBusy(false);
    }
  };

  const hosts: DiscoveredHost[] = b?.hosts?.length ? b.hosts : [];
  const edges: CommEdge[] = b?.graph?.edges?.length ? b.graph.edges : [];
  const gnodes: GraphNode[] = (b?.graph?.nodes?.length
    ? b.graph.nodes
    : hosts.map((h) => ({
        id: h.ip,
        ip: h.ip,
        label: h.hostname || h.ip,
        risk: h.riskScore,
        deviceType: h.deviceType || h.role,
      }))
  ).map((n) => ({
    ...n,
    deviceType:
      n.deviceType
      || hosts.find((h) => h.ip === n.ip)?.deviceType
      || hosts.find((h) => h.ip === n.ip)?.role,
  }));
  const topTalkers: TopTalker[] = b?.topTalkers?.length ? b.topTalkers : [];
  const dnsQueries: DnsQuery[] = b?.dns?.length ? b.dns : [];
  const networkSessions: NetworkSession[] = b?.flows?.length
    ? b.flows.map((r) => ({ ...r, threat: r.threat ?? null, severity: r.severity }))
    : [];
  const bandwidthData: BandwidthPoint[] = b?.bandwidth?.length ? b.bandwidth : [];
  const protocolDistribution: (ProtocolSlice & { color?: string })[] = b?.protocols?.length
    ? b.protocols.map((p, i) => ({ ...p, color: R_COLORS[i % R_COLORS.length] }))
    : [];
  const arpTable: ArpRow[] = b?.arp?.length ? b.arp : [];
  const tlsMetadata: TlsRow[] = b?.tls?.length ? b.tls : [];
  const httpObs = b?.http ?? [];
  const dhcpObs = b?.dhcp ?? [];
  const summary = b?.summary;

  const susH = hosts.filter((h) => h.riskScore > 70);
  const activeHosts = hosts.filter((h) => h.status === 'active').length;
  const protocolsSeen = summary?.protocolsSeen?.length
    ? summary.protocolsSeen
    : protocolDistribution.map((p) => p.protocol);
  const topTalkerIp = summary?.topTalker || topTalkers[0]?.ip || '—';
  const selectedHost = selectedIp ? hosts.find((h) => h.ip === selectedIp) : undefined;
  const selectedScanHost: ScannedHost | undefined = selectedIp
    ? (scanStatus?.hosts || []).find((h) => h.ip === selectedIp)
    : undefined;

  const connected = !err && b !== null;
  const srcLower = (source || '').toLowerCase();
  const isDemoSource = srcLower.includes('demo') || srcLower.includes('sample') || srcLower === 'auto-demo';
  const isLiveOrPcap = srcLower === 'live' || srcLower === 'pcap' || srcLower === 'scan'
    || srcLower.startsWith('live') || srcLower.startsWith('pcap') || srcLower.startsWith('scan');
  const isEmpty = connected && hosts.length === 0 && networkSessions.length === 0;
  const captureRunning = !!captureStatus?.running;
  const scanRunning = scanStatus?.status === 'scanning' || !!scanStatus?.scanning;

  const emptyMessage = (() => {
    if (captureRunning) return 'Live capture is running; waiting for packets…';
    if (scanRunning) return 'Network scan in progress…';
    if (isLiveOrPcap) return 'No traffic has been captured yet.';
    return 'Upload a PCAP, click Scan Network, or start a live capture.';
  })();

  return (
    <div className="p-4 md:p-6 space-y-4 overflow-auto h-full bg-[#0B1120]">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#243244] pb-4">
        <div>
          <h2 className="text-base font-bold text-[#E5E7EB] flex items-center gap-2">
            <Eye className="w-5 h-5 text-[#06B6D4]" /> Network Visibility & Capture Management
          </h2>
          <p className="text-xs text-[#94A3B8] mt-0.5 font-mono">
            TShark Live Engine · PCAPNG Capture · LAN Scan
            {b && (
              <span className="ml-2 text-[#64748B]">· Source: <span className="text-[#E5E7EB]">{source}</span></span>
            )}
            {isDemoSource && connected && (
              <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded border border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B] text-[10px] font-semibold uppercase tracking-wider">
                Demo data
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Device Export CSV */}
          <a
            href={getDevicesExportUrl()}
            download="netguard_devices_inventory.csv"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#172033] hover:bg-[#1E293B] border border-[#243244] rounded text-xs text-[#E5E7EB] font-mono transition-colors"
            title="Export discovered devices inventory as CSV"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-[#06B6D4]" />
            <span>Export Devices (CSV)</span>
          </a>

          {/* Upload PCAP */}
          <label className="flex items-center gap-2 px-3 py-1.5 bg-[#172033] hover:bg-[#1E293B] border border-[#243244] rounded text-xs cursor-pointer transition-colors">
            <Upload className="w-3 h-3 text-[#06B6D4]" />
            <span className="text-[#E5E7EB] font-mono">{upBusy ? 'Uploading…' : 'Upload PCAP'}</span>
            <input type="file" accept=".pcap,.pcapng,.cap" className="hidden" disabled={upBusy} onChange={onUpload} />
          </label>
          {scanRunning && (
            <span className="text-xs font-mono text-[#22C55E] px-2 py-1.5 border border-[#22C55E]/30 rounded bg-[#22C55E]/10">
              Scan {scanStatus?.progress ?? 0}%
            </span>
          )}
        </div>
      </div>

      {err && (
        <div className="text-xs text-[#F59E0B] bg-[#F59E0B]/5 border border-[#F59E0B]/30 rounded p-3 font-mono">
          <p className="font-semibold">Visibility API unreachable — {err}</p>
          <p className="mt-1 text-[#94A3B8]">Start backend: <code className="text-[#06B6D4]">python run_backend.py</code>.</p>
        </div>
      )}

      {loading && (
        <p className="text-xs text-[#94A3B8] font-mono">Loading telemetry…</p>
      )}

      {/* Operational Control Panels: Live Capture & Network Scanner */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <LiveCapturePanel
          captureStatus={captureStatus}
          setCaptureStatus={setCaptureStatus}
          onChanged={async () => { await reload(); await refreshStatus(); }}
        />
        <NetworkScanPanel
          scanStatus={scanStatus}
          setScanStatus={setScanStatus}
          onChanged={async () => { await reload(); }}
        />
      </div>

      {/* Wireshark-Style Saved Captures Panel */}
      <SavedCapturesPanel
        activeCaptureRunning={captureRunning}
        activeSessionId={captureStatus?.live?.activeSessionId}
        onRefreshParent={async () => { await reload(); await refreshStatus(); }}
      />

      {connected && isEmpty && (
        <div className="text-xs text-[#94A3B8] border border-[#243244] rounded p-3 bg-[#111827] font-mono">
          {emptyMessage}
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard
          title="Total Packets"
          value={(summary?.packetCount ?? networkSessions.reduce((a, s) => a + (s.packets || 0), 0)).toLocaleString()}
          icon={Activity}
          iconColor="text-[#06B6D4]"
        />
        <MetricCard
          title="Unique IPs"
          value={summary?.discoveredHostCount ?? hosts.length}
          icon={Server}
          iconColor="text-[#22C55E]"
          subtitle={`${activeHosts} active · ${susH.length} suspicious`}
        />
        <MetricCard
          title="Protocols Seen"
          value={protocolsSeen.length || '—'}
          icon={Globe}
          iconColor="text-[#A855F7]"
          subtitle={protocolsSeen.slice(0, 3).join(', ') || undefined}
        />
        <MetricCard
          title="Top Talker"
          value={topTalkerIp}
          icon={AlertTriangle}
          iconColor="text-[#F59E0B]"
          subtitle={topTalkers[0] ? `${topTalkers[0].pctOfTotal}% of traffic` : undefined}
        />
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-1 bg-[#111827] border border-[#243244] rounded-lg p-1 flex-wrap">
        {tabs.map((tab, i) => (
          <button
            key={tab}
            onClick={() => setActiveTab(i)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              activeTab === i
                ? 'bg-[#06B6D4]/15 text-[#06B6D4] font-semibold'
                : 'text-[#94A3B8] hover:text-[#E5E7EB] hover:bg-[#172033]'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 0 && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 xl:grid-cols-5 gap-3">
            <div className="xl:col-span-3 bg-[#111827] border border-[#243244] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">Host Communication Topology</h4>
                <span className="text-[11px] text-[#94A3B8] font-mono">{gnodes.length} nodes · {edges.length} edges</span>
              </div>
              <HostCommGraph nodes={gnodes} edges={edges} selectedIp={selectedIp} onSelect={setSelectedIp} />
            </div>
            <div className="xl:col-span-2 space-y-3">
              <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-[#243244] flex items-center justify-between">
                  <span className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">Discovered Asset Inventory</span>
                  <span className="text-[11px] text-[#94A3B8] font-mono">{hosts.length} hosts</span>
                </div>
                <div className="overflow-x-auto max-h-72">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#243244] text-[#94A3B8]">
                        {['IP Address', 'MAC', 'Device Type', 'Open Ports'].map((h) => (
                          <th key={h} className="px-3 py-2 text-left font-medium uppercase tracking-wider text-[10px] whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {hosts.length === 0 ? (
                        <EmptyHint>{emptyMessage}</EmptyHint>
                      ) : hosts.map((host) => (
                        <tr
                          key={host.id}
                          onClick={() => setSelectedIp(host.ip)}
                          className={`border-b border-[#243244]/50 hover:bg-[#172033]/60 cursor-pointer transition-colors ${selectedIp === host.ip ? 'bg-[#06B6D4]/10' : ''}`}
                        >
                          <td className="px-3 py-2 font-mono text-[#06B6D4] whitespace-nowrap">{host.ip}</td>
                          <td className="px-3 py-2 font-mono text-[#94A3B8] whitespace-nowrap text-[10px]">{host.mac || '—'}</td>
                          <td className="px-3 py-2 text-[#E5E7EB] whitespace-nowrap">{host.deviceType || host.role}</td>
                          <td className="px-3 py-2">
                            <div className="flex gap-1 flex-wrap">
                              {host.openPorts?.slice(0, 4).map((p) => (
                                <span key={p} className="bg-[#172033] border border-[#243244] text-[#94A3B8] px-1.5 py-0.5 rounded font-mono text-[10px]">{p}</span>
                              ))}
                              {!host.openPorts?.length && <span className="text-[#64748B]">—</span>}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
                <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider mb-3">Protocol Distribution</h4>
                {protocolDistribution.length === 0 ? (
                  <p className="text-xs text-[#94A3B8] font-mono">No protocol data recorded yet.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={160}>
                    <BarChart data={protocolDistribution.slice(0, 8)}>
                      <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" />
                      <XAxis dataKey="protocol" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
                      <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #243244', borderRadius: 4, fontSize: 11 }} />
                      <Bar dataKey="count" fill="#06b6d4" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
              {(selectedHost || selectedScanHost) && (
                <div className="bg-[#111827] border border-[#06B6D4]/40 rounded-lg p-4 space-y-2">
                  <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">Node Details</h4>
                  <p className="text-xs font-mono text-[#06B6D4] font-semibold">{selectedIp}</p>
                  <p className="text-xs text-[#94A3B8]">MAC: <span className="text-[#E5E7EB] font-mono">{selectedHost?.mac || selectedScanHost?.mac || '—'}</span></p>
                  <p className="text-xs text-[#94A3B8]">Device Type: <span className="text-[#E5E7EB]">{selectedHost?.deviceType || selectedHost?.role || selectedScanHost?.device_type || '—'}</span></p>
                  <p className="text-xs text-[#94A3B8]">Hostname: <span className="text-[#E5E7EB]">{selectedHost?.hostname || selectedScanHost?.hostname || '—'}</span></p>
                  <div className="flex gap-1 flex-wrap pt-1">
                    {(selectedScanHost?.ports?.map((p) => p.port) || selectedHost?.openPorts || []).map((p) => (
                      <span key={p} className="bg-[#172033] border border-[#243244] text-[#94A3B8] px-1.5 py-0.5 rounded font-mono text-[10px]">{p}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 1 && (
        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#243244] pb-3">
            <div>
              <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">Host Communication Graph</h4>
              <p className="text-[11px] text-[#94A3B8] mt-0.5">Click a node to inspect traffic relationships and device classification</p>
            </div>
            <div className="flex gap-2">
              <span className="text-[11px] font-mono bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444] px-2 py-0.5 rounded">
                {edges.filter((e) => e.suspicious).length} suspicious edges
              </span>
            </div>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-3">
            <div className="xl:col-span-3">
              <HostCommGraph nodes={gnodes} edges={edges} selectedIp={selectedIp} onSelect={setSelectedIp} />
            </div>
            <div className="bg-[#0F172A] border border-[#243244] rounded-lg p-3 text-xs space-y-2">
              <p className="text-[#94A3B8] font-bold uppercase tracking-wider text-[10px]">Selected Node</p>
              {!selectedIp && <p className="text-[#64748B]">Select a node in graph</p>}
              {selectedIp && (
                <>
                  <p className="font-mono text-[#06B6D4] font-semibold">{selectedIp}</p>
                  <p className="text-[#94A3B8]">Type: <span className="text-[#E5E7EB]">{selectedHost?.deviceType || selectedHost?.role || '—'}</span></p>
                  <p className="text-[#94A3B8]">MAC: <span className="text-[#E5E7EB] font-mono">{selectedHost?.mac || '—'}</span></p>
                  <div className="flex gap-1 flex-wrap pt-1">
                    {(selectedHost?.openPorts || []).map((p) => (
                      <span key={p} className="bg-[#172033] border border-[#243244] px-1.5 py-0.5 rounded font-mono text-[10px] text-[#94A3B8]">{p}</span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
            {[
              { label: 'Suspicious Flows', value: edges.filter((e) => e.suspicious).length, color: 'text-[#EF4444]' },
              { label: 'Total Edges', value: edges.length, color: 'text-[#22C55E]' },
              { label: 'Unique Nodes', value: gnodes.length, color: 'text-[#06B6D4]' },
              { label: 'Pattern Events', value: b?.patternEvents?.length ?? 0, color: 'text-[#F59E0B]' },
            ].map((s) => (
              <div key={s.label} className="bg-[#0F172A] border border-[#243244] rounded p-2.5 text-center">
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-[11px] text-[#94A3B8] mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 2 && (
        <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[#243244]">
            <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">Network Sessions &amp; Bidirectional Flows</h4>
            <p className="text-[11px] text-[#94A3B8] mt-0.5">Bidirectional 5-tuple flow aggregation with real-time ML threat classification</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#243244] text-[#94A3B8]">
                  {['Flow ID', 'Source', 'Destination', 'Proto', 'Duration', 'Packets', 'Bytes', 'State', 'Threat', 'Severity'].map((h) => (
                    <th key={h} className="px-3 py-2 text-left font-medium uppercase tracking-wider text-[10px] whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {networkSessions.length === 0 ? (
                  <EmptyHint>{emptyMessage}</EmptyHint>
                ) : networkSessions.map((s) => (
                  <tr key={s.id} className={`border-b border-[#243244]/50 hover:bg-[#172033]/60 transition-colors ${s.threat ? 'bg-[#EF4444]/5' : ''}`}>
                    <td className="px-3 py-2.5 font-mono text-[#94A3B8]">{s.id}</td>
                    <td className="px-3 py-2.5 font-mono text-[#06B6D4] whitespace-nowrap">{s.srcIp}:{s.srcPort}</td>
                    <td className="px-3 py-2.5 font-mono text-[#38BDF8] whitespace-nowrap">{s.dstIp}:{s.dstPort}</td>
                    <td className="px-3 py-2.5"><span className="bg-[#172033] border border-[#243244] text-[#94A3B8] px-1.5 py-0.5 rounded font-mono text-[10px]">{s.protocol}</span></td>
                    <td className="px-3 py-2.5 font-mono text-[#E5E7EB]">{s.duration.toFixed(1)}s</td>
                    <td className="px-3 py-2.5 font-mono text-[#E5E7EB]">{s.packets.toLocaleString()}</td>
                    <td className="px-3 py-2.5 font-mono text-[#E5E7EB]">{(s.bytes / 1000000).toFixed(2)} MB</td>
                    <td className="px-3 py-2.5"><span className={`text-[11px] font-mono ${s.state === 'ESTABLISHED' ? 'text-[#22C55E]' : 'text-[#94A3B8]'}`}>{s.state}</span></td>
                    <td className="px-3 py-2.5">{s.threat ? <span className="text-[#EF4444] font-semibold">{s.threat}</span> : <span className="text-[#64748B]">—</span>}</td>
                    <td className="px-3 py-2.5"><StatusBadge status={s.severity} size="xs" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 3 && (
        <div className="space-y-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-[#243244]">
              <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">DNS Query Analysis — Passive</h4>
              <p className="text-[11px] text-[#94A3B8]">Extracted from UDP/53; entropy and suspicious lookup detection</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#243244] text-[#94A3B8]">
                    {['Domain', 'Type', 'Count', 'First Seen', 'Resolved IP', 'Category', 'Suspicious'].map((h) => (
                      <th key={h} className="px-3 py-2 text-left font-medium uppercase tracking-wider text-[10px] whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {dnsQueries.length === 0 ? (
                    <EmptyHint>{emptyMessage}</EmptyHint>
                  ) : dnsQueries.map((d, i) => (
                    <tr key={i} className={`border-b border-[#243244]/50 hover:bg-[#172033]/60 transition-colors ${d.suspicious ? 'bg-[#EF4444]/5' : ''}`}>
                      <td className="px-3 py-2.5 font-mono text-xs max-w-xs truncate">
                        <span className={d.suspicious ? 'text-[#EF4444] font-semibold' : 'text-[#E5E7EB]'}>{d.domain}</span>
                      </td>
                      <td className="px-3 py-2.5"><span className="bg-[#172033] border border-[#243244] text-[#94A3B8] px-1.5 py-0.5 rounded font-mono text-[10px]">{d.queryType}</span></td>
                      <td className="px-3 py-2.5 font-mono text-[#E5E7EB]">{d.count.toLocaleString()}</td>
                      <td className="px-3 py-2.5 font-mono text-[#94A3B8] text-[11px]">{d.firstSeen ? new Date(d.firstSeen).toLocaleTimeString() : '—'}</td>
                      <td className="px-3 py-2.5 font-mono text-[#06B6D4]">{d.resolvedIp}</td>
                      <td className="px-3 py-2.5">
                        <span className={`text-[11px] font-medium ${d.suspicious ? 'text-[#EF4444]' : 'text-[#22C55E]'}`}>{d.category}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        {d.suspicious ? <span className="text-[#EF4444] font-bold text-xs">⚠ Flagged</span> : <span className="text-[#22C55E] text-xs">Normal</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 4 && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#243244]">
                <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">ARP Table (Passive)</h4>
                <p className="text-[11px] text-[#94A3B8]">IP ↔ MAC mappings; ARP spoofing and conflict detection</p>
              </div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#243244] text-[#94A3B8]">
                    {['IP', 'MAC', 'Type', 'TTL', 'Alert'].map((h) => <th key={h} className="px-3 py-2 text-left font-medium text-[10px] uppercase tracking-wider">{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {arpTable.map((a, i) => (
                    <tr key={i} className={`border-b border-[#243244]/50 hover:bg-[#172033]/60 transition-colors ${a.suspicious ? 'bg-[#EF4444]/10' : ''}`}>
                      <td className="px-3 py-2.5 font-mono text-[#06B6D4]">{a.ip}</td>
                      <td className="px-3 py-2.5 font-mono text-[#94A3B8] text-xs">{a.mac}</td>
                      <td className="px-3 py-2.5 text-[#E5E7EB]">{a.type}</td>
                      <td className="px-3 py-2.5 font-mono text-[#94A3B8]">{a.ttl ?? '∞'}</td>
                      <td className="px-3 py-2.5">{a.suspicious ? <span className="text-[#EF4444] font-bold text-xs">⚠ Spoof/Conflict</span> : <span className="text-[#22C55E] text-xs">OK</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#243244]">
                <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider">TLS Metadata (ClientHello SNI)</h4>
                <p className="text-[11px] text-[#94A3B8]">Passive inspection of SNI domain, TLS version, and cipher negotiation</p>
              </div>
              <div className="p-3 space-y-2 max-h-80 overflow-y-auto">
                {tlsMetadata.map((t, i) => (
                  <div key={i} className={`p-2.5 rounded border ${t.suspicious ? 'border-[#EF4444]/40 bg-[#EF4444]/5' : 'border-[#243244] bg-[#0F172A]'}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-xs font-mono font-semibold ${t.suspicious ? 'text-[#EF4444]' : 'text-[#E5E7EB]'}`}>{t.srcIp} → {t.dstIp}</span>
                      {t.suspicious && <span className="text-[10px] bg-[#EF4444]/20 text-[#EF4444] px-1.5 py-0.5 rounded font-mono font-bold">SUSPICIOUS</span>}
                    </div>
                    <div className="grid grid-cols-2 gap-1 text-xs">
                      <div><span className="text-[#64748B]">SNI:</span> <span className="text-[#06B6D4] font-mono">{t.sni}</span></div>
                      <div><span className="text-[#64748B]">Ver:</span> <span className="text-[#94A3B8] font-mono">{t.version}</span></div>
                      <div className="col-span-2"><span className="text-[#64748B]">Cipher:</span> <span className="text-[#94A3B8] font-mono text-[11px]">{t.cipherSuite}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 5 && (
        <div className="grid grid-cols-1 gap-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider mb-1">Bandwidth Timeline (Mb/s)</h4>
            <p className="text-[11px] text-[#94A3B8] mb-4">Traffic volume aggregated by time interval</p>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={bandwidthData} margin={{ top: 0, right: 0, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} unit=" Mb/s" />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="inbound" stroke="#06b6d4" fill="url(#inGrad)" strokeWidth={1.5} dot={false} name="Inbound (Mb/s)" />
                <Area type="monotone" dataKey="outbound" stroke="#22c55e" fill="url(#outGrad)" strokeWidth={1.5} dot={false} name="Outbound (Mb/s)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-xs font-bold text-[#E5E7EB] uppercase tracking-wider mb-3">Top Network Talkers</h4>
            <div className="space-y-2">
              {topTalkers.length === 0 ? (
                <p className="text-xs text-[#94A3B8] py-4 text-center font-mono">{emptyMessage}</p>
              ) : topTalkers.map((t) => (
                <div key={t.rank} className="flex items-center gap-3">
                  <span className="text-xs font-bold text-[#64748B] w-4 font-mono">#{t.rank}</span>
                  <span className="font-mono text-xs text-[#06B6D4] w-32 flex-shrink-0">{t.ip}</span>
                  <span className="text-xs text-[#94A3B8] w-28 hidden md:block truncate">{t.hostname}</span>
                  <div className="flex-1 h-2 bg-[#172033] rounded overflow-hidden border border-[#243244]">
                    <div className="h-full bg-[#06B6D4] rounded" style={{ width: `${Math.min(100, t.pctOfTotal * 3)}%` }} />
                  </div>
                  <span className="font-mono text-xs text-[#E5E7EB] w-20 text-right">{(t.totalBytes / 1e9).toFixed(2)} GB</span>
                  <span className="text-xs text-[#94A3B8] w-12 text-right font-mono">{t.pctOfTotal}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
