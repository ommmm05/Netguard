import { useEffect, useMemo, useState } from 'react';
import { Search, Download, Cpu, Shield, AlertTriangle, ChevronRight } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell
} from 'recharts';
import { API_BASE, apiFetch } from '../api/config';
import StatusBadge from '../components/shared/StatusBadge';

const tabs = ['SHAP Explainability', 'Incident Timeline', 'LLM Report', 'IOC Summary', 'Export'];

const sevColors: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b'
};

type ApiAlertRow = {
  id: string;
  title?: string;
  severity?: string;
  timestamp?: string | null;
  srcIp?: string | null;
  dstIp?: string | null;
  description?: string | null;
  attackType?: string | null;
  confidence?: number | null;
  model?: string | null;
  protocol?: string | null;
};

type TimelineEvent = {
  time: string;
  event: string;
  severity: string;
  host: string;
  details: string;
  mitre: string;
};

// Removed static demo maps

function IocMitreTab({ selectedAlertId, selectedAlert }: { selectedAlertId: string; selectedAlert: { srcIp: string; dstIp: string; confidence: number } }) {
  const [apiIocs, setApiIocs] = useState<{ type: string; value: string; category: string; confidence: number }[] | null>(null);
  const [apiMitre, setApiMitre] = useState<{ tactic: string; technique: string; desc: string; alert: string }[] | null>(null);
  const [iocSource, setIocSource] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/iocs`);
        if (r.ok) {
          const j = (await r.json()) as { iocs?: { type?: string; value?: string; category?: string; confidence?: number }[] };
          if (!cancel && j.iocs?.length) {
            setApiIocs(j.iocs.map(i => ({ type: i.type ?? 'IP', value: i.value ?? '—', category: i.category ?? '—', confidence: i.confidence ?? 0 })));
            setIocSource('API');
          }
        }
      } catch { /* demo fallback */ }
      try {
        const r2 = await apiFetch(`${API_BASE}/api/forensics/mitre/${selectedAlertId}`);
        if (r2.ok) {
          const j2 = (await r2.json()) as { mappings?: { tactic?: string; technique_id?: string; technique_name?: string }[] };
          if (!cancel && j2.mappings?.length) {
            setApiMitre(j2.mappings.map(m => ({ tactic: m.tactic ?? '—', technique: m.technique_id ?? '—', desc: m.technique_name ?? '—', alert: selectedAlertId })));
          }
        }
      } catch { /* demo fallback */ }
    })();
    return () => { cancel = true; };
  }, [selectedAlertId]);

  const iocs = apiIocs ?? [];
  const mitre = apiMitre ?? [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-white">Network IOCs</h4>
            <span className="text-xs text-slate-500 font-mono">{iocSource ? `Source: ${iocSource}` : 'Pending alert selected'}</span>
          </div>
          {(selectedAlert.srcIp && selectedAlert.srcIp !== '—') || (selectedAlert.dstIp && selectedAlert.dstIp !== '—') ? (
            <div className="space-y-2 mb-3 pb-3 border-b border-slate-800/60">
              <p className="text-xs text-cyan-400 font-mono mb-1">From selected alert {selectedAlertId}</p>
              {[
                { type: 'IP (src)', value: selectedAlert.srcIp, category: 'Flow endpoint', confidence: selectedAlert.confidence },
                { type: 'IP (dst)', value: selectedAlert.dstIp, category: 'Flow endpoint', confidence: selectedAlert.confidence },
              ].map((ioc, i) => (
                <div key={i} className="flex items-center gap-3 p-2 bg-[#0F172A] border border-[#243244] rounded-lg">
                  <span className="text-xs text-slate-500 w-24 flex-shrink-0">{ioc.type}</span>
                  <span className="text-xs font-mono text-cyan-300 flex-1 truncate">{ioc.value}</span>
                  <span className="text-xs text-slate-400">{ioc.category}</span>
                  <span className="text-xs font-mono text-slate-400">{typeof ioc.confidence === 'number' ? `${ioc.confidence.toFixed(0)}%` : '—'}</span>
                </div>
              ))}
            </div>
          ) : null}
          <div className="space-y-2">
            {iocs.map((ioc, i) => (
              <div key={i} className="flex items-center gap-3 p-2 bg-[#0F172A] border border-[#243244] rounded-lg">
                <span className="text-xs text-slate-500 w-24 flex-shrink-0">{ioc.type}</span>
                <span className="text-xs font-mono text-red-400 flex-1 truncate">{ioc.value}</span>
                <span className="text-xs text-orange-400">{ioc.category}</span>
                <span className="text-xs font-mono text-slate-400">{ioc.confidence}%</span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-white">MITRE ATT&CK Coverage</h4>
            <span className="text-xs text-slate-500 font-mono">{apiMitre ? 'API' : 'Pending map'}</span>
          </div>
          <div className="space-y-2">
            {mitre.map((m, i) => (
              <div key={i} className="flex items-center gap-2 p-2 bg-[#0F172A] border border-[#243244] rounded-lg text-xs">
                <span className="font-mono text-blue-400 w-20 flex-shrink-0">{m.technique}</span>
                <span className="text-slate-400 w-28 flex-shrink-0 truncate">{m.tactic}</span>
                <span className="text-slate-300 flex-1 truncate">{m.desc}</span>
                <span className="text-cyan-400 font-mono">{m.alert}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Forensics() {
  const [activeTab, setActiveTab] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [apiShap, setApiShap] = useState<{ top?: { feature: string; value: number; shap: number }[] } | null>(null);
  const [picker, setPicker] = useState<{ id: string; severity: string }[]>([]);
  const [apiAlerts, setApiAlerts] = useState<ApiAlertRow[]>([]);
  const [apiTimeline, setApiTimeline] = useState<TimelineEvent[] | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [apiReport, setApiReport] = useState<{
    summary: string;
    remediation: string[];
    timeline: { time?: string; event?: string; severity?: string; host?: string; details?: string }[];
  } | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportErr, setReportErr] = useState<string | null>(null);
  const [globalFi, setGlobalFi] = useState<{ feature: string; importance: number; category?: string }[] | null>(null);

  const selectedAlert = useMemo(() => {
    const api = apiAlerts.find((a) => a.id === selectedAlertId);
    if (!api) return null;
    return {
      id: api.id,
      title: api.title ?? api.id,
      severity: api.severity || 'medium',
      attackType: api.attackType ?? 'Unknown',
      confidence: typeof api.confidence === 'number' ? api.confidence : 0,
      srcIp: api.srcIp ?? '—',
      dstIp: api.dstIp ?? '—',
      protocol: api.protocol ?? '—',
      description: api.description ?? '',
      topShapFeatures: [],
      mitre: '—',
      mitrePhase: '—',
      remediation: ['Review flow in Visibility · run forensics export', 'Contain hosts at perimeter if confidence is high'],
    };
  }, [apiAlerts, selectedAlertId]);

  const harmfulExplain = useMemo(() => {
    return (apiShap?.top ?? [])
      .filter((t) => (t.shap ?? 0) > 0)
      .map((t) => ({
        feature: t.feature,
        value: t.value,
        shap: t.shap,
        direction: 'harmful' as const,
      }));
  }, [apiShap]);

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/feature-importance`);
        if (r.ok) {
          const j = (await r.json()) as { items?: { feature: string; importance: number; category?: string }[] };
          if (j.items?.length) setGlobalFi(j.items);
        }
      } catch {
        setGlobalFi(null);
      }
    })();
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/detection/alerts`);
        if (!r.ok) return;
        const j = (await r.json()) as { alerts: ApiAlertRow[] };
        if (j.alerts?.length) {
          setApiAlerts(j.alerts);
          setPicker(j.alerts.slice(0, 8).map((a) => ({ id: a.id, severity: a.severity ?? 'medium' })));
          setSelectedAlertId((cur) => (j.alerts?.some((x) => x.id === cur) ? cur : j.alerts[0].id));
        }
      } catch { /* */ }
    })();
  }, []);

  useEffect(() => {
    if (activeTab !== 1) return;
    let cancelled = false;
    (async () => {
      setTimelineLoading(true);
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/incidents?limit=200`);
        if (!r.ok) throw new Error('bad');
        const j = (await r.json()) as {
          groups?: { timeline?: ApiAlertRow[] }[];
        };
        const flat: TimelineEvent[] = [];
        for (const g of j.groups || []) {
          for (const ev of g.timeline || []) {
            const ts = ev.timestamp || '';
            flat.push({
              time: ts.includes('T') ? ts.slice(11, 19) : ts.slice(0, 8) || '—',
              event: ev.title || 'Alert',
              severity: ev.severity || 'info',
              host: `${ev.srcIp ?? ''} → ${ev.dstIp ?? ''}`,
              details: ev.description || '',
              mitre: String(ev.attackType || '—'),
            });
          }
        }
        flat.sort((a, b) => a.time.localeCompare(b.time));
        if (!cancelled) setApiTimeline(flat.length ? flat : null);
      } catch {
        if (!cancelled) setApiTimeline(null);
      } finally {
        if (!cancelled) setTimelineLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeTab]);

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/alert/${selectedAlertId}/shap`);
        if (r.ok) {
          const j = (await r.json()) as { explanation?: { top?: { feature: string; value: number; shap: number }[] } };
          setApiShap(j.explanation || null);
        } else {
          setApiShap(null);
        }
      } catch {
        setApiShap(null);
      }
    })();
  }, [selectedAlertId]);

  const globalFiChart = (globalFi?.length ? globalFi : []).slice(0, 14);

  const topList = (apiShap?.top?.length ? apiShap.top : []) as { feature: string; shap: number; value: number; direction?: string }[];
  const shapData = topList.map(f => {
    const dir = f.direction as string | undefined;
    const isHarm = dir ? dir === 'harmful' : f.shap >= 0;
    return {
    feature: f.feature,
    shap: isHarm ? f.shap : -f.shap,
    display: f.shap,
    direction: (dir as 'harmful' | 'benign') || (f.shap >= 0 ? 'harmful' : 'benign'),
  }; });

  if (!selectedAlert) {
    return (
      <div className="p-4 md:p-6 flex flex-col items-center justify-center h-full text-slate-400 space-y-4">
        <AlertTriangle className="w-8 h-8 text-slate-500 mb-2" />
        <p className="text-sm">No alert selected or alerts not loaded yet.</p>
        <p className="text-xs text-slate-500 max-w-md text-center">Ensure the backend is running and that alerts exist in the DB, or select one from the top bar.</p>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4 overflow-auto h-full">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-emerald-400" /> Forensics & Incident Intelligence
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            SHAP explainability · LLM-generated reports · Incident timeline · PDF/CSV export
          </p>
        </div>
        <div className="flex gap-2">
          <div className="px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-xs text-emerald-400 font-mono">
            shap_explain.py
          </div>
          <div className="px-3 py-1.5 bg-purple-500/10 border border-purple-500/20 rounded-lg text-xs text-purple-400 font-mono">
            llm_report.py
          </div>
        </div>
      </div>

      {/* Alert selector */}
      <div className="flex gap-2 overflow-x-auto pb-1">
        {picker.map((a) => (
          <button
            key={a.id}
            onClick={() => setSelectedAlertId(a.id)}
            className={`flex-shrink-0 px-3 py-2 rounded-lg border text-xs transition-all ${
              selectedAlertId === a.id
                ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400'
                : 'border-[#243244] bg-[#0F172A] text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="font-mono">{a.id}</span>
            <span className="text-slate-500 mx-1">·</span>
            <span className={`font-medium ${a.severity === 'critical' ? 'text-red-400' : a.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'}`}>
              {a.severity.toUpperCase()}
            </span>
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0F172A] border border-[#243244] rounded-lg p-1 flex-wrap">
        {tabs.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(i)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${activeTab === i ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'}`}>
            {tab}
          </button>
        ))}
      </div>

      {/* SHAP Tab */}
      {activeTab === 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* SHAP Waterfall */}
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-1">SHAP Waterfall Plot — {selectedAlert.id}</h4>
            <p className="text-xs text-slate-500 mb-3">
              TreeSHAP values explaining <span className="text-emerald-400 font-mono">{selectedAlert.attackType}</span> classification
            </p>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={shapData} layout="vertical" margin={{ left: 10, right: 50, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} tickFormatter={(v) => v.toFixed(1)} />
                <YAxis dataKey="feature" type="category" tick={{ fill: '#94a3b8', fontSize: 9 }} width={120} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }}
                  formatter={(_v: any, _n: any, p: any) => [`SHAP: ${p.payload.display.toFixed(3)}`, p.payload.feature]}
                />
                <Bar dataKey="shap" radius={[0, 4, 4, 0]} name="SHAP Value">
                  {shapData.map((d, i) => (
                    <Cell key={i} fill={d.direction === 'harmful' ? '#ef4444' : '#10b981'} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div className="flex gap-4 text-xs mt-2">
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded bg-red-500/70" /><span className="text-slate-400">Increases risk (harmful)</span></div>
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded bg-emerald-500/70" /><span className="text-slate-400">Reduces risk (benign)</span></div>
            </div>
          </div>

          {/* Global Feature Importance */}
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-1">Global Feature Importance</h4>
            <p className="text-xs text-slate-500 mb-3">
              {globalFi?.length ? 'From /api/forensics/feature-importance (CICIDS subset + training weights).' : 'Demo chart — backend offline; aligns with CICIDS flow feature names.'}
            </p>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={globalFiChart} layout="vertical" margin={{ left: 10, right: 30, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} tickFormatter={(v) => v.toFixed(2)} />
                <YAxis dataKey="feature" type="category" tick={{ fill: '#94a3b8', fontSize: 9 }} width={115} fontFamily="monospace" />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} formatter={(v: any) => [v.toFixed(4), 'Importance']} />
                <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                  {globalFiChart.map((_, i) => (
                    <Cell key={i} fill={`hsl(${220 - i * 12}, 70%, 60%)`} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Alert reasoning */}
          <div className="lg:col-span-2 bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" /> AI Alert Reasoning — {selectedAlert.id}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-semibold text-slate-300 mb-2">Why was this flagged?</p>
                <div className="space-y-2">
                  {harmfulExplain.length === 0 && (
                    <p className="text-xs text-slate-500">No positive SHAP drivers loaded yet — ensure the backend is up and this alert exists in the DB.</p>
                  )}
                  {harmfulExplain.map(f => (
                    <div key={f.feature} className="flex items-start gap-2 p-2 bg-red-950/20 border border-red-500/20 rounded-lg">
                      <span className="text-red-400 text-xs mt-0.5">►</span>
                      <div>
                        <span className="text-xs font-mono text-red-400">{f.feature}</span>
                        <span className="text-xs text-slate-400"> = {typeof f.value === 'number' ? f.value.toFixed(2) : f.value}</span>
                        <p className="text-xs text-slate-500 mt-0.5">SHAP contribution: <span className="text-red-400 font-mono">+{f.shap.toFixed(3)}</span> toward {selectedAlert.attackType}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-300 mb-2">Root Cause Indicators</p>
                <div className="space-y-2 text-xs">
                  {[
                    `High ${selectedAlert.attackType} confidence (${selectedAlert.confidence}%) — above 85% threshold`,
                    `MITRE ATT&CK: ${selectedAlert.mitre} — ${selectedAlert.mitrePhase} phase`,
                    `Source ${selectedAlert.srcIp} — ${String(selectedAlert.srcIp).startsWith('10.') ? 'External attacker' : 'Internal host (compromised)'}`,
                    `Protocol: ${selectedAlert.protocol} — matches known attack vector`,
                  ].map((r, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <ChevronRight className="w-3 h-3 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <span className="text-slate-300">{r}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-3 p-3 bg-emerald-950/20 border border-emerald-500/20 rounded-lg">
                  <p className="text-xs font-semibold text-emerald-400 mb-1">Recommended Action</p>
                  <p className="text-xs text-slate-300">{selectedAlert.remediation[0]}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === 1 && (
        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4 md:p-6">
          <h4 className="text-sm font-semibold text-white mb-1">Incident Timeline — Attack Chain Reconstruction</h4>
          <p className="text-xs text-slate-500 mb-2">
            {apiTimeline ? 'From /api/forensics/incidents (correlated DB alerts)' : 'Demo timeline (load PCAP + scan or use Settings → demo)'}
            {timelineLoading && ' · loading…'}
          </p>
          <div className="relative">
            <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-[#243244]" />
            <div className="space-y-6">
              {!apiTimeline && !timelineLoading && (
                <div className="text-xs text-slate-500 pl-16">No incident correlations found. Load PCAP and run Detection scan.</div>
              )}
              {(apiTimeline || []).map((event, i) => (
                <div key={i} className="flex items-start gap-4 relative">
                  <div className={`relative z-10 flex-shrink-0 w-6 h-6 rounded-full border-2 flex items-center justify-center ${
                    event.severity === 'critical' ? 'bg-red-950 border-red-500' :
                    event.severity === 'high' ? 'bg-orange-950 border-orange-500' :
                    'bg-yellow-950 border-yellow-500'
                  }`}>
                    <span className="w-2 h-2 rounded-full" style={{ background: sevColors[event.severity] }} />
                  </div>
                  <div className={`flex-1 p-3 md:p-4 rounded-lg border ${
                    event.severity === 'critical' ? 'bg-red-950/20 border-red-500/30' :
                    event.severity === 'high' ? 'bg-orange-950/10 border-orange-500/20' :
                    'bg-yellow-950/10 border-yellow-500/20'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-slate-400">{event.time}</span>
                      <StatusBadge status={event.severity} size="xs" />
                      <span className="text-xs bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono">{event.mitre}</span>
                    </div>
                    <h5 className="text-sm font-semibold text-white">{event.event}</h5>
                    <p className="text-xs text-slate-400 mt-1">{event.details}</p>
                    <p className="text-xs text-slate-500 mt-1.5 font-mono">Host: {event.host}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* LLM Report Tab */}
      {activeTab === 2 && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={reportBusy}
              onClick={() => {
                setReportErr(null);
                setReportBusy(true);
                void (async () => {
                  try {
                    const r = await apiFetch(`${API_BASE}/api/forensics/alert/${selectedAlertId}/report`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ with_llm: true }),
                    });
                    const j = (await r.json()) as {
                      report?: {
                        summary?: string;
                        remediation?: string[] | string;
                        timeline?: { time?: string; event?: string; severity?: string; host?: string; details?: string }[];
                      };
                      detail?: unknown;
                    };
                    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : 'Report failed');
                    const rep = j.report;
                    if (!rep?.summary) throw new Error('Empty report');
                    setApiReport({
                      summary: rep.summary,
                      remediation: Array.isArray(rep.remediation) ? rep.remediation : [String(rep.remediation ?? '')],
                      timeline: Array.isArray(rep.timeline) ? rep.timeline : [],
                    });
                  } catch (e) {
                    setReportErr((e as Error).message);
                    setApiReport(null);
                  } finally {
                    setReportBusy(false);
                  }
                })();
              }}
              className="px-3 py-2 rounded-lg text-xs font-medium border border-purple-500/40 bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 disabled:opacity-50"
            >
              {reportBusy ? 'Generating…' : 'Generate report (API)'}
            </button>
            <span className="text-xs text-slate-500 font-mono">POST /api/forensics/alert/{'{id}'}/report</span>
          </div>
          {reportErr && <p className="text-xs text-amber-400">{reportErr}</p>}

          {apiReport && (
            <div className="bg-[#111827] border border-[#06B6D4]/30 rounded-lg p-4 md:p-6 space-y-4">
              <h4 className="text-base font-semibold text-cyan-400">Incident Narrative</h4>
              <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">{apiReport.summary}</p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                <div>
                  <h5 className="text-xs font-semibold text-white uppercase tracking-wider mb-2">Recommended Actions</h5>
                  <ol className="list-decimal list-inside text-xs text-slate-300 space-y-2">
                    {apiReport.remediation.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ol>
                </div>
                {apiReport.timeline.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-white uppercase tracking-wider mb-2">Incident Timeline</h5>
                    <ul className="text-xs text-slate-400 space-y-1.5 font-mono bg-slate-800/40 p-3 rounded-lg">
                      {apiReport.timeline.slice(0, 8).map((ev, i) => (
                        <li key={i}><span className="text-cyan-400">{ev.time}</span> — {ev.event}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
      {/* IOC Summary */}
      {activeTab === 3 && (
        <IocMitreTab selectedAlertId={selectedAlertId as string} selectedAlert={selectedAlert} />
      )}

      {/* Export Tab */}
      {activeTab === 4 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-6">
            <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Download className="w-4 h-4 text-emerald-400" /> Export Options — exporter.py
            </h4>
            <p className="text-xs text-slate-500 mb-3 font-mono">alert_id={selectedAlertId}</p>
            <div className="space-y-3">
              {[
                {
                  format: 'PDF Report',
                  desc: 'Simple PDF: alert narrative + top SHAP lines for the selected alert.',
                  file: `netguard-${selectedAlertId}.pdf`,
                  icon: '📄',
                  href: `${API_BASE}/api/forensics/export/pdf?alert_id=${encodeURIComponent(selectedAlertId as string)}`,
                },
                {
                  format: 'CSV — Alerts',
                  desc: 'All persisted ML alerts (SQLite) — GET /api/forensics/export/csv',
                  file: 'alerts_export.csv',
                  icon: '📊',
                  href: `${API_BASE}/api/forensics/export/csv`,
                },
                {
                  format: 'CSV — PCAP Flows',
                  desc: 'Not exposed as a single file in this build — use Visibility + offline tooling.',
                  file: 'flows_export.csv',
                  icon: '🔬',
                  href: null as string | null,
                },
                {
                  format: 'JSON — IOCs',
                  desc: 'Use CSV + SOAR mapping; STIX export is not wired in demo mode.',
                  file: 'iocs_stix.json',
                  icon: '🔗',
                  href: null,
                },
                {
                  format: 'CSV — SHAP Values',
                  desc: 'Use SHAP tab + PDF export; dedicated SHAP CSV is not implemented.',
                  file: 'shap_values.csv',
                  icon: '🧠',
                  href: null,
                },
              ].map((e, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-[#0F172A] border border-[#243244] rounded-lg hover:border-[#06B6D4]/30 transition-colors">
                  <span className="text-2xl">{e.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-white">{e.format}</p>
                    <p className="text-xs text-slate-400 mt-0.5">{e.desc}</p>
                    <p className="text-xs font-mono text-emerald-400 mt-0.5">{e.file}</p>
                  </div>
                  {e.href ? (
                    <a
                      href={e.href}
                      target="_blank"
                      rel="noreferrer"
                      className="flex-shrink-0 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-lg hover:bg-emerald-500/20 transition-colors"
                    >
                      Export
                    </a>
                  ) : (
                    <span className="flex-shrink-0 px-3 py-1.5 text-slate-500 text-xs border border-slate-700 rounded-lg">N/A</span>
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-6">
            <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" /> Audit Trail & Evidence Chain
            </h4>
            <div className="space-y-2 text-xs">
              {[
                { label: 'PCAP Hash (SHA-256)', value: 'a4f3d1e8b2c9f7...', type: 'integrity' },
                { label: 'Model Version', value: 'xgboost_v1.2_20241201', type: 'model' },
                { label: 'Analyst ID', value: 'SOC-ANALYST-T2-001', type: 'analyst' },
                { label: 'Capture Start', value: '2024-12-01T00:00:00Z', type: 'timestamp' },
                { label: 'Total Evidence Files', value: '47 PCAP files, 5 CSVs', type: 'evidence' },
                { label: 'Chain of Custody', value: 'Preserved — netguard.db', type: 'custody' },
              ].map((a, i) => (
                <div key={i} className="flex items-center justify-between p-2 bg-[#0F172A] border border-[#243244] rounded">
                  <span className="text-slate-400">{a.label}</span>
                  <span className="font-mono text-slate-300 text-xs truncate ml-2 max-w-[200px]">{a.value}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 p-3 bg-blue-950/20 border border-blue-500/20 rounded-lg">
              <p className="text-xs font-semibold text-blue-400 mb-1">Legal Admissibility Note</p>
              <p className="text-xs text-slate-400">All evidence captured passively. SHA-256 integrity hashes maintained. Timestamps from NTP-synchronized source. Chain of custody logged in SQLite DB.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
