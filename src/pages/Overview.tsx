import { useEffect, useMemo, useState } from 'react';
import { Shield, AlertTriangle, Activity, Server, Cpu, Eye, TrendingUp, Globe, Lock } from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { fetchDashboardOverview, type DashboardOverview } from '../api/dashboard';
import MetricCard from '../components/shared/MetricCard';
import StatusBadge from '../components/shared/StatusBadge';

interface OverviewProps {
  onNavigate: (page: string) => void;
}

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, protocol }: any) => {
  if (percent < 0.06) return null;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={10} fontWeight={600}>
      {protocol}
    </text>
  );
};

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-1 font-mono">{label}</p>
      {payload.map((p: any) => (
        <p key={p.name} style={{ color: p.color }} className="font-mono">
          {p.name}: {typeof p.value === 'number' && p.value > 1000 ? (p.value / 1000000).toFixed(1) + 'M' : p.value}
        </p>
      ))}
    </div>
  );
};

type CritRow = {
  id: string;
  title: string;
  severity: string;
  srcIp: string;
  dstIp: string;
  confidence: number;
  model: string;
};

function EmptyState({ message, action }: { message: string; action?: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-32 text-center gap-2">
      <p className="text-xs text-slate-500">{message}</p>
      {action && <p className="text-xs text-cyan-500 font-mono">{action}</p>}
    </div>
  );
}

export default function Overview({ onNavigate }: OverviewProps) {
  const [ov, setOv] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    (async () => {
      setLoading(true);
      setErr(null);
      try {
        const d = await fetchDashboardOverview();
        if (!cancel) setOv(d);
      } catch (e) {
        if (!cancel) setErr((e as Error).message);
      } finally {
        if (!cancel) setLoading(false);
      }
    })();
    return () => { cancel = true; };
  }, []);

  const kpis = useMemo(() => {
    if (!ov) return null;
    return ov.kpis;
  }, [ov]);

  const tl = ov?.trafficTimeline ?? [];
  const pie = ov?.protocolDistribution ?? [];
  const atk = ov?.attackDistribution ?? [];

  const critAlerts: CritRow[] = useMemo(() => {
    if (!ov?.latestCriticalAlerts?.length) return [];
    return (ov.latestCriticalAlerts as Record<string, unknown>[]).map((a) => ({
      id: String(a.id ?? ''),
      title: String(a.title ?? ''),
      severity: String(a.severity ?? 'critical'),
      srcIp: String(a.srcIp ?? ''),
      dstIp: String(a.dstIp ?? ''),
      confidence: Number(a.confidence ?? 0),
      model: String(a.model ?? ''),
    }));
  }, [ov]);

  const threatScore = kpis?.threatScore ?? 0;
  const threatColor = threatScore >= 75 ? 'text-red-400' : threatScore >= 50 ? 'text-amber-400' : 'text-emerald-400';
  const threatLabel = threatScore >= 75 ? 'HIGH' : threatScore >= 50 ? 'ELEVATED' : 'LOW';

  const modelBadge = ov?.modelMeta?.isRealTraining
    ? <span className="text-emerald-400 font-mono">cicids2017_real</span>
    : <span className="text-amber-400 font-mono">synthetic_fallback</span>;

  return (
    <div className="p-4 md:p-6 space-y-6 overflow-auto h-full">
      {loading && (
        <p className="text-xs text-slate-500 font-mono animate-pulse">Loading dashboard from API…</p>
      )}
      {err && (
        <div className="text-xs text-amber-400 border border-amber-500/20 rounded-lg px-3 py-2 bg-amber-500/5">
          <p className="font-semibold">Backend unreachable — {err}</p>
          <p className="mt-1 text-slate-400">Start the backend: <code className="text-cyan-300 font-mono">python run_backend.py</code></p>
          <p className="mt-0.5 text-slate-400">No mock data will be displayed — all values below reflect real API state only.</p>
        </div>
      )}
      {ov?.modelMeta && (
        <p className="text-xs text-slate-500">
          Model: {modelBadge}
          {!ov.modelMeta.isRealTraining && (
            <span className="text-amber-500 ml-2">
              — Upload CICIDS2017 CSV in Settings to train real models
            </span>
          )}
          {' · '}Source: <span className="text-slate-300 font-mono">{ov.source}</span>
        </p>
      )}

      {/* Threat Banner */}
      <div className="rounded-lg bg-[#111827] border border-[#243244] p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Shield className="w-4 h-4 text-[#06B6D4]" />
              <span className="text-[11px] font-mono text-[#06B6D4] uppercase tracking-widest font-semibold">NetGuard SOC Dashboard</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">Security Operations Center — Live View</h2>
            <p className="text-xs text-slate-400 mt-1">
              {kpis
                ? <>Monitoring <span className="text-white font-mono font-medium">{kpis.activeHosts}</span> hosts · <span className="text-white font-mono font-medium">{kpis.packetsPerSecond.toLocaleString()}</span> pkt/s · RF + XGB + IsoForest</>
                : <span className="text-slate-500">Awaiting backend data…</span>
              }
            </p>
          </div>
          <div className="text-center px-4 py-3 rounded-lg bg-[#0F172A] border border-[#243244] min-w-[140px]">
            <p className="text-[10px] uppercase font-mono text-slate-400 tracking-wider mb-1">Threat Score</p>
            <p className={`text-3xl font-bold font-mono tracking-tight ${threatColor}`}>{threatScore}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">/ 100 — <span className="font-semibold">{kpis ? threatLabel : '—'}</span></p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetricCard title="Critical Alerts" value={kpis?.criticalAlerts ?? '—'} icon={AlertTriangle} iconColor="text-red-400" alert={(kpis?.criticalAlerts ?? 0) > 0} onClick={() => onNavigate('alerts')} />
        <MetricCard title="Active Hosts" value={kpis?.activeHosts ?? '—'} icon={Server} iconColor="text-[#06B6D4]" subtitle="Discovered passive" />
        <MetricCard title="Packets / sec" value={kpis ? kpis.packetsPerSecond.toLocaleString() : '—'} icon={Activity} iconColor="text-emerald-400" />
        <MetricCard
          title="RF Accuracy"
          value={kpis?.modelAccuracy != null ? `${kpis.modelAccuracy}%` : '—'}
          icon={Cpu}
          iconColor={kpis?.modelType === 'cicids2017_real' ? 'text-purple-400' : 'text-amber-400'}
          subtitle={kpis?.modelType === 'cicids2017_real' ? 'CICIDS2017 real' : 'Pending real training'}
        />
        <MetricCard title="Total Flows" value={kpis ? kpis.totalFlows.toLocaleString() : '—'} icon={TrendingUp} iconColor="text-blue-400" />
        <MetricCard title="Data Ingested" value={kpis?.bytesIngestedLabel ?? '—'} icon={Globe} iconColor="text-yellow-400" subtitle="Capture window" />
      </div>

      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Critical', count: kpis?.criticalAlerts, border: 'border-red-500/30', bg: 'bg-red-500/5', textColor: 'text-red-400' },
          { label: 'High', count: kpis?.highAlerts, border: 'border-orange-500/30', bg: 'bg-orange-500/5', textColor: 'text-orange-400' },
          { label: 'Medium', count: kpis?.mediumAlerts, border: 'border-yellow-500/30', bg: 'bg-yellow-500/5', textColor: 'text-yellow-400' },
          { label: 'Low', count: kpis?.lowAlerts, border: 'border-blue-500/30', bg: 'bg-blue-500/5', textColor: 'text-blue-400' },
        ].map((item) => (
          <button key={item.label} type="button" onClick={() => onNavigate('alerts')} className={`rounded-lg border ${item.border} ${item.bg} p-3 text-center hover:bg-opacity-20 transition-colors`}>
            <p className={`text-2xl font-bold font-mono ${item.textColor}`}>{item.count ?? '—'}</p>
            <p className="text-xs text-slate-400 mt-0.5">{item.label} Alerts</p>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-[#111827] border border-[#243244] rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">24h Traffic & Alert Timeline</h3>
              <p className="text-xs text-slate-500">From passive capture bucket buckets + alert DB</p>
            </div>
            <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/20 rounded px-2 py-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span className="text-[11px] text-emerald-400 font-mono">API LIVE</span>
            </div>
          </div>
          {tl.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={tl} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="packetsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="alertsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} interval={3} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="packets" stroke="#06b6d4" fill="url(#packetsGrad)" strokeWidth={1.5} dot={false} name="Packets" />
                <Area type="monotone" dataKey="alerts" stroke="#ef4444" fill="url(#alertsGrad)" strokeWidth={1.5} dot={false} name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState message="No traffic data yet." action="Start TShark capture or upload a PCAP in Network Visibility" />
          )}
        </div>

        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Protocol Distribution</h3>
          <p className="text-xs text-slate-500 mb-3">Passive protocol mix from capture</p>
          {pie.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pie} cx="50%" cy="50%" outerRadius={68} dataKey="count" label={renderCustomLabel} labelLine={false}>
                    {pie.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip formatter={(value: any) => [value >= 1000 ? `${(value / 1000).toFixed(1)}K` : value, 'Packets']} contentStyle={{ background: '#0f172a', border: '1px solid #243244', borderRadius: 6, fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5 mt-2">
                {pie.slice(0, 4).map((p) => (
                  <div key={p.protocol} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: p.color }} />
                      <span className="text-slate-300 font-medium">{p.protocol}</span>
                    </div>
                    <span className="text-slate-400 font-mono">{p.percentage}%</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <EmptyState message="No protocol data yet." action="Capture or upload traffic to see protocol breakdown" />
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Attack Type Distribution</h3>
          <p className="text-xs text-slate-500 mb-3">From persisted ML alerts (detection scan output)</p>
          {atk.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={atk} layout="vertical" margin={{ left: 20, right: 30, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis dataKey="attack" type="category" tick={{ fill: '#94a3b8', fontSize: 10 }} width={90} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #243244', borderRadius: 6, fontSize: 11 }} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]} name="Attacks">
                  {atk.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState message="No attack detections yet." action="Run Detection scan after capture" />
          )}
        </div>

        <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">Recent Critical / High Alerts</h3>
            <button type="button" onClick={() => onNavigate('alerts')} className="text-xs text-[#06B6D4] hover:underline">View all →</button>
          </div>
          <div className="space-y-2">
            {critAlerts.length > 0
              ? critAlerts.slice(0, 4).map((alert) => (
                <div key={alert.id} className="flex items-start gap-3 p-2.5 bg-red-950/20 border border-red-500/20 rounded-lg">
                  <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-semibold text-white truncate">{alert.title}</p>
                      <StatusBadge status={alert.severity} size="xs" />
                    </div>
                    <p className="text-xs text-slate-400 truncate mt-0.5">{alert.srcIp} → {alert.dstIp}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs font-mono text-[#06B6D4]">{alert.confidence.toFixed(1)}% conf</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-xs text-slate-500 font-mono">{alert.model}</span>
                    </div>
                  </div>
                </div>
              ))
              : <EmptyState message="No critical/high alerts yet." action="Run Detection scan on captured flows" />
            }
          </div>
        </div>
      </div>

      {/* Model status card */}
      <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-white mb-3">AI Model Status</h3>
        {ov?.modelMeta ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              {
                label: 'RF Accuracy',
                value: ov.modelMeta.rfAccuracy != null ? `${ov.modelMeta.rfAccuracy}%` : 'Pending',
                color: ov.modelMeta.isRealTraining ? 'text-emerald-400' : 'text-amber-400',
                sub: ov.modelMeta.isRealTraining ? 'CICIDS2017 real' : 'Synthetic fallback',
              },
              {
                label: 'XGBoost Accuracy',
                value: ov.modelMeta.xgbAccuracy != null ? `${ov.modelMeta.xgbAccuracy}%` : 'Pending',
                color: ov.modelMeta.isRealTraining ? 'text-emerald-400' : 'text-amber-400',
                sub: ov.modelMeta.isRealTraining ? 'CICIDS2017 real' : 'Synthetic fallback',
              },
              { label: 'Features', value: `${ov.modelMeta.nFeatures}`, color: 'text-[#06B6D4]', sub: 'CICIDS2017 subset' },
              { label: 'Classes', value: `${(ov.modelMeta.classes ?? []).length}`, color: 'text-purple-400', sub: (ov.modelMeta.classes ?? []).join(', ') || '—' },
            ].map((m) => (
              <div key={m.label} className="bg-[#0F172A] border border-[#243244] rounded-md p-3">
                <p className="text-[11px] text-slate-400">{m.label}</p>
                <p className={`text-xl font-bold font-mono mt-1 ${m.color}`}>{m.value}</p>
                <p className="text-[10px] text-slate-500 mt-0.5 truncate" title={m.sub}>{m.sub}</p>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="Model status unavailable — backend offline." />
        )}
        {ov?.modelMeta && !ov.modelMeta.isRealTraining && (
          <p className="text-xs text-amber-400 mt-3 border border-amber-500/20 rounded px-2.5 py-1.5 bg-amber-500/5">
            ⚠ Current model trained on synthetic fallback data. Upload a CICIDS2017 CSV in Settings to get real evaluation metrics.
          </p>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {[
          { id: 'visibility', label: 'Network Visibility', desc: 'Real TShark capture · Host discovery · PCAPNG export', icon: Eye },
          { id: 'detection', label: 'AI Threat Detection', desc: 'Random Forest · XGBoost · Isolation Forest', icon: Cpu },
          { id: 'forensics', label: 'Forensics & Intel', desc: 'SHAP explainability · LLM reports · Timeline', icon: Lock },
        ].map((mod) => {
          const Icon = mod.icon;
          return (
            <button key={mod.id} type="button" onClick={() => onNavigate(mod.id)} className="text-left p-4 bg-[#111827] border border-[#243244] hover:border-[#06B6D4]/50 rounded-lg transition-colors group">
              <Icon className="w-5 h-5 text-slate-300 mb-2 group-hover:text-[#06B6D4] transition-colors" />
              <h4 className="text-sm font-semibold text-white">{mod.label}</h4>
              <p className="text-xs text-slate-400 mt-0.5">{mod.desc}</p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
